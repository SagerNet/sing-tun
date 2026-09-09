package tun

import (
	"hash/maphash"
	"math"
	"net/netip"
	"runtime"
	"slices"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	goWaitIndefinite    = time.Duration(-1)
	goShutdownBudget    = 250 * time.Millisecond
	goEngineLoadWindow  = 100 * time.Millisecond
	goEngineBusyPercent = 70
)

type goFrame struct {
	data []byte
	meta ForwardFrameMeta
}

type goSocketEvent struct {
	token    uint32
	readable bool
	writable bool
}

const (
	goInterestRead uint8 = 1 << iota
	goInterestWrite
)

var errGoQueueUnavailable = E.New("go: tun queue unavailable")

type goPlatformIO interface {
	start() error
	wait(timeout time.Duration, events []goSocketEvent) (tunReadable bool, count int, err error)
	registerSocket(socket *goSocket, token uint32, interest uint8) error
	updateSocket(socket *goSocket, interest uint8) error
	unregisterSocket(socket *goSocket)
	readBurst(frames []goFrame) (count int, drained bool, err error)
	writeFrame(frame [][]byte, meta ForwardFrameMeta) error
	writeData(frame [][]byte, meta ForwardFrameMeta) error
	flush()
	transmitPrefix() int
	transmitChecksumOffload() bool
	transmitSegmentOffload() bool
	armTransmitWritable() (bool, error)
	takeTransmitWritable() bool
	wake()
	drainWake()
	close() error
}

const (
	goMessageStackClose uint8 = iota
	goMessageStackReset
	goMessageConnEngage
	goMessageConnClose
	goMessageConnReadShut
	goMessageConnRetransmit
	goMessageConnWindow
	goMessageConnBlocked
	goMessageConnDropped
	goMessageConnSplice
	goMessagePacketSplice
	goMessagePacketClose
	goMessageInject
)

const goInjectQueueLimit = 512

type goInjectedFrame struct {
	next   *goInjectedFrame
	buffer *buf.Buffer
	meta   ForwardFrameMeta
}

type goInjectStack struct {
	head atomic.Pointer[goInjectedFrame]
}

func (s *goInjectStack) push(frame *goInjectedFrame) {
	for {
		head := s.head.Load()
		frame.next = head
		if s.head.CompareAndSwap(head, frame) {
			return
		}
	}
}

func (s *goInjectStack) popAll() *goInjectedFrame {
	head := s.head.Swap(nil)
	var ordered *goInjectedFrame
	for head != nil {
		next := head.next
		head.next = ordered
		ordered = head
		head = next
	}
	return ordered
}

type goMessage struct {
	next   *goMessage
	conn   *GoConn
	packet *GoPacketConn
	queued atomic.Bool
	kind   uint8
}

type goControlStack struct {
	head atomic.Pointer[goMessage]
}

func (s *goControlStack) push(message *goMessage) {
	for {
		head := s.head.Load()
		message.next = head
		if s.head.CompareAndSwap(head, message) {
			return
		}
	}
}

func (s *goControlStack) empty() bool {
	return s.head.Load() == nil
}

func (s *goControlStack) popAll() *goMessage {
	return s.head.Swap(nil)
}

const (
	goEngineRunning uint32 = iota
	goEngineParked
	goEngineExited
)

type goEngine struct {
	stack                *Go
	platformIO           goPlatformIO
	dispatcher           *ForwardDispatcher
	dispatchStage        *ForwardStage
	wheel                goWheel
	controlStack         goControlStack
	injectStack          goInjectStack
	injectCount          atomic.Int32
	injectMessage        goMessage
	droppedInjectFrames  goDropCounter
	engineState          atomic.Uint32
	coarseTime           atomic.Int64
	epoch                time.Time
	frames               []goFrame
	closeMessage         goMessage
	resetMessage         goMessage
	delayedAckTickNode   goWheelNode
	reassemblyTickNode   goWheelNode
	sweepTickNode        goWheelNode
	reclaimTickNode      goWheelNode
	reassemblyEntries    []goReassemblyEntry
	udpUserData          goUDPUserData
	udpSessions          map[udpNatSessionKey]*goUDPSession
	transmitFrame        [1][]byte
	exitSignal           chan struct{}
	wokeHandlerThisBurst bool
	tunPending           bool
	parkedNanos          int64
	loadWindowStart      int64
	ackCoalescing        bool
	inlineTransmitBudget int
	socketEvents         []goSocketEvent
	spliceSlots          []goSpliceSlot
	spliceFree           []uint32
	spliceDirtyList      *GoConn
	spliceSegments       [][]byte
	spliceIovecs         []goIOVector
	packetReceive        *buf.Buffer

	flows           map[flowKey]*GoConn
	flowCapacity    int
	slabPool        *goSlabPool
	descriptorPool  goDescriptorPool
	sequenceSeed    maphash.Seed
	ackList         *GoConn
	blockedList     *GoConn
	dyingList       *GoConn
	reclaimPending  bool
	resetBurst      int
	controlIdent    uint32
	controlScratch  [goHeaderScratchSize]byte
	controlSegments [][]byte
	sackScratch     [goMaxSackBlocks]goSackBlock
	sackRaw         [goMaxSackBlocks]goRawSackBlock
}

func (e *goEngine) singleFrame(packet []byte) [][]byte {
	e.transmitFrame[0] = packet
	return e.transmitFrame[:]
}

func newGoEngine(stack *Go, platformIO goPlatformIO, engineCount int) *goEngine {
	engine := &goEngine{
		stack:             stack,
		platformIO:        platformIO,
		dispatcher:        stack.dispatcher,
		dispatchStage:     stack.dispatcher.NewStage(&goWriteback{platformIO: platformIO}),
		epoch:             time.Now(),
		frames:            make([]goFrame, goReadBatch),
		reassemblyEntries: make([]goReassemblyEntry, goReassemblyEntries),
		exitSignal:        make(chan struct{}),
		flows:             make(map[flowKey]*GoConn),
		udpSessions:       make(map[udpNatSessionKey]*goUDPSession),
		flowCapacity:      max(goFlowCapacity/engineCount, 1024),
		slabPool:          newGoSlabPool(stack.memoryPressure, max(goSlabPoolLowWater/engineCount, 8)),
		descriptorPool:    goDescriptorPool{lowWater: max(goDescriptorPoolLowWater/engineCount, 4)},
		sequenceSeed:      maphash.MakeSeed(),
		controlSegments:   make([][]byte, 0, 8),
		socketEvents:      make([]goSocketEvent, goSocketEventBatch),
		spliceSegments:    make([][]byte, 0, 8),
		spliceIovecs:      make([]goIOVector, 0, 8),
	}
	engine.closeMessage.kind = goMessageStackClose
	engine.resetMessage.kind = goMessageStackReset
	engine.injectMessage.kind = goMessageInject
	engine.delayedAckTickNode.expire = engine.expireDelayedAckTick
	engine.reassemblyTickNode.expire = engine.expireReassemblyTick
	engine.sweepTickNode.expire = engine.expireSweepTick
	engine.reclaimTickNode.expire = engine.expireReclaimTick
	engine.refreshCoarseTime()
	engine.wheel.schedule(&engine.sweepTickNode, engine.now()+int64(goSweepInterval))
	engine.wheel.schedule(&engine.reclaimTickNode, engine.now()+int64(goReclaimInterval))
	return engine
}

func (e *goEngine) run() {
	defer close(e.exitSignal)
	defer e.exit()
	e.loadWindowStart = e.now()
	for {
		parkStart := int64(time.Since(e.epoch))
		tunReadable, eventCount, err := e.park()
		e.parkedNanos += e.now() - parkStart
		e.updateLoad(e.now())
		e.drainControlQueue()
		if e.stack.closed.Load() {
			return
		}
		if e.platformIO.takeTransmitWritable() {
			e.releaseBlockedWriters()
		}
		if err != nil {
			e.stack.logger.Error(E.Cause(err, "go: engine wait"))
			return
		}
		e.resetBurst = 0
		e.inlineTransmitBudget = goEngineInlineBurst
		e.platformIO.flush()
		if tunReadable || e.tunPending {
			err = e.processBurst()
			if err != nil {
				if e.stack.closed.Load() || E.IsClosedOrCanceled(err) {
					return
				}
				e.stack.logger.Error(E.Cause(err, "go: engine read"))
				if goFatalReadError(err) {
					return
				}
			}
		}
		e.dispatchSocketEvents(eventCount)
		e.flushSpliceDirty()
		e.wheel.advance(e.now())
		e.flushAcks()
		e.dispatchStage.Flush()
		e.platformIO.flush()
		e.reapDying()
		if e.reclaimPending {
			e.reclaimPending = false
			e.reclaim()
		}
		if e.wokeHandlerThisBurst {
			e.wokeHandlerThisBurst = false
			runtime.Gosched()
		}
	}
}

func (e *goEngine) exit() {
	e.shutdown()
	e.engineState.Store(goEngineExited)
	message := e.controlStack.popAll()
	for message != nil {
		next := message.next
		message.next = nil
		message.queued.Store(false)
		e.releasePending(message)
		message = next
	}
	e.releaseInjected()
}

func (e *goEngine) updateLoad(now int64) {
	elapsed := now - e.loadWindowStart
	if elapsed < int64(goEngineLoadWindow) {
		return
	}
	busy := elapsed - e.parkedNanos
	e.ackCoalescing = busy*100 >= elapsed*goEngineBusyPercent && len(e.flows) >= 2
	e.parkedNanos = 0
	e.loadWindowStart = now
}

func (e *goEngine) park() (bool, int, error) {
	deadline, scheduled := e.wheel.nextDeadline()
	e.engineState.Store(goEngineParked)
	if !e.controlStack.empty() {
		e.engineState.Store(goEngineRunning)
		e.refreshCoarseTime()
		return false, 0, nil
	}
	timeout := goWaitIndefinite
	if scheduled {
		timeout = max(time.Duration(deadline-e.now()), 0)
	}
	if e.tunPending {
		timeout = 0
	}
	tunReadable, eventCount, err := e.platformIO.wait(timeout, e.socketEvents)
	e.engineState.Store(goEngineRunning)
	e.refreshCoarseTime()
	e.platformIO.drainWake()
	return tunReadable, eventCount, err
}

func (e *goEngine) postMessage(message *goMessage) {
	if !message.queued.CompareAndSwap(false, true) {
		return
	}
	e.controlStack.push(message)
	switch e.engineState.Load() {
	case goEngineParked:
		e.platformIO.wake()
	case goEngineExited:
		e.releasePending(message)
	}
}

func (e *goEngine) drainControlQueue() {
	message := e.controlStack.popAll()
	for message != nil {
		next := message.next
		message.next = nil
		message.queued.Store(false)
		e.handleMessage(message)
		message = next
	}
}

func (e *goEngine) handleMessage(message *goMessage) {
	switch message.kind {
	case goMessageStackReset:
		e.dispatcher.ResetNetwork()
		e.reclaimPending = true
	case goMessageConnEngage:
		e.handleEngage(message.conn)
	case goMessageConnClose:
		e.handleCloseRequest(message.conn)
	case goMessageConnReadShut:
		e.handleReadShut(message.conn)
	case goMessageConnRetransmit:
		e.handleRetransmitArm(message.conn)
	case goMessageConnWindow:
		e.handleWindowUpdate(message.conn)
	case goMessageConnBlocked:
		e.handleTransmitBlocked(message.conn)
	case goMessageConnDropped:
		e.handleDroppedFrames(message.conn)
	case goMessageConnSplice:
		e.handleSpliceEngage(message.conn)
	case goMessagePacketSplice:
		e.handlePacketSpliceEngage(message.packet)
	case goMessagePacketClose:
		e.handlePacketSpliceClose(message.packet)
	case goMessageInject:
		e.processInjected()
	}
}

func (e *goEngine) inject(packet []byte, meta ForwardFrameMeta) {
	if e.injectCount.Add(1) > goInjectQueueLimit {
		e.injectCount.Add(-1)
		e.droppedInjectFrames.record(e.stack.logger, "frames handed over between queues")
		return
	}
	frame := &goInjectedFrame{buffer: buf.NewSize(len(packet)), meta: meta}
	common.Must1(frame.buffer.Write(packet))
	e.injectStack.push(frame)
	e.postMessage(&e.injectMessage)
}

func (e *goEngine) processInjected() {
	for frame := e.injectStack.popAll(); frame != nil; {
		next := frame.next
		e.injectCount.Add(-1)
		e.processFrame(&goFrame{data: frame.buffer.Bytes(), meta: frame.meta})
		frame.buffer.Release()
		frame = next
	}
}

func (e *goEngine) releaseInjected() {
	for frame := e.injectStack.popAll(); frame != nil; {
		next := frame.next
		e.injectCount.Add(-1)
		frame.buffer.Release()
		frame = next
	}
}

func (e *goEngine) handleEngage(conn *GoConn) {
	if conn.connState.Load() != goConnStateEngaged {
		return
	}
	conn.handshakeAttempts = 0
	conn.handshakeDeadline = e.now() + int64(goSynAckRetransmit)
	e.rearmTimer(conn)
}

func (e *goEngine) shutdown() {
	e.closeAllPacketSplices()
	unreset := e.closeAllFlows()
	deadline := e.now() + int64(goShutdownBudget)
	for len(unreset) > 0 {
		remaining := deadline - e.refreshCoarseTime()
		if remaining <= 0 {
			break
		}
		armed, err := e.platformIO.armTransmitWritable()
		if err != nil || !armed {
			time.Sleep(time.Millisecond)
		} else {
			e.platformIO.wait(min(time.Duration(remaining), 10*time.Millisecond), nil)
			e.platformIO.drainWake()
			if !e.platformIO.takeTransmitWritable() {
				time.Sleep(time.Millisecond)
			}
		}
		kept := unreset[:0]
		for _, conn := range unreset {
			if !e.sendReset(conn) {
				kept = append(kept, conn)
			}
		}
		unreset = kept
	}
	for {
		e.reapDying()
		if e.dyingList == nil || e.refreshCoarseTime() >= deadline {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func (e *goEngine) processBurst() error {
	remaining := goReadBatch
	budget := goEngineBurstBytes
	e.tunPending = false
	for remaining > 0 && budget > 0 {
		count, drained, err := e.platformIO.readBurst(e.frames[:remaining])
		if err != nil {
			return err
		}
		for index := range count {
			budget -= len(e.frames[index].data)
			e.processFrame(&e.frames[index])
		}
		if drained || count == 0 {
			return nil
		}
		remaining -= count
	}
	e.tunPending = true
	return nil
}

func (e *goEngine) processFrame(frame *goFrame) {
	parsed, ok := parseForwardPacket(frame.data)
	if !ok {
		return
	}
	if e.dropNonUnicast(&parsed) {
		return
	}
	if parsed.fragment {
		e.reassemble(frame.data, &parsed)
		return
	}
	e.processParsed(frame.data, frame.meta, &parsed)
}

func (e *goEngine) processParsed(packet []byte, meta ForwardFrameMeta, parsed *forwardPacket) {
	if e.handleLoopbackHairpin(packet, meta, parsed) {
		return
	}
	establishedTCP := parsed.protocol == uint8(header.TCPProtocolNumber) && parsed.hasFlow && !parsed.isPureTCPSyn()
	if establishedTCP {
		conn := e.flows[parsed.flowKey()]
		if conn != nil {
			e.inputTCP(conn, parsed)
			return
		}
	}
	if e.dispatchStage.DispatchParsed(packet, meta, parsed) {
		return
	}
	if establishedTCP {
		owner := e.stack.directory.lookup(parsed.flowKey())
		if owner != nil && owner.engine != e {
			owner.engine.inject(packet, meta)
			return
		}
	}
	e.demuxL4(packet, meta, parsed)
}

func (e *goEngine) demuxL4(packet []byte, meta ForwardFrameMeta, parsed *forwardPacket) {
	switch parsed.protocol {
	case uint8(header.TCPProtocolNumber):
		e.demuxTCP(packet, parsed)
	case uint8(header.UDPProtocolNumber):
		e.demuxUDP(packet, meta, parsed)
	case uint8(header.ICMPv4ProtocolNumber), uint8(header.ICMPv6ProtocolNumber):
		e.answerEcho(packet, parsed)
	}
}

func (e *goEngine) dropNonUnicast(parsed *forwardPacket) bool {
	destination := parsed.destination.Addr()
	if parsed.ipVersion == 4 && destination == e.stack.broadcastAddr {
		return true
	}
	return !destination.IsGlobalUnicast()
}

func (e *goEngine) handleLoopbackHairpin(packet []byte, meta ForwardFrameMeta, parsed *forwardPacket) bool {
	if parsed.protocol != uint8(header.TCPProtocolNumber) || len(parsed.transport) < header.TCPMinimumSize {
		return false
	}
	destination := parsed.destination.Addr()
	var loopbackAddresses []netip.Addr
	if parsed.ipVersion == 4 {
		loopbackAddresses = e.stack.inet4LoopbackAddress
	} else {
		loopbackAddresses = e.stack.inet6LoopbackAddress
	}
	if !slices.Contains(loopbackAddresses, destination) {
		return false
	}
	tcpHdr := header.TCP(parsed.transport)
	if parsed.ipVersion == 4 {
		rewriteIPv4TCP(header.IPv4(parsed.network), tcpHdr, false,
			destination, 0, false,
			parsed.source.Addr(), 0, false)
	} else {
		rewriteIPv6TCP(header.IPv6(parsed.network), tcpHdr, false,
			destination, 0, false,
			parsed.source.Addr(), 0, false)
	}
	err := e.platformIO.writeFrame(e.singleFrame(packet), meta)
	if err != nil {
		e.stack.logger.Trace(E.Cause(err, "go: hairpin write"))
	}
	return true
}

func (e *goEngine) now() int64 {
	return e.coarseTime.Load()
}

func (e *goEngine) refreshCoarseTime() int64 {
	now := int64(time.Since(e.epoch))
	e.coarseTime.Store(now)
	return now
}

const (
	goReassemblyTimeout   = 3 * time.Second
	goReassemblyHeadroom  = 64
	goReassemblyCapacity  = goReassemblyHeadroom + 65535
	goReassemblyMaxRanges = 8
)

type goReassemblyRange struct {
	start int
	end   int
}

type goReassemblyEntry struct {
	active       bool
	headerSeen   bool
	ipVersion    uint8
	protocol     uint8
	source       netip.Addr
	destination  netip.Addr
	ident        uint32
	deadline     int64
	headerLength int
	totalLength  int
	buffer       []byte
	ranges       [goReassemblyMaxRanges]goReassemblyRange
	rangeCount   int
}

func (e *goEngine) reassemble(packet []byte, parsed *forwardPacket) {
	if parsed.ipVersion == 4 {
		e.reassembleIPv4(packet, parsed)
	} else {
		e.reassembleIPv6(packet, parsed)
	}
}

func (e *goEngine) reassembleIPv4(packet []byte, parsed *forwardPacket) {
	ipHdr := header.IPv4(parsed.network)
	headerLength := int(ipHdr.HeaderLength())
	if headerLength < header.IPv4MinimumSize || headerLength > len(packet) || headerLength > goReassemblyHeadroom {
		return
	}
	entry := e.reassemblyEntry(4, uint8(ipHdr.TransportProtocol()), parsed.source.Addr(), parsed.destination.Addr(), uint32(ipHdr.ID()))
	offset := int(ipHdr.FragmentOffset())
	if offset == 0 {
		copy(entry.buffer[goReassemblyHeadroom-headerLength:], packet[:headerLength])
		entry.headerLength = headerLength
		entry.headerSeen = true
	}
	e.reassemblyAdd(entry, offset, ipHdr.Payload(), ipHdr.More())
}

func (e *goEngine) reassembleIPv6(packet []byte, parsed *forwardPacket) {
	ipHdr := header.IPv6(parsed.network)
	if ipHdr.NextHeader() != header.IPv6FragmentHeader {
		return
	}
	fragHdr := header.IPv6Fragment(ipHdr.Payload())
	if !fragHdr.IsValid() {
		return
	}
	entry := e.reassemblyEntry(6, fragHdr.NextHeader(), parsed.source.Addr(), parsed.destination.Addr(), fragHdr.ID())
	if !entry.headerSeen {
		copy(entry.buffer[goReassemblyHeadroom-header.IPv6MinimumSize:], packet[:header.IPv6MinimumSize])
		entry.headerLength = header.IPv6MinimumSize
		entry.headerSeen = true
	}
	e.reassemblyAdd(entry, int(fragHdr.FragmentOffset())*8, fragHdr.Payload(), fragHdr.More())
}

func (e *goEngine) reassemblyEntry(ipVersion uint8, protocol uint8, source netip.Addr, destination netip.Addr, ident uint32) *goReassemblyEntry {
	now := e.now()
	var free *goReassemblyEntry
	var oldest *goReassemblyEntry
	for index := range e.reassemblyEntries {
		entry := &e.reassemblyEntries[index]
		if entry.active && entry.deadline <= now {
			entry.active = false
		}
		if !entry.active {
			if free == nil {
				free = entry
			}
			continue
		}
		if entry.ipVersion == ipVersion && entry.protocol == protocol && entry.ident == ident &&
			entry.source == source && entry.destination == destination {
			return entry
		}
		if oldest == nil || entry.deadline < oldest.deadline {
			oldest = entry
		}
	}
	entry := free
	if entry == nil {
		entry = oldest
	}
	if entry.buffer == nil {
		entry.buffer = make([]byte, goReassemblyCapacity)
	}
	entry.active = true
	entry.headerSeen = false
	entry.ipVersion = ipVersion
	entry.protocol = protocol
	entry.source = source
	entry.destination = destination
	entry.ident = ident
	entry.deadline = now + int64(goReassemblyTimeout)
	entry.headerLength = 0
	entry.totalLength = -1
	entry.rangeCount = 0
	if e.reassemblyTickNode.slot == nil {
		e.wheel.schedule(&e.reassemblyTickNode, entry.deadline)
	}
	return entry
}

func (e *goEngine) reassemblyAdd(entry *goReassemblyEntry, offset int, fragment []byte, more bool) {
	if len(fragment) == 0 {
		return
	}
	end := offset + len(fragment)
	if end > 65535 {
		entry.active = false
		return
	}
	if !more {
		if entry.totalLength >= 0 && entry.totalLength != end {
			entry.active = false
			return
		}
		entry.totalLength = end
	}
	if entry.totalLength >= 0 && end > entry.totalLength {
		entry.active = false
		return
	}
	copy(entry.buffer[goReassemblyHeadroom+offset:], fragment)
	if !reassemblyMergeRanges(entry, offset, end) {
		entry.active = false
		return
	}
	if entry.headerSeen && entry.totalLength >= 0 && entry.rangeCount == 1 &&
		entry.ranges[0].start == 0 && entry.ranges[0].end == entry.totalLength {
		e.completeReassembly(entry)
	}
}

func reassemblyMergeRanges(entry *goReassemblyEntry, start int, end int) bool {
	count := entry.rangeCount
	index := 0
	for index < count && entry.ranges[index].end < start {
		index++
	}
	if index == count || entry.ranges[index].start > end {
		if count == goReassemblyMaxRanges {
			return false
		}
		copy(entry.ranges[index+1:count+1], entry.ranges[index:count])
		entry.ranges[index] = goReassemblyRange{start: start, end: end}
		entry.rangeCount = count + 1
		return true
	}
	mergedStart := min(start, entry.ranges[index].start)
	mergedEnd := end
	mergeEnd := index
	for mergeEnd < count && entry.ranges[mergeEnd].start <= end {
		mergedEnd = max(mergedEnd, entry.ranges[mergeEnd].end)
		mergeEnd++
	}
	entry.ranges[index] = goReassemblyRange{start: mergedStart, end: mergedEnd}
	copy(entry.ranges[index+1:], entry.ranges[mergeEnd:count])
	entry.rangeCount = count - (mergeEnd - index) + 1
	return true
}

func (e *goEngine) completeReassembly(entry *goReassemblyEntry) {
	entry.active = false
	if entry.ipVersion == 4 && entry.headerLength+entry.totalLength > 65535 {
		return
	}
	packet := entry.buffer[goReassemblyHeadroom-entry.headerLength : goReassemblyHeadroom+entry.totalLength]
	if entry.ipVersion == 4 {
		ipHdr := header.IPv4(packet)
		ipHdr.SetTotalLength(uint16(len(packet)))
		ipHdr.SetFlagsFragmentOffset(ipHdr.Flags()&^header.IPv4FlagMoreFragments, 0)
		ipHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	} else {
		ipHdr := header.IPv6(packet)
		ipHdr.SetNextHeader(entry.protocol)
		ipHdr.SetPayloadLength(uint16(entry.totalLength))
	}
	parsed, ok := parseForwardPacket(packet)
	if !ok || parsed.fragment {
		return
	}
	e.processParsed(packet, ForwardFrameMeta{}, &parsed)
}

func (e *goEngine) expireReassemblyTick(now int64) {
	next := int64(math.MaxInt64)
	for index := range e.reassemblyEntries {
		entry := &e.reassemblyEntries[index]
		if !entry.active {
			continue
		}
		if entry.deadline <= now {
			entry.active = false
		} else {
			next = min(next, entry.deadline)
		}
	}
	if next != math.MaxInt64 {
		e.wheel.schedule(&e.reassemblyTickNode, next)
	}
}
