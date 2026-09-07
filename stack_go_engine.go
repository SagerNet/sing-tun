package tun

import (
	"hash/maphash"
	"math"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

const (
	goWaitIndefinite    = time.Duration(-1)
	goShutdownBudget    = 250 * time.Millisecond
	goEngineLoadWindow  = 100 * time.Millisecond
	goEngineBusyPercent = 70
)

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
	exitReapPending      atomic.Bool
	exitReapAccess       sync.Mutex
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
	udpNat               *UDPNat
	transmitFrame        [1][]byte
	exitSignal           chan struct{}
	wokeHandlerThisBurst bool
	tunPending           bool
	transmitReady        bool
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
	packetReceiveBuffers [goPacketBatchSize]*buf.Buffer
	packetReceiveBatch   int
	packetMessages       [goPacketBatchSize]goPacketMessage
	packetFrames         [goPacketBatchSize]goUDPFrame
	packetFrameCount     int
	packetUploads        [goPacketBatchSize]goPacketUpload
	packetUploadCount    int
	packetDirtyList      *goSplicePacket
	packetIO             goPacketBatchIO
	packetFlows          map[flowKey]*GoPacketConn
	packetReadOptions    atomic.Pointer[N.ReadWaitOptions]

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
		stack:              stack,
		platformIO:         platformIO,
		dispatcher:         stack.dispatcher,
		dispatchStage:      stack.dispatcher.NewStage(&goWriteback{platformIO: platformIO}),
		epoch:              time.Now(),
		frames:             make([]goFrame, goReadBatch),
		reassemblyEntries:  make([]goReassemblyEntry, goReassemblyEntries),
		exitSignal:         make(chan struct{}),
		flows:              make(map[flowKey]*GoConn),
		flowCapacity:       max(goFlowCapacity/engineCount, 1024),
		slabPool:           newGoSlabPool(stack.memoryPressure, max(goSlabPoolLowWater/engineCount, 8)),
		descriptorPool:     goDescriptorPool{lowWater: max(goDescriptorPoolLowWater/engineCount, 4)},
		sequenceSeed:       maphash.MakeSeed(),
		controlSegments:    make([][]byte, 0, 8),
		socketEvents:       make([]goSocketEvent, goSocketEventBatch),
		spliceSegments:     make([][]byte, 0, 8),
		spliceIovecs:       make([]goIOVector, 0, 8),
		packetFlows:        make(map[flowKey]*GoPacketConn, goReadBatch),
		packetReceiveBatch: goReceiveBatchMin,
	}
	engine.closeMessage.kind = goMessageStackClose
	engine.resetMessage.kind = goMessageStackReset
	engine.injectMessage.kind = goMessageInject
	engine.packetReadOptions.Store(new(N.ReadWaitOptions))
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
		transmitWritable := e.platformIO.takeTransmitWritable()
		if e.transmitReady || transmitWritable {
			e.transmitReady = false
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
		e.drainAckList(e.now(), true)
		e.dispatchStage.Flush()
		e.flushPacketUploads()
		e.flushPacketFrames()
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
	e.releaseReadBuffers()
	e.engineState.Store(goEngineExited)
	message := e.controlStack.head.Swap(nil)
	for message != nil {
		next := message.next
		message.next = nil
		message.queued.Store(false)
		e.releasePending(message)
		message = next
	}
	e.releaseInjected()
	e.slabPool.close()
	if e.dyingList != nil {
		e.exitReapPending.Store(true)
		e.reapAfterExit()
	}
}

func (e *goEngine) reapAfterExit() {
	if !e.exitReapPending.Load() {
		return
	}
	e.exitReapAccess.Lock()
	defer e.exitReapAccess.Unlock()
	e.refreshCoarseTime()
	e.reapDying()
	e.exitReapPending.Store(e.dyingList != nil)
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
	clear(e.packetFlows)
	deadline, scheduled := e.wheel.nextDeadline()
	e.engineState.Store(goEngineParked)
	if e.controlStack.head.Load() != nil {
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
	tunReadable, eventCount, err := e.platformIO.wait(0, e.socketEvents)
	e.transmitReady = e.platformIO.takeTransmitWritable()
	if timeout != 0 && !tunReadable && eventCount == 0 && !e.transmitReady && err == nil && e.controlStack.head.Load() == nil {
		e.releaseReadBuffers()
		tunReadable, eventCount, err = e.platformIO.wait(timeout, e.socketEvents)
	}
	e.engineState.Store(goEngineRunning)
	e.refreshCoarseTime()
	return tunReadable, eventCount, err
}

func (e *goEngine) releaseReadBuffers() {
	e.flushPacketUploads()
	e.flushPacketFrames()
	clear(e.frames)
	e.udpUserData.packet = nil
	clear(e.transmitFrame[:])
	clear(e.spliceSegments[:cap(e.spliceSegments)])
	clear(e.spliceIovecs[:cap(e.spliceIovecs)])
	clear(e.controlSegments[:cap(e.controlSegments)])
	buf.ReleaseMulti(e.packetReceiveBuffers[:])
	clear(e.packetReceiveBuffers[:])
	clear(e.packetMessages[:])
	clear(e.packetFrames[:])
	clear(e.packetUploads[:])
	e.packetIO.reset()
	e.platformIO.releaseReadBuffers()
	for index := range e.reassemblyEntries {
		entry := &e.reassemblyEntries[index]
		if !entry.active {
			entry.buffer.Release()
			entry.buffer = nil
		}
	}
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
	message := e.controlStack.head.Swap(nil)
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
	options := e.packetReadOptions.Load()
	frame := &goInjectedFrame{buffer: options.NewBufferSize(len(packet)), meta: meta}
	common.Must1(frame.buffer.Write(packet))
	options.PostReturn(frame.buffer)
	e.injectStack.push(frame)
	e.postMessage(&e.injectMessage)
}

func (e *goEngine) processInjected() {
	for frame := e.injectStack.popAll(); frame != nil; {
		next := frame.next
		e.injectCount.Add(-1)
		frame.buffer = e.packetReadOptions.Load().Copy(frame.buffer)
		e.processFrame(&goFrame{buffer: frame.buffer, meta: frame.meta})
		e.flushPacketUploads()
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
	for index := range e.reassemblyEntries {
		e.reassemblyEntries[index].active = false
	}
	e.releaseReadBuffers()
	unreset := e.closeAllFlows()
	for conn := e.dyingList; conn != nil; conn = conn.dyingNext {
		e.spliceDetach(conn, net.ErrClosed)
		conn.receiveDrainable.Store(false)
	}
	deadline := e.now() + int64(goShutdownBudget)
	for len(unreset) > 0 {
		e.releaseReadBuffers()
		remaining := deadline - e.refreshCoarseTime()
		if remaining <= 0 {
			break
		}
		armed, err := e.platformIO.armTransmitWritable()
		if err != nil || !armed {
			time.Sleep(time.Millisecond)
		} else {
			e.platformIO.wait(min(time.Duration(remaining), 10*time.Millisecond), nil)
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
		count, drained, err := e.platformIO.readBurst(e.frames[:remaining], *e.packetReadOptions.Load())
		if err != nil {
			return err
		}
		for index := range count {
			budget -= e.frames[index].buffer.Len()
			e.processFrame(&e.frames[index])
		}
		e.flushPacketUploads()
		if drained || count == 0 {
			return nil
		}
		remaining -= count
	}
	e.tunPending = true
	return nil
}

func (e *goEngine) processFrame(frame *goFrame) {
	if frame.meta.gsoType == goUDPGSOType {
		e.processUDPSegments(frame)
		return
	}
	parsed, ok := parseForwardPacket(frame.buffer.Bytes())
	if !ok {
		return
	}
	if e.dropNonUnicast(&parsed) {
		return
	}
	if parsed.fragment {
		e.reassemble(frame.buffer.Bytes(), &parsed)
		return
	}
	e.processParsed(frame.buffer, frame.meta, &parsed)
}

func (e *goEngine) processParsed(buffer *buf.Buffer, meta ForwardFrameMeta, parsed *forwardPacket) {
	packet := buffer.Bytes()
	if e.handleLoopbackHairpin(packet, meta, parsed) {
		return
	}
	if parsed.protocol == uint8(header.UDPProtocolNumber) && parsed.hasFlow {
		writer := e.packetFlows[parsed.flowKey()]
		if writer != nil && writer.splice != nil {
			conn := writer.conn.Load()
			if conn != nil && !conn.isClosed() && conn.service.state.Load() == udpNatStateStarted {
				e.packetSpliceInput(writer, buffer, parsed)
				return
			}
		}
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
	e.demuxL4(buffer, meta, parsed)
}

func (e *goEngine) demuxL4(buffer *buf.Buffer, meta ForwardFrameMeta, parsed *forwardPacket) {
	switch parsed.protocol {
	case uint8(header.TCPProtocolNumber):
		e.demuxTCP(buffer.Bytes(), parsed)
	case uint8(header.UDPProtocolNumber):
		e.demuxUDP(buffer, meta, parsed)
	case uint8(header.ICMPv4ProtocolNumber), uint8(header.ICMPv6ProtocolNumber):
		e.answerEcho(buffer.Bytes(), parsed)
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
	buffer       *buf.Buffer
	headroom     int
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
		copy(entry.buffer.Range(entry.headroom-headerLength, entry.headroom), packet[:headerLength])
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
		copy(entry.buffer.Range(entry.headroom-header.IPv6MinimumSize, entry.headroom), packet[:header.IPv6MinimumSize])
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
	options := e.packetReadOptions.Load()
	bufferSize := options.FrontHeadroom + goReassemblyCapacity + options.RearHeadroom
	if entry.buffer == nil || entry.buffer.RawCap() < bufferSize {
		entry.buffer.Release()
		entry.buffer = buf.NewSize(bufferSize)
	} else {
		entry.buffer.Reset()
	}
	entry.headroom = options.FrontHeadroom + goReassemblyHeadroom
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
	copy(entry.buffer.Range(entry.headroom+offset, entry.headroom+end), fragment)
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
	buffer := entry.buffer
	buffer.Resize(entry.headroom-entry.headerLength, entry.headerLength+entry.totalLength)
	packet := buffer.Bytes()
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
	e.processParsed(buffer, ForwardFrameMeta{}, &parsed)
	e.flushPacketUploads()
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

func (e *goEngine) answerEcho(packet []byte, parsed *forwardPacket) {
	switch parsed.protocol {
	case uint8(header.ICMPv4ProtocolNumber):
		if len(parsed.transport) < header.ICMPv4MinimumSize {
			return
		}
		if !rewriteEchoReplyIPv4(header.IPv4(parsed.network), header.ICMPv4(parsed.transport)) {
			return
		}
	case uint8(header.ICMPv6ProtocolNumber):
		if len(parsed.transport) < header.ICMPv6MinimumSize {
			return
		}
		if !rewriteEchoReplyIPv6(header.IPv6(parsed.network), header.ICMPv6(parsed.transport)) {
			return
		}
	default:
		return
	}
	err := e.platformIO.writeFrame(e.singleFrame(packet), ForwardFrameMeta{})
	if err != nil {
		e.stack.logger.Trace(E.Cause(err, "go: write echo reply"))
	}
}
