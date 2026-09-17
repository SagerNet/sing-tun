package tun

import (
	"errors"
	"hash/maphash"
	"math"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	tcpip "github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
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
	goMessageConnDial
	goMessageConnEngage
	goMessageConnClose
	goMessageConnReadShut
	goMessageConnRetransmit
	goMessageConnWindow
	goMessageConnTransmit
	goMessageConnBlocked
	goMessageConnDropped
	goMessageConnPacing
	goMessageConnThrottle
	goMessageConnSplice
	goMessageConnKeepalive
	goMessageConnTransmitted
	goMessagePacketSplice
	goMessagePacketClose
	goMessageUDPOpen
	goMessageUDPClose
	goMessageListenOpen
	goMessageListenClose
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
	next     *goMessage
	conn     *GoConn
	packet   *GoPacketConn
	socket   *GoUDPConn
	listener *GoListener
	queued   atomic.Bool
	kind     uint8
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
	dispatchTickNode     goWheelNode
	reassemblyEntries    []goReassemblyEntry
	udpUserData          goUDPUserData
	udpNat               *UDPNat
	transmitFrame        [1][]byte
	exitSignal           chan struct{}
	wokeHandlerThisBurst bool
	tunPending           bool
	transmitReady        bool
	readBuffersHeld      bool
	idleSince            int64
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
	packetSlots          goReadSlots
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
	udpSockets           map[netip.AddrPort]*GoUDPConn
	tcpListeners         map[netip.AddrPort]*GoListener

	flows           map[flowKey]*GoConn
	flowCapacity    int
	slabPool        *goSlabPool
	descriptorPool  goDescriptorPool
	sequenceSeed    maphash.Seed
	ackList         *GoConn
	blockedList     *GoConn
	blockedTail     *GoConn
	dyingList       *GoConn
	reclaimPending  bool
	resetBurst      int
	controlIdent    uint32
	controlScratch  [goHeaderScratchSize]byte
	controlSegments [][]byte
	sackScratch     [goMaxSackBlocks]goSackBlock
	sackRaw         [goMaxSackBlocks]goRawSackBlock
	rateSample      goRateSample
	ackSample       goAckSample

	gsoSlots    goReadSlots
	gsoSegments [goGSOMaxSegments][]byte
	gsoSizes    [goGSOMaxSegments]int
	gsoFrame    goFrame
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
		epoch:              time.Now(),
		frames:             make([]goFrame, goReadBatch),
		reassemblyEntries:  make([]goReassemblyEntry, goReassemblyEntries),
		exitSignal:         make(chan struct{}),
		flows:              stack.directory.flows,
		flowCapacity:       max(goFlowCapacity/engineCount, 1024),
		slabPool:           newGoSlabPool(stack.memoryPressure, max(goSlabPoolLowWater/engineCount, 8)),
		sequenceSeed:       maphash.MakeSeed(),
		controlSegments:    make([][]byte, 0, 8),
		socketEvents:       make([]goSocketEvent, goSocketEventBatch),
		spliceSegments:     make([][]byte, 0, 8),
		spliceIovecs:       make([]goIOVector, 0, 8),
		packetFlows:        make(map[flowKey]*GoPacketConn, goReadBatch),
		packetReceiveBatch: goReceiveBatchMin,
		udpSockets:         stack.directory.udpSockets,
		tcpListeners:       stack.directory.listeners,
	}
	if engineCount > 1 {
		engine.flows = make(map[flowKey]*GoConn)
		engine.udpSockets = make(map[netip.AddrPort]*GoUDPConn)
		engine.tcpListeners = make(map[netip.AddrPort]*GoListener)
	}
	if stack.dispatcher != nil {
		engine.dispatchStage = stack.dispatcher.NewStage(&goWriteback{platformIO: platformIO})
	}
	engine.closeMessage.kind = goMessageStackClose
	engine.resetMessage.kind = goMessageStackReset
	engine.injectMessage.kind = goMessageInject
	engine.packetReadOptions.Store(new(N.ReadWaitOptions))
	engine.delayedAckTickNode.expire = func(now int64) { engine.drainAckList(now, false) }
	engine.reassemblyTickNode.expire = engine.expireReassemblyTick
	engine.dispatchTickNode.expire = func(int64) { engine.dispatchStage.Flush() }
	engine.refreshCoarseTime()
	engine.wheel.currentTick = engine.coarseTime.Load() / goWheelTick
	return engine
}

func (e *goEngine) run() {
	defer close(e.exitSignal)
	defer e.exit()
	e.loadWindowStart = e.coarseTime.Load()
	for {
		parkStart := int64(time.Since(e.epoch))
		tunReadable, eventCount, err := e.park()
		e.parkedNanos += e.coarseTime.Load() - parkStart
		e.updateLoad(e.coarseTime.Load())
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
			if !errors.Is(err, os.ErrClosed) {
				e.stack.logger.Error(E.Cause(err, "go: engine wait"))
			}
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
		e.wheel.advance(e.coarseTime.Load())
		e.drainAckList(e.coarseTime.Load(), true)
		if e.dispatchStage != nil {
			e.dispatchStage.Flush()
			remaining, pending := e.dispatchStage.sweepDue()
			if pending && e.dispatchTickNode.slot == nil {
				e.wheel.schedule(&e.dispatchTickNode, e.coarseTime.Load()+int64(remaining))
			}
		}
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
	e.packetSlots.release()
	e.gsoSlots.release()
	e.engineState.Store(goEngineExited)
	e.releaseControlQueue()
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
		timeout = max(time.Duration(deadline-e.coarseTime.Load()), 0)
	}
	if e.tunPending {
		timeout = 0
	}
	tunReadable, eventCount, err := e.platformIO.wait(0, e.socketEvents)
	e.transmitReady = e.platformIO.takeTransmitWritable()
	if timeout != 0 && !tunReadable && eventCount == 0 && !e.transmitReady && err == nil && e.controlStack.head.Load() == nil {
		tunReadable, eventCount, err = e.platformIO.wait(e.idleTimeout(timeout), e.socketEvents)
	}
	if tunReadable || eventCount > 0 {
		e.readBuffersHeld = true
		e.idleSince = -1
	}
	e.engineState.Store(goEngineRunning)
	e.refreshCoarseTime()
	return tunReadable, eventCount, err
}

func (e *goEngine) idleTimeout(timeout time.Duration) time.Duration {
	if !e.readBuffersHeld {
		return timeout
	}
	now := e.coarseTime.Load()
	if e.idleSince < 0 {
		e.idleSince = now
	}
	releaseAt := e.idleSince + int64(goReadBufferIdle)
	if now >= releaseAt || e.slabPool.pressureLevel() != MemoryPressureNone {
		e.releaseReadBuffers()
		return timeout
	}
	if timeout == goWaitIndefinite || time.Duration(releaseAt-now) < timeout {
		return time.Duration(releaseAt - now)
	}
	return timeout
}

func (e *goEngine) releaseReadBuffers() {
	e.readBuffersHeld = false
	e.flushPacketUploads()
	e.flushPacketFrames()
	clear(e.frames)
	e.udpUserData.packet = nil
	clear(e.transmitFrame[:])
	clear(e.spliceSegments[:cap(e.spliceSegments)])
	clear(e.spliceIovecs[:cap(e.spliceIovecs)])
	clear(e.controlSegments[:cap(e.controlSegments)])
	e.packetSlots.sleep()
	e.gsoSlots.sleep()
	clear(e.gsoSegments[:])
	e.gsoFrame = goFrame{}
	clear(e.packetMessages[:])
	clear(e.packetFrames[:])
	clear(e.packetUploads[:])
	e.packetIO.reset()
	e.platformIO.releaseReadBuffers()
	e.slabPool.purge()
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
		e.releaseControlQueue()
	}
}

func (e *goEngine) releaseControlQueue() {
	message := e.controlStack.head.Swap(nil)
	for message != nil {
		next := message.next
		message.next = nil
		message.queued.Store(false)
		e.releasePending(message)
		message = next
	}
}

func (e *goEngine) drainControlQueue() {
	message := e.controlStack.head.Swap(nil)
	if message != nil {
		e.readBuffersHeld = true
		e.idleSince = -1
	}
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
		e.reclaimPending = true
	case goMessageConnDial:
		e.handleDial(message.conn)
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
	case goMessageConnTransmit:
		e.handleTransmitRequest(message.conn)
	case goMessageConnBlocked:
		e.handleTransmitBlocked(message.conn)
	case goMessageConnDropped:
		e.handleDroppedFrames(message.conn)
	case goMessageConnPacing:
		e.handlePacingRequest(message.conn)
	case goMessageConnThrottle:
		if !message.conn.dead {
			message.conn.wakeTransmitter()
		}
	case goMessageConnSplice:
		e.handleSpliceEngage(message.conn)
	case goMessageConnKeepalive:
		e.handleKeepaliveUpdate(message.conn)
	case goMessageConnTransmitted:
		e.handleTransmitted(message.conn)
	case goMessagePacketSplice:
		e.handlePacketSpliceEngage(message.packet)
	case goMessagePacketClose:
		e.handlePacketSpliceClose(message.packet)
	case goMessageUDPOpen:
		e.handleUDPOpen(message.socket)
	case goMessageUDPClose:
		e.handleUDPClose(message.socket)
	case goMessageListenOpen:
		e.handleListenOpen(message.listener)
	case goMessageListenClose:
		e.handleListenClose(message.listener)
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
	if conn.dead || conn.phase != goPhaseJudged {
		return
	}
	conn.access.Lock()
	conn.phase = goPhaseEngaged
	conn.access.Unlock()
	err := goIgnoreDropped(conn.engine.platformIO.writePacket(conn.handshakeImage[:conn.handshakeLength], ForwardFrameMeta{}))
	if err != nil {
		e.sendReset(conn)
		e.detachConn(conn, E.Cause(err, "go: send SYN-ACK"), goDeathAbortLinger)
		return
	}
	conn.handshakeAttempts = 0
	conn.handshakeDeadline = e.coarseTime.Load() + int64(goSynAckRetransmit)
	e.rearmTimer(conn)
}

func (e *goEngine) shutdown() {
	e.closeAllPacketSplices()
	e.closeAllUDPSockets()
	e.closeAllListeners()
	for index := range e.reassemblyEntries {
		e.reassemblyEntries[index].discard()
	}
	e.releaseReadBuffers()
	unreset := e.closeAllFlows()
	for conn := e.dyingList; conn != nil; conn = conn.dyingNext {
		e.spliceDetach(conn, net.ErrClosed)
		conn.access.Lock()
		conn.drainable = false
		conn.access.Unlock()
	}
	deadline := e.coarseTime.Load() + int64(goShutdownBudget)
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
	if e.stack.validateChecksum && parsed.ipVersion == 4 && !header.IPv4(parsed.network).IsChecksumValid() {
		return
	}
	if e.dropNonUnicast(&parsed) {
		return
	}
	if parsed.fragment {
		if parsed.ipVersion == 4 {
			e.reassembleIPv4(frame.buffer.Bytes(), &parsed)
		} else {
			e.reassembleIPv6(frame.buffer.Bytes(), &parsed)
		}
		return
	}
	e.processParsed(frame.buffer, frame.meta, &parsed)
}

func (e *goEngine) processParsed(buffer *buf.Buffer, meta ForwardFrameMeta, parsed *forwardPacket) {
	if parsed.protocol == uint8(header.UDPProtocolNumber) {
		if len(parsed.transport) < header.UDPMinimumSize {
			return
		}
		length := int(header.UDP(parsed.transport).Length())
		if length < header.UDPMinimumSize || length > len(parsed.transport) {
			return
		}
		parsed.transport = parsed.transport[:length]
	}
	if e.stack.validateChecksum && !goValidateTransportChecksum(parsed) {
		return
	}
	packet := buffer.Bytes()
	if e.handleLoopbackHairpin(packet, meta, parsed) {
		return
	}
	if parsed.protocol == uint8(header.UDPProtocolNumber) && parsed.hasFlow {
		if socket := e.udpSockets[parsed.destination]; socket != nil {
			e.inputUDPSocket(socket, parsed)
			return
		}
		if len(e.stack.engines) > 1 {
			if owner := e.stack.directory.lookupUDPSocket(parsed.destination); owner != nil && owner.engine != e {
				owner.engine.inject(packet, meta)
				return
			}
		}
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
	} else if parsed.hasFlow && parsed.isPureTCPSyn() && e.lookupListener(parsed.destination) != nil {
		e.demuxL4(buffer, meta, parsed)
		return
	}
	if e.dispatchStage != nil && e.dispatchStage.DispatchParsed(packet, meta, parsed) {
		return
	}
	if establishedTCP && len(e.stack.engines) > 1 {
		owner := e.stack.directory.lookup(parsed.flowKey())
		if owner != nil && owner.engine != e {
			owner.engine.inject(packet, meta)
			return
		}
	}
	e.demuxL4(buffer, meta, parsed)
}

func goValidateTransportChecksum(parsed *forwardPacket) bool {
	transport := parsed.transport
	switch parsed.protocol {
	case uint8(header.TCPProtocolNumber):
		if len(transport) < header.TCPMinimumSize {
			return false
		}
	case uint8(header.UDPProtocolNumber):
		if len(transport) < header.UDPMinimumSize {
			return false
		}
		udpHeader := header.UDP(transport)
		length := int(udpHeader.Length())
		if length < header.UDPMinimumSize || length > len(transport) {
			return false
		}
		if udpHeader.Checksum() == 0 {
			return parsed.ipVersion == 4
		}
		transport = transport[:length]
	case uint8(header.ICMPv4ProtocolNumber):
		return len(transport) >= header.ICMPv4MinimumSize && checksum.Checksum(transport, 0) == 0xffff
	case uint8(header.ICMPv6ProtocolNumber):
		if len(transport) < header.ICMPv6MinimumSize {
			return false
		}
	default:
		return true
	}
	partial := header.PseudoHeaderChecksum(tcpip.TransportProtocolNumber(parsed.protocol), parsed.source.Addr().AsSlice(), parsed.destination.Addr().AsSlice(), uint16(len(transport)))
	return checksum.Checksum(transport, partial) == 0xffff
}

func (e *goEngine) demuxL4(buffer *buf.Buffer, meta ForwardFrameMeta, parsed *forwardPacket) {
	switch parsed.protocol {
	case uint8(header.TCPProtocolNumber):
		e.demuxTCP(buffer.Bytes(), parsed)
	case uint8(header.UDPProtocolNumber):
		e.demuxUDP(buffer, meta, parsed)
	case uint8(header.ICMPv4ProtocolNumber), uint8(header.ICMPv6ProtocolNumber):
		if parsed.isICMPError() {
			e.inputICMPError(parsed)
			return
		}
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

func (r *goReassemblyEntry) discard() {
	r.active = false
	r.buffer.Release()
	r.buffer = nil
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
	now := e.coarseTime.Load()
	var free *goReassemblyEntry
	var oldest *goReassemblyEntry
	for index := range e.reassemblyEntries {
		entry := &e.reassemblyEntries[index]
		if entry.active && entry.deadline <= now {
			entry.discard()
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
		entry.discard()
		return
	}
	if !more {
		if entry.totalLength >= 0 && entry.totalLength != end {
			entry.discard()
			return
		}
		entry.totalLength = end
	}
	if entry.totalLength >= 0 && end > entry.totalLength {
		entry.discard()
		return
	}
	copy(entry.buffer.Range(entry.headroom+offset, entry.headroom+end), fragment)
	if !reassemblyMergeRanges(entry, offset, end) {
		entry.discard()
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
	buffer := entry.buffer
	entry.buffer = nil
	defer buffer.Release()
	if entry.ipVersion == 4 && entry.headerLength+entry.totalLength > 65535 {
		return
	}
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
			entry.discard()
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
	err := e.platformIO.writeDatagram(packet, ForwardFrameMeta{})
	if err != nil {
		e.stack.logger.Trace(E.Cause(err, "go: write echo reply"))
	}
}
