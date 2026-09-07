package tun

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

const (
	goConnStateJudged uint32 = iota
	goConnStateEngaged
	goConnStateEstablished
	goConnStateAborted
	goConnStateDead
)

const (
	goTCPSynReceived uint8 = iota
	goTCPEstablished
	goTCPFinWait1
	goTCPFinWait2
	goTCPClosing
	goTCPCloseWait
	goTCPLastAck
	goTCPClosed
)

const (
	goCloseModeNone uint32 = iota
	goCloseModeGraceful
	goCloseModeAbort
)

const (
	goDeathImmediate uint8 = iota
	goDeathFinLinger
	goDeathAbortLinger
)

const (
	goTimeUnit         = 4096
	goTimestampShift   = 20
	goLocalWindowShift = 7
)

var errGoReset = E.Cause(syscall.ECONNRESET, "go: connection reset by peer")

type goPostedReceive struct {
	buffer *buf.Buffer
	direct []byte
	target []byte
	filled int
}

type goConnError struct {
	err error
}

type GoConn struct {
	engine                 *goEngine
	key                    flowKey
	source                 M.Socksaddr
	destination            M.Socksaddr
	epoch                  int64
	receiveNext            uint64
	receiveCapacity        uint64
	receiveCapacityMax     uint64
	publishedEdge          uint64
	receiveRoundTripMark   uint64
	receiveRoundTripStamp  int64
	receiveSpaceConsumed   uint64
	receiveSpaceCopied     uint64
	receiveSpaceStamp      int64
	receiveChain           goSlabChain
	oooRanges              *goRangeSet
	dsackStart             uint64
	dsackEnd               uint64
	congestionWindow       uint32
	slowStartThreshold     uint32
	undoCongestionWindow   uint32
	undoSlowStartThreshold uint32
	undoRetransmits        int32
	smoothedRoundTrip      int32
	roundTripVariance      int32
	retransmitTimeout      int32
	receiveRoundTrip       int32
	recoveryPoint          uint64
	highestSacked          uint64
	highestRetransmit      uint64
	pipe                   uint64
	undoMarker             uint64
	undoLimit              uint64
	peerWindow             uint64
	ackPending             uint64
	ackCovered             uint64
	lastAckSent            uint64
	lastActivity           int64
	sweepSentTail          uint64
	retransmitPoint        uint64
	retransmitHighWater    uint64
	windowLeft1            int64
	windowLeft2            int64
	ackedBytes             uint32
	keepaliveProbes        uint8
	finWait2Since          int64
	scoreboard             goScoreboard
	frtoRecoveryPoint      uint64
	frtoSendLimit          uint64
	timerNode              goWheelNode
	retransmitDeadline     int64
	probeDeadline          int64
	persistDeadline        int64
	lingerDeadline         int64
	handshakeDeadline      int64
	retransmitAttempts     uint8
	probeAttempts          uint8
	handshakeAttempts      uint8
	persistAttempts        uint8
	duplicateAckCount      uint8
	frtoState              uint8
	state                  uint8
	ipVersion              uint8
	deathClass             uint8
	peerWindowShift        uint8
	localWindowShift       uint8
	peerMSS                uint16
	effectiveMSS           uint16
	lastPeerWindow         uint16
	synAckLength           uint8
	keyed                  bool
	finPending             bool
	sackPermitted          bool
	timestampsEnabled      bool
	discardReceive         bool
	finSent                bool
	finAcked               bool
	finReceived            bool
	inRecovery             bool
	ackForced              bool
	ackDirty               bool
	onBlockedList          bool
	onDyingList            bool
	clientISN              uint32
	sendISN                uint32
	finOffset              uint64
	dyingSince             int64
	ackNext                *GoConn
	blockedNext            *GoConn
	dyingNext              *GoConn
	synAckImage            [96]byte
	_                      [64]byte

	sendPermit               atomic.Uint64
	sendUnacked              atomic.Uint64
	sendReleased             atomic.Uint64
	receiveNextAck           atomic.Uint64
	receiveEdge              atomic.Uint64
	sentEdge                 atomic.Uint64
	receiveAvailable         atomic.Uint64
	receiveCapacityPublished atomic.Uint64
	windowUpdateThreshold    atomic.Uint64
	tsRecent                 atomic.Uint32
	ident                    atomic.Uint32
	connState                atomic.Uint32
	receiveShutdown          atomic.Bool
	everEstablished          atomic.Bool
	receiveDrainable         atomic.Bool
	receiveReleased          atomic.Bool
	_                        [64]byte

	sentTail          atomic.Uint64
	transmittedTail   atomic.Uint64
	bufferedTail      atomic.Uint64
	writerParked      atomic.Bool
	retransmitArmed   atomic.Bool
	writerActive      atomic.Int32
	writerNeeds       atomic.Int32
	transmitterActive atomic.Int32
	transmitOwner     atomic.Int32
	_                 [64]byte

	consumedTail atomic.Uint64
	readerParked atomic.Bool
	readerActive atomic.Int32
	postedTarget atomic.Pointer[goPostedReceive]
	targetDone   atomic.Bool
	_            [64]byte

	transmitStore    goTransmitStore
	slabHolder       goSlabHolder
	transmitScratch  [goHeaderScratchSize]byte
	transmitSegments [][]byte
	descriptors      goDescriptorRing
	blockedSegment   goSegment
	blockedFrame     [][]byte
	blockedMeta      ForwardFrameMeta
	blockedValid     bool

	receiveTarget   goPostedReceive
	readWaitOptions N.ReadWaitOptions
	readDeadline    pipe.Deadline
	writeDeadline   pipe.Deadline

	writeAccess       sync.Mutex
	readAccess        sync.Mutex
	readSignal        goSignal
	writeSignal       goSignal
	transmitSignal    goSignal
	establishedSignal chan struct{}
	closeSignal       chan struct{}
	connErr           atomic.Pointer[goConnError]
	closeMode         atomic.Uint32
	writeShut         atomic.Bool
	readShut          atomic.Bool
	userClosed        atomic.Bool
	finRequested      atomic.Bool
	engageMessage     goMessage
	closeMessage      goMessage
	readShutMessage   goMessage
	retransmitMessage goMessage
	windowMessage     goMessage
	blockedMessage    goMessage
	droppedMessage    goMessage
	spliceMessage     goMessage
	splicePending     atomic.Pointer[goSpliceStream]
	spliced           atomic.Bool
	splice            *goSpliceStream
}

func (c *GoConn) initialize(engine *goEngine, key flowKey, source M.Socksaddr, destination M.Socksaddr) {
	c.engine = engine
	c.key = key
	c.source = source
	c.destination = destination
	c.epoch = engine.now()
	c.readDeadline = pipe.MakeDeadline()
	c.writeDeadline = pipe.MakeDeadline()
	c.readSignal = make(goSignal, 1)
	c.writeSignal = make(goSignal, 1)
	c.transmitSignal = make(goSignal, 1)
	c.establishedSignal = make(chan struct{})
	c.closeSignal = make(chan struct{})
	c.receiveChain = goSlabChain{maxSlots: goReceiveCapacityMax/goSlabSize + 1, pool: engine.slabPool, holder: &c.slabHolder}
	c.transmitStore.chain = goSlabChain{maxSlots: goTransmitCapacityMax/goSlabSize + 1, pool: engine.slabPool, holder: &c.slabHolder}
	c.descriptors.pool = &engine.descriptorPool
	c.timerNode.expire = c.expireTimer
	c.engageMessage = goMessage{kind: goMessageConnEngage, conn: c}
	c.closeMessage = goMessage{kind: goMessageConnClose, conn: c}
	c.readShutMessage = goMessage{kind: goMessageConnReadShut, conn: c}
	c.retransmitMessage = goMessage{kind: goMessageConnRetransmit, conn: c}
	c.windowMessage = goMessage{kind: goMessageConnWindow, conn: c}
	c.blockedMessage = goMessage{kind: goMessageConnBlocked, conn: c}
	c.droppedMessage = goMessage{kind: goMessageConnDropped, conn: c}
	c.spliceMessage = goMessage{kind: goMessageConnSplice, conn: c}
}

func (c *GoConn) sendNext() uint64 {
	if c.finSent {
		return c.finOffset + 1
	}
	return c.transmittedTail.Load()
}

func (c *GoConn) ackThreshold() uint64 {
	threshold := min(2*uint64(c.effectiveMSS), c.receiveCapacity/2)
	if c.engine.ackCoalescing {
		threshold = min(max(threshold, min(c.receiveCapacity/4, goAckCoalesceBytes)), c.receiveCapacity/2)
	}
	return threshold
}

func (c *GoConn) stamp(now int64) int32 {
	return int32((now - c.epoch) / goTimeUnit)
}

func (c *GoConn) storeError(err error) {
	c.connErr.CompareAndSwap(nil, &goConnError{err: err})
}

func (c *GoConn) loadError() error {
	value := c.connErr.Load()
	if value == nil {
		return nil
	}
	return value.err
}

func (c *GoConn) closeError() error {
	err := c.loadError()
	if err != nil {
		return err
	}
	return net.ErrClosed
}

func (c *GoConn) enterWriter() bool {
	c.writerActive.Add(1)
	if c.connState.Load() >= goConnStateAborted {
		c.writerActive.Add(-1)
		c.engine.reapAfterExit()
		return false
	}
	return true
}

func (c *GoConn) exitWriter() {
	c.writerActive.Add(-1)
	c.engine.reapAfterExit()
	if c.finRequested.Load() {
		c.engine.postMessage(&c.closeMessage)
	}
}

func (c *GoConn) enterReader() bool {
	c.readerActive.Add(1)
	state := c.connState.Load()
	if state < goConnStateAborted {
		return true
	}
	if state == goConnStateDead && c.receiveDrainable.Load() && !c.receiveReleased.Load() {
		return true
	}
	c.exitReader()
	return false
}

func (c *GoConn) exitReader() {
	c.readerActive.Add(-1)
	c.engine.reapAfterExit()
}

func (c *GoConn) requestAbort(err error) {
	c.storeError(err)
	c.closeMode.Store(goCloseModeAbort)
	c.engine.postMessage(&c.closeMessage)
}

func (c *GoConn) awaitHandshake(ctx context.Context, deadlineSignal <-chan struct{}) error {
	state := c.connState.Load()
	if state >= goConnStateEstablished {
		return c.handshakeResult()
	}
	select {
	case <-deadlineSignal:
		return os.ErrDeadlineExceeded
	default:
	}
	if c.connState.CompareAndSwap(goConnStateJudged, goConnStateEngaged) {
		err := c.writeSynAck()
		if err != nil {
			c.requestAbort(E.Cause(err, "go: send SYN-ACK"))
			return err
		}
		c.engine.postMessage(&c.engageMessage)
	}
	select {
	case <-c.establishedSignal:
		return c.handshakeResult()
	case <-deadlineSignal:
		return os.ErrDeadlineExceeded
	case <-ctx.Done():
		c.requestAbort(ctx.Err())
		return E.Cause(ctx.Err(), "go: handshake")
	case <-c.engine.stack.ctx.Done():
		cause := context.Cause(c.engine.stack.ctx)
		c.requestAbort(cause)
		return E.Cause(cause, "go: handshake")
	}
}

func (c *GoConn) handshakeResult() error {
	err := c.loadError()
	if err != nil {
		return err
	}
	if c.everEstablished.Load() {
		return nil
	}
	if c.connState.Load() >= goConnStateAborted {
		return net.ErrClosed
	}
	return nil
}

func (c *GoConn) HandshakeFailure(err error) error {
	if c.connState.CompareAndSwap(goConnStateJudged, goConnStateAborted) {
		c.storeError(err)
		writeErr := c.writeReset()
		c.closeMode.Store(goCloseModeAbort)
		c.engine.postMessage(&c.closeMessage)
		return writeErr
	}
	if c.connState.Load() >= goConnStateAborted {
		return os.ErrInvalid
	}
	c.userClosed.Store(true)
	c.requestAbort(err)
	return nil
}

func (c *GoConn) HandshakeSuccess() error {
	return c.awaitHandshake(context.Background(), nil)
}

func (c *GoConn) NeedHandshakeForRead() bool {
	return c.connState.Load() < goConnStateEstablished
}

func (c *GoConn) NeedHandshakeForWrite() bool {
	return c.connState.Load() < goConnStateEstablished
}

func (c *GoConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.readWaitOptions = options
	return false
}

func (c *GoConn) WaitReadBuffer() (*buf.Buffer, error) {
	err := c.awaitHandshake(context.Background(), c.readDeadline.Wait())
	if err != nil {
		return nil, err
	}
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if !c.enterReader() {
		return nil, c.receiveResult()
	}
	defer c.exitReader()
	for {
		select {
		case <-c.readDeadline.Wait():
			return nil, os.ErrDeadlineExceeded
		default:
		}
		available := c.receiveAvailable.Load()
		consumed := c.consumedTail.Load()
		if available > consumed {
			buffer := c.readWaitOptions.NewBuffer()
			n := c.copyReceived(buffer.FreeBytes(), consumed, available)
			buffer.Truncate(n)
			c.advanceConsumed(n)
			c.readWaitOptions.PostReturn(buffer)
			return buffer, nil
		}
		result := c.receiveResult()
		if result != nil {
			return nil, result
		}
		c.receiveTarget.buffer = c.readWaitOptions.NewBuffer()
		delivered, parkErr := c.parkReader()
		if delivered {
			buffer := c.receiveTarget.buffer
			c.receiveTarget.buffer = nil
			buffer.Truncate(c.receiveTarget.filled)
			c.advanceConsumed(c.receiveTarget.filled)
			c.readWaitOptions.PostReturn(buffer)
			return buffer, nil
		}
		c.receiveTarget.buffer.Release()
		c.receiveTarget.buffer = nil
		if parkErr != nil {
			return nil, parkErr
		}
	}
}

func (c *GoConn) Read(p []byte) (int, error) {
	err := c.awaitHandshake(context.Background(), c.readDeadline.Wait())
	if err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if !c.enterReader() {
		return 0, c.receiveResult()
	}
	defer c.exitReader()
	for {
		select {
		case <-c.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		default:
		}
		available := c.receiveAvailable.Load()
		consumed := c.consumedTail.Load()
		if available > consumed {
			n := c.copyReceived(p, consumed, available)
			c.advanceConsumed(n)
			return n, nil
		}
		result := c.receiveResult()
		if result != nil {
			return 0, result
		}
		c.receiveTarget.buffer = nil
		c.receiveTarget.direct = p
		delivered, parkErr := c.parkReader()
		c.receiveTarget.direct = nil
		if delivered {
			n := c.receiveTarget.filled
			c.advanceConsumed(n)
			return n, nil
		}
		if parkErr != nil {
			return 0, parkErr
		}
	}
}

func (c *GoConn) receiveResult() error {
	err := c.loadError()
	if err != nil {
		return err
	}
	if c.userClosed.Load() {
		return net.ErrClosed
	}
	if c.readShut.Load() || c.receiveShutdown.Load() {
		return io.EOF
	}
	if c.connState.Load() >= goConnStateAborted {
		return io.EOF
	}
	return nil
}

func (c *GoConn) wakeUser() {
	c.readSignal.notify()
	c.writeSignal.notify()
}

func (c *GoConn) copyReceived(target []byte, consumed uint64, available uint64) int {
	length := min(len(target), int(available-consumed))
	c.receiveChain.readAt(consumed, target[:length])
	return length
}

func (c *GoConn) advanceConsumed(n int) {
	if c.windowUpdateDue(c.consumedTail.Add(uint64(n))) {
		c.engine.postMessage(&c.windowMessage)
	}
}

func (c *GoConn) windowUpdateDue(consumed uint64) bool {
	edge := c.sentEdge.Load()
	capacity := c.receiveCapacityPublished.Load()
	free := consumed + capacity
	if free <= edge || free-edge < c.windowUpdateThreshold.Load() {
		return false
	}
	available := c.receiveAvailable.Load()
	if available < edge {
		window := edge - available
		if 2*window > capacity || free-available < 2*window {
			return false
		}
	}
	return true
}

func (c *GoConn) parkReader() (bool, error) {
	target := &c.receiveTarget
	target.filled = 0
	if target.buffer != nil {
		target.target = target.buffer.FreeBytes()
	} else {
		target.target = target.direct
	}
	c.targetDone.Store(false)
	c.readSignal.drain()
	c.postedTarget.Store(target)
	c.readerParked.Store(true)
	if c.receiveAvailable.Load() > c.consumedTail.Load() || c.receiveResult() != nil {
		c.readerParked.Store(false)
		return c.claimTarget(target), nil
	}
	deadlineSignal := c.readDeadline.Wait()
	select {
	case <-c.readSignal:
		c.readerParked.Store(false)
		return c.claimTarget(target), nil
	case <-deadlineSignal:
		c.readerParked.Store(false)
		if c.claimTarget(target) {
			return true, nil
		}
		if c.receiveAvailable.Load() > c.consumedTail.Load() {
			return false, nil
		}
		return false, os.ErrDeadlineExceeded
	case <-c.closeSignal:
		c.readerParked.Store(false)
		if c.claimTarget(target) {
			return true, nil
		}
		return false, nil
	}
}

func (c *GoConn) claimTarget(target *goPostedReceive) bool {
	if c.postedTarget.CompareAndSwap(target, nil) {
		return false
	}
	for !c.targetDone.Load() {
		<-c.readSignal
	}
	return true
}

func (c *GoConn) Close() error {
	if c.connState.CompareAndSwap(goConnStateJudged, goConnStateAborted) {
		c.storeError(net.ErrClosed)
		writeErr := c.writeReset()
		c.closeMode.Store(goCloseModeAbort)
		c.engine.postMessage(&c.closeMessage)
		return writeErr
	}
	if !c.userClosed.CompareAndSwap(false, true) {
		return nil
	}
	c.writeShut.Store(true)
	c.readShut.Store(true)
	if c.connState.Load() == goConnStateEngaged || c.splicePending.Load() != nil || c.spliced.Load() {
		c.requestAbort(net.ErrClosed)
		return nil
	}
	if c.connState.Load() >= goConnStateAborted {
		c.engine.postMessage(&c.closeMessage)
		c.wakeUser()
		return nil
	}
	if c.receiveAvailable.Load() > c.consumedTail.Load() {
		c.closeMode.CompareAndSwap(goCloseModeNone, goCloseModeAbort)
	} else {
		c.closeMode.CompareAndSwap(goCloseModeNone, goCloseModeGraceful)
		c.finRequested.Store(true)
		c.engine.postMessage(&c.readShutMessage)
	}
	c.engine.postMessage(&c.closeMessage)
	c.wakeUser()
	return nil
}

func (c *GoConn) CloseRead() error {
	if c.connState.Load() >= goConnStateAborted {
		return nil
	}
	c.readShut.Store(true)
	c.engine.postMessage(&c.readShutMessage)
	c.readSignal.notify()
	return nil
}

func (c *GoConn) CloseWrite() error {
	if c.connState.Load() >= goConnStateAborted {
		return nil
	}
	c.writeShut.Store(true)
	c.closeMode.CompareAndSwap(goCloseModeNone, goCloseModeGraceful)
	c.finRequested.Store(true)
	c.engine.postMessage(&c.closeMessage)
	c.writeSignal.notify()
	return nil
}

func (c *GoConn) LocalAddr() net.Addr {
	return c.source.TCPAddr()
}

func (c *GoConn) RemoteAddr() net.Addr {
	return c.destination.TCPAddr()
}

func (c *GoConn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	c.writeDeadline.Set(t)
	return nil
}

func (c *GoConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *GoConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return nil
}

type goSignal chan struct{}

func (s goSignal) notify() bool {
	select {
	case s <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s goSignal) drain() {
	select {
	case <-s:
	default:
	}
}

var (
	_ net.Conn           = (*GoConn)(nil)
	_ N.ReadWaiter       = (*GoConn)(nil)
	_ N.ExtendedWriter   = (*GoConn)(nil)
	_ N.FrontHeadroom    = (*GoConn)(nil)
	_ N.WriterWithMTU    = (*GoConn)(nil)
	_ N.ReadCloser       = (*GoConn)(nil)
	_ N.WriteCloser      = (*GoConn)(nil)
	_ N.EarlyReader      = (*GoConn)(nil)
	_ N.EarlyWriter      = (*GoConn)(nil)
	_ N.HandshakeSuccess = (*GoConn)(nil)
	_ N.HandshakeFailure = (*GoConn)(nil)
)
