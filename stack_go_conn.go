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
	goPhaseJudged uint8 = iota
	goPhaseEngaged
	goPhaseEstablished
)

const (
	goTCPSynReceived uint8 = iota
	goTCPSynSent
	goTCPEstablished
	goTCPFinWait1
	goTCPFinWait2
	goTCPClosing
	goTCPCloseWait
	goTCPLastAck
	goTCPClosed
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
	goPermitWindowBit  = 1 << 63
)

var errGoReset = E.Cause(syscall.ECONNRESET, "go: connection reset by peer")

type goPostedReceive struct {
	buffer *buf.Buffer
	direct []byte
	target []byte
	filled int
}

var (
	goTargetTaken  goPostedReceive
	goTargetFilled goPostedReceive
)

type GoConn struct {
	engine                *goEngine
	key                   flowKey
	peer                  M.Socksaddr
	local                 M.Socksaddr
	epoch                 int64
	receiveNext           uint64
	receiveCapacity       uint64
	publishedEdge         uint64
	sentEdge              uint64
	receiveRoundTripMark  uint64
	receiveRoundTripStamp int64
	receiveSpaceConsumed  uint64
	receiveSpaceCopied    uint64
	receiveSpaceStamp     int64
	receiveChain          goSlabChain
	oooRanges             *goRangeSet
	dsackStart            uint64
	dsackEnd              uint64
	smoothedRoundTrip     int32
	roundTripVariance     int32
	retransmitTimeout     int32
	receiveRoundTrip      int32
	highestSacked         uint64
	peerWindow            uint64
	maxPeerWindow         uint64
	ackPending            uint64
	ackCovered            uint64
	lastAckSent           uint64
	lastActivity          int64
	windowLeft1           int64
	windowLeft2           int64
	keepaliveProbes       uint8
	finWait2Since         int64
	scoreboard            goScoreboard
	timerNode             goWheelNode
	retransmitDeadline    int64
	probeDeadline         int64
	persistDeadline       int64
	lingerDeadline        int64
	handshakeDeadline     int64
	handshakeStamp        int64
	idleDeadline          int64
	pacingDeadline        int64
	reorderDeadline       int64
	keepaliveDeadline     int64
	retransmitAttempts    uint8
	probeAttempts         uint8
	handshakeAttempts     uint8
	persistAttempts       uint8
	state                 uint8

	congestion              *goCongestionOps
	congestionPrivate       any
	flight                  goFlightSummary
	roundTripMin            goMinMax
	congestionState         uint8
	frto                    bool
	sackReneging            bool
	windowLimited           bool
	rateAppLimited          bool
	probeRetransmitted      bool
	congestionWindow        uint32
	slowStartThreshold      uint32
	congestionClamp         uint32
	congestionWindowCount   uint32
	congestionWindowUsed    uint32
	priorCongestionWindow   uint32
	priorSlowStartThreshold uint32
	reductionDelivered      uint32
	reductionRetransmits    uint32
	reductionSegmentsOut    uint32
	totalRetransmits        uint64
	duplicateSegments       uint64
	delivered               uint32
	lost                    uint32
	renoSacked              uint32
	reordering              uint32
	reorderingSeen          uint32
	maxPacketsOut           uint32
	rateDelivered           uint32
	rateIntervalMicros      uint32
	retransmitStamp         uint32
	lastTimestampEcho       uint32
	undoRetransmits         int32
	deliveredStamp          int32
	deliveredTime           int64
	lastSendStamp           int64
	undoMarker              uint64
	highSeq                 uint64
	probeHighSeq            uint64
	rackEndOffset           uint64
	rackRoundTripMicros     int64
	rackStamp               int32
	rackAdvanced            bool
	rackDSACKSeen           bool
	rackLastDelivered       uint32
	reorderWindowSteps      uint32
	reorderWindowPersist    uint8
	windowUsageSeq          uint64
	congestionWindowStamp   int64
	ipVersion               uint8
	deathClass              uint8
	peerWindowShift         uint8
	localWindowShift        uint8
	peerMSS                 uint16
	effectiveMSS            atomic.Uint32
	lastPeerWindow          uint16
	handshakeLength         uint8
	keyed                   bool
	socket                  bool
	finPending              bool
	sackPermitted           bool
	timestampsEnabled       bool
	discardReceive          bool
	finSent                 bool
	finAcked                bool
	ackForced               bool
	ackDirty                bool
	onBlockedList           bool
	onDyingList             bool
	clientISN               uint32
	sendISN                 uint32
	finOffset               uint64
	dyingSince              int64
	ackNext                 *GoConn
	blockedNext             *GoConn
	dyingNext               *GoConn
	splice                  *goSpliceStream
	listener                *GoListener
	handshakeImage          [96]byte
	_                       [64]byte

	sendPermit       atomic.Uint64
	sendPacketPermit atomic.Uint32
	packetCreditBase atomic.Uint32
	sendUnacked      atomic.Uint64
	sendReleased     atomic.Uint64
	receiveNextAck   atomic.Uint64
	receiveEdge      atomic.Uint64
	receiveAvailable atomic.Uint64
	windowUpdateAt   atomic.Uint64
	deliveryState    atomic.Uint64
	pacingRate       atomic.Uint64
	pacingStamp      atomic.Int64
	queuedBytes      atomic.Int64
	departedTail     atomic.Uint64
	queueThrottled   atomic.Bool
	firstSentStamp   atomic.Int32
	appLimited       atomic.Uint32
	frameLimit       atomic.Uint32
	tsRecent         atomic.Uint32
	_                [64]byte

	transmitAccess     sync.Mutex
	sentTail           atomic.Uint64
	transmittedTail    atomic.Uint64
	dataSentEdge       atomic.Uint64
	peakFlight         atomic.Uint64
	pacingRequest      atomic.Int64
	dataSegmentsOut    atomic.Uint32
	ident              atomic.Uint32
	windowLimitedSince atomic.Bool
	transmitStore      goTransmitStore
	descriptors        goDescriptorRing
	transmitScratch    [goHeaderScratchSize]byte
	transmitSegments   [][]byte
	blockedSegment     goSegment
	blockedFrame       [][]byte
	blockedMeta        ForwardFrameMeta
	blockedValid       bool
	_                  [64]byte

	writeAccess   sync.Mutex
	bufferedTail  atomic.Uint64
	writerWaiting atomic.Int32
	writeDeadline pipe.Deadline
	writeSignal   goSignal
	_             [64]byte

	readAccess      sync.Mutex
	consumedTail    atomic.Uint64
	readerParked    atomic.Bool
	postedTarget    atomic.Pointer[goPostedReceive]
	receiveTarget   goPostedReceive
	readWaitOptions N.ReadWaitOptions
	readDeadline    pipe.Deadline
	readSignal      goSignal
	_               [64]byte

	access             sync.Mutex
	phase              uint8
	receiveCapacityMax uint64
	transmitCapacity   uint64
	keepaliveIdle      time.Duration
	keepaliveInterval  time.Duration
	keepaliveCount     uint8
	keepaliveEnabled   bool
	nagle              bool
	linger             int
	dead               bool
	finReceived        bool
	drainable          bool
	released           bool
	spliced            bool
	userClosed         bool
	writeShut          bool
	readShut           bool
	finRequested       bool
	abort              bool
	writing            bool
	transmitterRunning bool
	err                error
	splicePending      *goSpliceStream
	establishedSignal  chan struct{}
	finAckedSignal     chan struct{}
	closeSignal        chan struct{}
	transmitSignal     goSignal
	dialMessage        goMessage
	engageMessage      goMessage
	closeMessage       goMessage
	readShutMessage    goMessage
	retransmitMessage  goMessage
	windowMessage      goMessage
	transmitMessage    goMessage
	blockedMessage     goMessage
	droppedMessage     goMessage
	pacingMessage      goMessage
	throttleMessage    goMessage
	spliceMessage      goMessage
	keepaliveMessage   goMessage
	transmittedMessage goMessage
	slabHolder         goSlabHolder
}

func (c *GoConn) initialize(engine *goEngine, key flowKey, peer M.Socksaddr, local M.Socksaddr) {
	c.engine = engine
	c.key = key
	c.peer = peer
	c.local = local
	c.epoch = engine.coarseTime.Load()
	c.lastSendStamp = -1
	c.readDeadline = pipe.MakeDeadline()
	c.writeDeadline = pipe.MakeDeadline()
	c.readSignal = make(goSignal, 1)
	c.writeSignal = make(goSignal, 1)
	c.transmitSignal = make(goSignal, 1)
	c.establishedSignal = make(chan struct{})
	c.finAckedSignal = make(chan struct{})
	c.closeSignal = make(chan struct{})
	c.receiveCapacityMax = goReceiveCapacityMax
	c.transmitCapacity = goTransmitCapacityMax
	c.keepaliveIdle = tcpEstablishedTimeout
	c.keepaliveInterval = goKeepaliveInterval
	c.keepaliveCount = goKeepaliveCount
	c.keepaliveEnabled = true
	c.linger = -1
	c.receiveChain = goSlabChain{maxSlots: goReceiveCapacityMax/goSlabSize + 1, pool: engine.slabPool, holder: &c.slabHolder}
	c.transmitStore.chain = goSlabChain{maxSlots: goTransmitCapacityMax/goSlabSize + 1, pool: engine.slabPool, holder: &c.slabHolder}
	c.descriptors.pool = &engine.descriptorPool
	c.timerNode.expire = func(now int64) { engine.fireConnTimer(c, now) }
	c.engageMessage = goMessage{kind: goMessageConnEngage, conn: c}
	c.closeMessage = goMessage{kind: goMessageConnClose, conn: c}
	c.readShutMessage = goMessage{kind: goMessageConnReadShut, conn: c}
	c.retransmitMessage = goMessage{kind: goMessageConnRetransmit, conn: c}
	c.windowMessage = goMessage{kind: goMessageConnWindow, conn: c}
	c.transmitMessage = goMessage{kind: goMessageConnTransmit, conn: c}
	c.blockedMessage = goMessage{kind: goMessageConnBlocked, conn: c}
	c.droppedMessage = goMessage{kind: goMessageConnDropped, conn: c}
	c.pacingMessage = goMessage{kind: goMessageConnPacing, conn: c}
	c.throttleMessage = goMessage{kind: goMessageConnThrottle, conn: c}
	c.spliceMessage = goMessage{kind: goMessageConnSplice, conn: c}
	c.keepaliveMessage = goMessage{kind: goMessageConnKeepalive, conn: c}
	c.transmittedMessage = goMessage{kind: goMessageConnTransmitted, conn: c}
}

func (c *GoConn) transmitted(tail uint64) {
	c.transmittedTail.Store(tail)
	if c.sendReleased.Load() < min(c.sendUnacked.Load(), tail) {
		c.engine.postMessage(&c.transmittedMessage)
	}
}

func (c *GoConn) handshaking() bool {
	return c.state == goTCPSynReceived || c.state == goTCPSynSent
}

func (c *GoConn) receiveWindowBound() uint64 {
	c.access.Lock()
	capacityMax := c.receiveCapacityMax
	c.access.Unlock()
	return min(capacityMax, uint64(0xffff)<<c.localWindowShift)
}

func (c *GoConn) sendNext() uint64 {
	if c.finSent {
		return c.finOffset + 1
	}
	return c.transmittedTail.Load()
}

func (c *GoConn) ackThreshold() uint64 {
	threshold := min(2*uint64(c.effectiveMSS.Load()), c.receiveCapacity/2)
	if c.engine.ackCoalescing {
		threshold = min(max(threshold, min(c.receiveCapacity/4, goAckCoalesceBytes)), c.receiveCapacity/2)
	}
	return threshold
}

func (c *GoConn) stamp(now int64) int32 {
	return int32((now - c.epoch) / goTimeUnit)
}

func (c *GoConn) closed() bool {
	c.access.Lock()
	dead := c.dead
	c.access.Unlock()
	return dead
}

func (c *GoConn) closeError() error {
	c.access.Lock()
	err := c.err
	c.access.Unlock()
	if err != nil {
		return err
	}
	return net.ErrClosed
}

func (c *GoConn) fail(err error) {
	c.access.Lock()
	if c.err == nil {
		c.err = err
	}
	c.abort = true
	c.access.Unlock()
	c.engine.postMessage(&c.closeMessage)
}

func (c *GoConn) awaitHandshake(ctx context.Context, deadlineSignal <-chan struct{}) error {
	c.access.Lock()
	phase := c.phase
	dead := c.dead
	c.access.Unlock()
	if phase == goPhaseEstablished || dead {
		return c.handshakeResult()
	}
	select {
	case <-deadlineSignal:
		return os.ErrDeadlineExceeded
	default:
	}
	if phase == goPhaseJudged {
		c.engine.postMessage(&c.engageMessage)
	}
	select {
	case <-c.establishedSignal:
		return c.handshakeResult()
	case <-deadlineSignal:
		return os.ErrDeadlineExceeded
	case <-ctx.Done():
		c.fail(ctx.Err())
		return E.Cause(ctx.Err(), "go: handshake")
	case <-c.engine.stack.ctx.Done():
		cause := context.Cause(c.engine.stack.ctx)
		c.fail(cause)
		return E.Cause(cause, "go: handshake")
	}
}

func (c *GoConn) handshakeResult() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.err != nil {
		return c.err
	}
	if c.dead && c.phase != goPhaseEstablished {
		return net.ErrClosed
	}
	return nil
}

func (c *GoConn) HandshakeFailure(err error) error {
	c.access.Lock()
	if c.dead {
		c.access.Unlock()
		return os.ErrInvalid
	}
	c.userClosed = true
	c.writeShut = true
	c.readShut = true
	c.abort = true
	if c.err == nil {
		c.err = err
	}
	c.access.Unlock()
	c.engine.postMessage(&c.closeMessage)
	return nil
}

func (c *GoConn) HandshakeSuccess() error {
	return c.awaitHandshake(context.Background(), nil)
}

func (c *GoConn) NeedHandshakeForRead() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.phase != goPhaseEstablished
}

func (c *GoConn) NeedHandshakeForWrite() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.phase != goPhaseEstablished
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
	buffer, err := c.waitReadBufferLocked()
	c.readAccess.Unlock()
	c.engine.reapAfterExit()
	return buffer, err
}

func (c *GoConn) waitReadBufferLocked() (*buf.Buffer, error) {
	if !c.readable() {
		return nil, c.receiveResult()
	}
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
	n, err := c.readLocked(p)
	c.readAccess.Unlock()
	c.engine.reapAfterExit()
	return n, err
}

func (c *GoConn) readLocked(p []byte) (int, error) {
	if !c.readable() {
		return 0, c.receiveResult()
	}
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

func (c *GoConn) readable() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return !c.dead || (c.drainable && !c.released)
}

func (c *GoConn) receiveResult() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.err != nil {
		return c.err
	}
	if c.userClosed {
		return net.ErrClosed
	}
	if c.readShut || c.finReceived || c.dead {
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
	consumed := c.consumedTail.Add(uint64(n))
	if consumed >= c.windowUpdateAt.Load() {
		c.engine.postMessage(&c.windowMessage)
		return
	}
	if c.receiveChain.held.Load() == 0 {
		return
	}
	if consumed/goSlabSize != (consumed-uint64(n))/goSlabSize || consumed == c.receiveAvailable.Load() {
		c.engine.postMessage(&c.windowMessage)
	}
}

func (c *GoConn) parkReader() (bool, error) {
	target := &c.receiveTarget
	target.filled = 0
	if target.buffer != nil {
		target.target = target.buffer.FreeBytes()
	} else {
		target.target = target.direct
	}
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
		target.target = nil
		return false
	}
	for c.postedTarget.Load() != &goTargetFilled {
		<-c.readSignal
	}
	c.postedTarget.Store(nil)
	target.target = nil
	return true
}

func (c *GoConn) Close() error {
	c.access.Lock()
	if c.userClosed {
		c.access.Unlock()
		return nil
	}
	c.userClosed = true
	c.writeShut = true
	c.readShut = true
	linger := c.linger
	graceful := !c.dead && !c.abort && linger != 0 && c.phase == goPhaseEstablished && !c.spliced && c.splicePending == nil &&
		c.receiveAvailable.Load() <= c.consumedTail.Load()
	if graceful {
		c.finRequested = true
	} else {
		c.abort = true
		if c.err == nil {
			c.err = net.ErrClosed
		}
	}
	c.access.Unlock()
	if graceful {
		c.engine.postMessage(&c.readShutMessage)
	}
	c.engine.postMessage(&c.closeMessage)
	c.wakeUser()
	if graceful && linger > 0 {
		timer := time.NewTimer(time.Duration(linger) * time.Second)
		defer timer.Stop()
		select {
		case <-c.finAckedSignal:
		case <-c.closeSignal:
		case <-timer.C:
		}
	}
	return nil
}

func (c *GoConn) CloseRead() error {
	c.access.Lock()
	if c.dead {
		c.access.Unlock()
		return nil
	}
	c.readShut = true
	c.access.Unlock()
	c.engine.postMessage(&c.readShutMessage)
	c.readSignal.notify()
	return nil
}

func (c *GoConn) CloseWrite() error {
	c.access.Lock()
	if c.dead {
		c.access.Unlock()
		return nil
	}
	c.writeShut = true
	c.finRequested = true
	c.access.Unlock()
	c.engine.postMessage(&c.closeMessage)
	c.writeSignal.notify()
	return nil
}

func (c *GoConn) LocalAddr() net.Addr {
	if c.socket {
		return c.local.TCPAddr()
	}
	return c.peer.TCPAddr()
}

func (c *GoConn) RemoteAddr() net.Addr {
	if c.socket {
		return c.peer.TCPAddr()
	}
	return c.local.TCPAddr()
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
