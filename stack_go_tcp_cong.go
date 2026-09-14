package tun

import (
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Mirrors net/ipv4/tcp_cong.c and the congestion control core of net/ipv4/tcp_input.c.

const (
	goCongestionOpen uint8 = iota
	goCongestionDisorder
	goCongestionCWR
	goCongestionRecovery
	goCongestionLoss
)

const (
	goCongestionEventWindowRestart uint8 = iota
	goCongestionEventCompleteCWR
	goCongestionEventLoss
)

const (
	goInfiniteSlowStartThreshold = 0x7fffffff
	goInitialReordering          = 3
	goMaxReordering              = 300
	goMinRoundTripWindow         = 300 * time.Second
	goPacingSlowStartRatio       = 200
	goPacingAvoidanceRatio       = 120
	goMinTSOSegments             = 2
	goTSORoundTripShift          = 9
	goPacingShift                = 10
	goPacingUnpacedSegments      = 10
	goRackRecoveryThreshold      = 16
	goRackTimeoutMinMicros       = 2000
)

type goAckFlags uint32

const (
	goAckData goAckFlags = 1 << iota
	goAckWindowUpdate
	goAckDataAcked
	goAckRetransmittedAcked
	goAckDataSacked
	goAckOriginalSacked
	goAckUnackedAdvanced
	goAckDSACK
	goAckMaybeDelayed
	goAckDSACKProbe
	goAckReneging
	goAckKeepTimer
)

const (
	goAckNotDuplicate    = goAckData | goAckWindowUpdate | goAckDataAcked
	goAckAlert           = goAckDataSacked | goAckDSACK
	goAckForwardProgress = goAckDataAcked | goAckDataSacked
)

const (
	goRexmitNone uint8 = iota
	goRexmitLost
	goRexmitNew
)

type goAckSample struct {
	packetsAcked    uint32
	roundTripMicros int64
	inFlightBytes   uint64
}

type goRateSample struct {
	valid                 bool
	priorStamp            int32
	priorDelivered        uint32
	delivered             int64
	intervalMicros        int64
	sendIntervalMicros    int64
	receiveIntervalMicros int64
	roundTripMicros       int64
	losses                uint32
	ackedSacked           uint32
	priorInFlight         uint32
	lastEndOffset         uint64
	appLimited            bool
	retransmitted         bool
	ackDelayed            bool
}

type goFlightSummary struct {
	packetsEnd    uint64
	packetsOut    uint32
	sackedOut     uint32
	lostOut       uint32
	retransmitOut uint32
	retransmitted uint32
}

func (s *goFlightSummary) inFlight() uint32 {
	return s.packetsOut - s.sackedOut - s.lostOut + s.retransmitOut
}

func (s *goFlightSummary) leftOut() uint32 {
	return s.sackedOut + s.lostOut
}

type goCongestionOps struct {
	name               string
	init               func(conn *GoConn)
	release            func(conn *GoConn)
	slowStartThreshold func(conn *GoConn) uint32
	congAvoid          func(conn *GoConn, acked uint32)
	congControl        func(conn *GoConn, flags goAckFlags, sample *goRateSample)
	undoWindow         func(conn *GoConn) uint32
	setState           func(conn *GoConn, state uint8)
	windowEvent        func(conn *GoConn, event uint8)
	windowEventTxStart func(conn *GoConn, idleNanos int64)
	packetsAcked       func(conn *GoConn, sample *goAckSample)
	minTSOSegments     func(conn *GoConn) uint32
	pacing             bool
}

var goCongestionRegistry = make(map[string]*goCongestionOps)

const goDefaultCongestionControl = "cubic"

func goRegisterCongestionControl(ops *goCongestionOps) {
	if ops.slowStartThreshold == nil || ops.undoWindow == nil || (ops.congAvoid == nil && ops.congControl == nil) {
		panic("go: congestion control " + ops.name + " does not implement required ops")
	}
	if _, exists := goCongestionRegistry[ops.name]; exists {
		panic("go: congestion control " + ops.name + " already registered")
	}
	goCongestionRegistry[ops.name] = ops
}

func goLookupCongestionControl(name string) (*goCongestionOps, error) {
	if name == "" {
		name = goDefaultCongestionControl
	}
	ops, found := goCongestionRegistry[name]
	if !found {
		return nil, E.New("go: unknown congestion control: ", name)
	}
	return ops, nil
}

func (c *GoConn) initCongestionControl(ops *goCongestionOps) {
	c.congestion = ops
	c.congestionWindow = goInitialWindow
	c.slowStartThreshold = goInfiniteSlowStartThreshold
	c.congestionClamp = max(uint32(goMaxCongestionSize/uint64(c.effectiveMSS)), 2)
	c.reordering = goInitialReordering
	c.reorderWindowSteps = 1
	c.deliveredTime = c.engine.now()
	c.undoRetransmits = -1
	c.priorSlowStartThreshold = 0
	c.roundTripMin.reset(0, ^uint32(0))
	if ops.init != nil {
		ops.init(c)
	}
}

func (c *GoConn) releaseCongestionControl() {
	if c.congestion != nil && c.congestion.release != nil {
		c.congestion.release(c)
	}
	c.congestionPrivate = nil
}

func (c *GoConn) setCAState(state uint8) {
	if c.congestion.setState != nil {
		c.congestion.setState(c, state)
	}
	c.congestionState = state
}

func (c *GoConn) congestionEvent(event uint8) {
	if c.congestion.windowEvent != nil {
		c.congestion.windowEvent(c, event)
	}
}

func (c *GoConn) inSlowStart() bool {
	return c.congestionWindow < c.slowStartThreshold
}

func (c *GoConn) inWindowReduction() bool {
	return c.congestionState == goCongestionCWR || c.congestionState == goCongestionRecovery
}

func (c *GoConn) currentSlowStartThreshold() uint32 {
	if c.inWindowReduction() {
		return c.slowStartThreshold
	}
	return max(c.slowStartThreshold, c.congestionWindow>>1+c.congestionWindow>>2)
}

func (c *GoConn) setCongestionWindow(window uint32) {
	c.congestionWindow = min(max(window, 1), c.congestionClamp)
}

func (c *GoConn) isWindowLimited() bool {
	if c.windowLimited {
		return true
	}
	if c.inSlowStart() {
		return c.congestionWindow < 2*c.maxPacketsOut
	}
	return false
}

func (c *GoConn) minRoundTripMicros() uint32 {
	return c.roundTripMin.get()
}

func (c *GoConn) slowStart(acked uint32) uint32 {
	window := min(c.congestionWindow+acked, c.slowStartThreshold)
	acked -= window - c.congestionWindow
	c.setCongestionWindow(window)
	return acked
}

func (c *GoConn) congAvoidAI(w uint32, acked uint32) {
	if c.congestionWindowCount >= w {
		c.congestionWindowCount = 0
		c.setCongestionWindow(c.congestionWindow + 1)
	}
	c.congestionWindowCount += acked
	if c.congestionWindowCount >= w {
		delta := c.congestionWindowCount / w
		c.congestionWindowCount -= delta * w
		c.setCongestionWindow(c.congestionWindow + delta)
	}
}

func goRenoCongAvoid(c *GoConn, acked uint32) {
	if !c.isWindowLimited() {
		return
	}
	if c.inSlowStart() {
		acked = c.slowStart(acked)
		if acked == 0 {
			return
		}
	}
	c.congAvoidAI(c.congestionWindow, acked)
}

func goRenoSlowStartThreshold(c *GoConn) uint32 {
	return max(c.congestionWindow>>1, 2)
}

func goRenoUndoWindow(c *GoConn) uint32 {
	return max(c.congestionWindow, c.priorCongestionWindow)
}

var goRenoOps = goCongestionOps{
	name:               "reno",
	slowStartThreshold: goRenoSlowStartThreshold,
	congAvoid:          goRenoCongAvoid,
	undoWindow:         goRenoUndoWindow,
}

func init() {
	goRegisterCongestionControl(&goRenoOps)
}

func (e *goEngine) initUndo(conn *GoConn) {
	conn.undoMarker = conn.sendUnacked.Load()
	conn.undoRetransmits = int32(conn.flight.retransmitOut)
	if conn.probeHighSeq != 0 && conn.probeRetransmitted {
		conn.undoRetransmits++
	}
	if conn.undoRetransmits == 0 {
		conn.undoRetransmits = -1
	}
}

func (e *goEngine) initWindowReduction(conn *GoConn) {
	conn.highSeq = conn.sentTail.Load()
	conn.probeHighSeq = 0
	conn.congestionWindowCount = 0
	conn.priorCongestionWindow = conn.congestionWindow
	conn.reductionDelivered = 0
	conn.reductionRetransmits = 0
	conn.reductionSegmentsOut = conn.dataSegmentsOut.Load()
	conn.slowStartThreshold = conn.congestion.slowStartThreshold(conn)
}

func (c *GoConn) reductionOut() uint32 {
	return c.reductionRetransmits + c.dataSegmentsOut.Load() - c.reductionSegmentsOut
}

func (e *goEngine) reduceWindow(conn *GoConn, newlyAckedSacked uint32, newlyLost uint32, flags goAckFlags) {
	if newlyAckedSacked == 0 || conn.priorCongestionWindow == 0 {
		return
	}
	inFlight := conn.flight.inFlight()
	conn.reductionDelivered += newlyAckedSacked
	out := conn.reductionOut()
	var sendCount int64
	delta := int64(conn.slowStartThreshold) - int64(inFlight)
	if delta < 0 {
		dividend := uint64(conn.slowStartThreshold)*uint64(conn.reductionDelivered) + uint64(conn.priorCongestionWindow) - 1
		sendCount = int64(dividend/uint64(conn.priorCongestionWindow)) - int64(out)
	} else {
		sendCount = max(int64(conn.reductionDelivered)-int64(out), int64(newlyAckedSacked))
		if flags&goAckUnackedAdvanced != 0 && newlyLost == 0 {
			sendCount++
		}
		sendCount = min(delta, sendCount)
	}
	if out == 0 {
		sendCount = max(sendCount, 1)
	} else {
		sendCount = max(sendCount, 0)
	}
	conn.setCongestionWindow(inFlight + uint32(sendCount))
}

func (e *goEngine) endWindowReduction(conn *GoConn) {
	if conn.congestion.congControl != nil {
		return
	}
	if conn.slowStartThreshold < goInfiniteSlowStartThreshold && (conn.congestionState == goCongestionCWR || conn.undoMarker != 0) {
		conn.setCongestionWindow(conn.slowStartThreshold)
		conn.congestionWindowStamp = e.now()
	}
	conn.congestionEvent(goCongestionEventCompleteCWR)
}

func (e *goEngine) enterCWR(conn *GoConn) {
	conn.priorSlowStartThreshold = 0
	if conn.congestionState < goCongestionCWR {
		conn.undoMarker = 0
		e.initWindowReduction(conn)
		conn.setCAState(goCongestionCWR)
	}
}

func (e *goEngine) enterRecovery(conn *GoConn) {
	if !e.anyRetransmitDone(conn) {
		conn.retransmitStamp = 0
	}
	conn.priorSlowStartThreshold = 0
	e.initUndo(conn)
	if !conn.inWindowReduction() {
		conn.priorSlowStartThreshold = conn.currentSlowStartThreshold()
		e.initWindowReduction(conn)
	}
	conn.setCAState(goCongestionRecovery)
}

func (e *goEngine) enterLoss(conn *GoConn) {
	newRecovery := conn.congestionState < goCongestionRecovery
	unacked := conn.sendUnacked.Load()
	sent := conn.sentTail.Load()
	reneging := len(conn.scoreboard.entries) > 0 && conn.scoreboard.entries[0].flags&goDescriptorSacked != 0
	if reneging {
		conn.highestSacked = unacked
		conn.sackReneging = true
	} else if !conn.sackPermitted {
		conn.renoSacked = 0
	}
	now := e.now()
	for index := range conn.scoreboard.entries {
		descriptor := &conn.scoreboard.entries[index]
		if reneging {
			descriptor.flags &^= goDescriptorSacked
		} else if index != 0 && e.rackDescriptorTimeout(conn, descriptor, 0, now) > 0 {
			continue
		}
		e.markLost(conn, descriptor)
	}
	e.summarizeFlight(conn)
	if conn.congestionState <= goCongestionDisorder || unacked >= conn.highSeq || (conn.congestionState == goCongestionLoss && conn.retransmitAttempts == 0) {
		conn.priorSlowStartThreshold = conn.currentSlowStartThreshold()
		conn.priorCongestionWindow = conn.congestionWindow
		conn.slowStartThreshold = conn.congestion.slowStartThreshold(conn)
		conn.congestionEvent(goCongestionEventLoss)
		e.initUndo(conn)
	}
	conn.setCongestionWindow(conn.flight.inFlight() + 1)
	conn.congestionWindowCount = 0
	conn.congestionWindowStamp = e.now()
	if conn.congestionState <= goCongestionDisorder && conn.flight.sackedOut >= goInitialReordering {
		conn.reordering = min(conn.reordering, goInitialReordering)
	}
	conn.setCAState(goCongestionLoss)
	conn.highSeq = sent
	conn.probeHighSeq = 0
	conn.frto = conn.sackPermitted && (newRecovery || conn.retransmitAttempts > 0)
}

func (e *goEngine) anyRetransmitDone(conn *GoConn) bool {
	if conn.flight.retransmitOut > 0 {
		return true
	}
	return len(conn.scoreboard.entries) > 0 && conn.scoreboard.entries[0].flags&goDescriptorRetransmitted != 0
}

func (c *GoConn) packetDelayed(flags goAckFlags) bool {
	if c.retransmitStamp != 0 {
		return c.echoedTimestampBefore(c.retransmitStamp)
	}
	if !c.sackPermitted && c.sendUnacked.Load() >= c.highSeq {
		return false
	}
	return true
}

func (c *GoConn) echoedTimestampBefore(stamp uint32) bool {
	return c.timestampsEnabled && c.lastTimestampEcho != 0 && int32(c.lastTimestampEcho-stamp) < 0
}

func (c *GoConn) mayUndo(flags goAckFlags) bool {
	return c.undoMarker != 0 && (c.undoRetransmits == 0 || c.packetDelayed(flags))
}

func (e *goEngine) undoWindowReduction(conn *GoConn, unmarkLoss bool) {
	if unmarkLoss {
		for index := range conn.scoreboard.entries {
			conn.scoreboard.entries[index].flags &^= goDescriptorLost
		}
		e.summarizeFlight(conn)
	}
	if conn.priorSlowStartThreshold != 0 {
		conn.setCongestionWindow(conn.congestion.undoWindow(conn))
		if conn.priorSlowStartThreshold > conn.slowStartThreshold {
			conn.slowStartThreshold = conn.priorSlowStartThreshold
		}
	}
	conn.congestionWindowStamp = e.now()
	conn.undoMarker = 0
	conn.rackAdvanced = true
}

func (e *goEngine) nonSackPreventingReopen(conn *GoConn) bool {
	if !conn.sackPermitted && conn.sendUnacked.Load() == conn.highSeq {
		if !e.anyRetransmitDone(conn) {
			conn.retransmitStamp = 0
		}
		return true
	}
	return false
}

func (e *goEngine) tryUndoRecovery(conn *GoConn, flags goAckFlags) bool {
	if conn.mayUndo(flags) {
		e.undoWindowReduction(conn, false)
	} else if conn.reorderWindowPersist > 0 {
		conn.reorderWindowPersist--
	}
	if e.nonSackPreventingReopen(conn) {
		return true
	}
	conn.setCAState(goCongestionOpen)
	conn.sackReneging = false
	return false
}

func (e *goEngine) tryUndoDSACK(conn *GoConn) bool {
	if conn.undoMarker != 0 && conn.undoRetransmits == 0 {
		conn.reorderWindowPersist = min(goRackRecoveryThreshold, conn.reorderWindowPersist+1)
		e.undoWindowReduction(conn, false)
		return true
	}
	return false
}

func (e *goEngine) tryUndoLoss(conn *GoConn, flags goAckFlags, frtoUndo bool) bool {
	if !frtoUndo && !conn.mayUndo(flags) {
		return false
	}
	e.undoWindowReduction(conn, true)
	conn.retransmitAttempts = 0
	if e.nonSackPreventingReopen(conn) {
		return true
	}
	if frtoUndo || conn.sackPermitted {
		conn.setCAState(goCongestionOpen)
		conn.sackReneging = false
	}
	return true
}

func (e *goEngine) tryUndoPartial(conn *GoConn, flags goAckFlags, priorUnacked uint64) bool {
	if conn.undoMarker == 0 || !conn.packetDelayed(flags) {
		return false
	}
	e.checkSackReordering(conn, priorUnacked)
	if conn.flight.retransmitOut > 0 {
		return true
	}
	if !e.anyRetransmitDone(conn) {
		conn.retransmitStamp = 0
	}
	e.undoWindowReduction(conn, true)
	e.tryKeepOpen(conn)
	return false
}

func (e *goEngine) tryKeepOpen(conn *GoConn) {
	state := goCongestionOpen
	if conn.flight.leftOut() != 0 || e.anyRetransmitDone(conn) {
		state = goCongestionDisorder
	}
	if conn.congestionState != state {
		conn.setCAState(state)
		conn.highSeq = conn.sentTail.Load()
	}
}

func (e *goEngine) tryToOpen(conn *GoConn) {
	if !e.anyRetransmitDone(conn) {
		conn.retransmitStamp = 0
	}
	if conn.congestionState != goCongestionCWR {
		e.tryKeepOpen(conn)
	}
}

func (e *goEngine) checkSackReordering(conn *GoConn, lowOffset uint64) {
	fack := conn.highestSacked
	if lowOffset >= fack {
		return
	}
	metric := fack - lowOffset
	mss := uint64(conn.effectiveMSS)
	if metric > uint64(conn.reordering)*mss {
		conn.reordering = uint32(min((metric+mss-1)/mss, goMaxReordering))
	}
	conn.reorderingSeen++
}

func (e *goEngine) mayRaiseWindow(conn *GoConn, flags goAckFlags) bool {
	if conn.reordering > goInitialReordering {
		return flags&goAckForwardProgress != 0
	}
	return flags&goAckDataAcked != 0
}

func (e *goEngine) congestionControl(conn *GoConn, ackedSacked uint32, flags goAckFlags, sample *goRateSample) {
	if conn.congestion.congControl != nil {
		conn.congestion.congControl(conn, flags, sample)
		return
	}
	if conn.inWindowReduction() {
		e.reduceWindow(conn, ackedSacked, sample.losses, flags)
	} else if e.mayRaiseWindow(conn, flags) {
		conn.congestion.congAvoid(conn, ackedSacked)
		conn.congestionWindowStamp = e.now()
	}
	e.updatePacingRate(conn)
}

func (e *goEngine) updatePacingRate(conn *GoConn) {
	rate := uint64(conn.effectiveMSS) * (uint64(time.Second/time.Microsecond) / 100)
	if conn.congestionWindow < conn.slowStartThreshold/2 {
		rate *= goPacingSlowStartRatio
	} else {
		rate *= goPacingAvoidanceRatio
	}
	rate *= uint64(max(conn.congestionWindow, conn.flight.packetsOut))
	if conn.smoothedRoundTrip > 0 {
		rate /= uint64(conn.smoothedRoundTrip)
	}
	conn.pacingRate.Store(rate)
}

func (e *goEngine) validateWindow(conn *GoConn) {
	limited := conn.windowLimitedSince.Swap(false)
	peak := conn.peakFlight.Swap(0)
	if peak == 0 && !limited {
		return
	}
	peakPackets := uint32(peak)
	if conn.sendUnacked.Load() >= conn.windowUsageSeq || limited || (!conn.windowLimited && peakPackets > conn.maxPacketsOut) {
		conn.windowLimited = limited
		conn.maxPacketsOut = peakPackets
		conn.windowUsageSeq = conn.sentTail.Load()
	}
	now := e.now()
	if conn.isWindowLimited() {
		conn.congestionWindowUsed = 0
		conn.congestionWindowStamp = now
		return
	}
	if peakPackets > conn.congestionWindowUsed {
		conn.congestionWindowUsed = peakPackets
	}
	if conn.congestion.congControl == nil && now-conn.congestionWindowStamp >= int64(conn.retransmitTimeout)*int64(time.Microsecond) {
		e.applicationLimitedWindow(conn, now)
	}
}

func (e *goEngine) armIdleRestart(conn *GoConn) {
	if conn.congestion.congControl != nil || conn.congestionState != goCongestionOpen || conn.congestionWindow <= goInitialWindow {
		conn.idleDeadline = 0
		return
	}
	conn.idleDeadline = e.now() + int64(conn.retransmitTimeout)*int64(time.Microsecond)
}

func (e *goEngine) expireIdleRestart(conn *GoConn, now int64) {
	conn.idleDeadline = 0
	if conn.hasOutstanding() || conn.congestionState != goCongestionOpen || conn.congestion.congControl != nil {
		e.rearmTimer(conn)
		return
	}
	conn.congestionEvent(goCongestionEventWindowRestart)
	conn.slowStartThreshold = conn.currentSlowStartThreshold()
	restart := min(uint32(goInitialWindow), conn.congestionWindow)
	conn.setCongestionWindow(max(conn.congestionWindow>>1, restart))
	conn.congestionWindowStamp = now
	conn.congestionWindowUsed = 0
	e.summarizeFlight(conn)
	conn.publishPermit(conn.sendUnacked.Load())
	e.armIdleRestart(conn)
	e.rearmTimer(conn)
}

func (e *goEngine) applicationLimitedWindow(conn *GoConn, now int64) {
	if conn.congestionState == goCongestionOpen {
		used := max(conn.congestionWindowUsed, uint32(goInitialWindow))
		if used < conn.congestionWindow {
			conn.slowStartThreshold = conn.currentSlowStartThreshold()
			conn.setCongestionWindow((conn.congestionWindow + used) >> 1)
		}
		conn.congestionWindowUsed = 0
	}
	conn.congestionWindowStamp = now
}

type goMinMaxSample struct {
	time  uint32
	value uint32
}

// Mirrors lib/win_minmax.c.
type goMinMax struct {
	samples [3]goMinMaxSample
}

func (m *goMinMax) get() uint32 {
	return m.samples[0].value
}

func (m *goMinMax) reset(time uint32, value uint32) uint32 {
	sample := goMinMaxSample{time: time, value: value}
	m.samples[0] = sample
	m.samples[1] = sample
	m.samples[2] = sample
	return value
}

func (m *goMinMax) subwindowUpdate(window uint32, sample goMinMaxSample) uint32 {
	dt := sample.time - m.samples[0].time
	if dt > window {
		m.samples[0] = m.samples[1]
		m.samples[1] = m.samples[2]
		m.samples[2] = sample
		if sample.time-m.samples[0].time > window {
			m.samples[0] = m.samples[1]
			m.samples[1] = m.samples[2]
			m.samples[2] = sample
		}
	} else if m.samples[1].time == m.samples[0].time && dt > window/4 {
		m.samples[2] = sample
		m.samples[1] = sample
	} else if m.samples[2].time == m.samples[1].time && dt > window/2 {
		m.samples[2] = sample
	}
	return m.samples[0].value
}

func (m *goMinMax) runningMax(window uint32, time uint32, value uint32) uint32 {
	sample := goMinMaxSample{time: time, value: value}
	if value >= m.samples[0].value || time-m.samples[2].time > window {
		return m.reset(time, value)
	}
	if value >= m.samples[1].value {
		m.samples[2] = sample
		m.samples[1] = sample
	} else if value >= m.samples[2].value {
		m.samples[2] = sample
	}
	return m.subwindowUpdate(window, sample)
}

func (m *goMinMax) runningMin(window uint32, time uint32, value uint32) uint32 {
	sample := goMinMaxSample{time: time, value: value}
	if value <= m.samples[0].value || time-m.samples[2].time > window {
		return m.reset(time, value)
	}
	if value <= m.samples[1].value {
		m.samples[2] = sample
		m.samples[1] = sample
	} else if value <= m.samples[2].value {
		m.samples[2] = sample
	}
	return m.subwindowUpdate(window, sample)
}
