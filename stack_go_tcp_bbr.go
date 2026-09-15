package tun

import (
	"math/bits"
	"math/rand/v2"
	"time"
)

// Mirrors net/ipv4/tcp_bbr.c with HZ = 1000.

const (
	goBBRBandwidthScale = 24
	goBBRBandwidthUnit  = 1 << goBBRBandwidthScale
	goBBRScale          = 8
	goBBRUnit           = 1 << goBBRScale
	goBBRCycleLength    = 8
)

const (
	goBBRModeStartup uint8 = iota
	goBBRModeDrain
	goBBRModeProbeBandwidth
	goBBRModeProbeRoundTrip
)

const (
	goBBRBandwidthRounds        = goBBRCycleLength + 2
	goBBRMinRoundTripWindowMs   = 10 * 1000
	goBBRProbeRoundTripModeMs   = 200
	goBBRMinTSORate             = 1200000
	goBBRPacingMarginPercent    = 1
	goBBRHighGain               = goBBRUnit*2885/1000 + 1
	goBBRDrainGain              = goBBRUnit * 1000 / 2885
	goBBRWindowGain             = goBBRUnit * 2
	goBBRCycleRandom            = 7
	goBBRWindowMinTarget        = 4
	goBBRFullBandwidthThresh    = goBBRUnit * 5 / 4
	goBBRFullBandwidthCount     = 3
	goBBRLongTermMinRounds      = 4
	goBBRLongTermLossThresh     = 50
	goBBRLongTermBandwidthRatio = goBBRUnit / 8
	goBBRLongTermBandwidthDiff  = 4000 / 8
	goBBRLongTermMaxRounds      = 48
	goBBRExtraAckedGain         = goBBRUnit
	goBBRExtraAckedWindowRounds = 5
	goBBRAckEpochResetThresh    = 1 << 20
	goBBRExtraAckedMaxMicros    = 100 * 1000
)

var goBBRPacingGains = [goBBRCycleLength]uint32{
	goBBRUnit * 5 / 4,
	goBBRUnit * 3 / 4,
	goBBRUnit, goBBRUnit, goBBRUnit,
	goBBRUnit, goBBRUnit, goBBRUnit,
}

type goBBRState struct {
	minRoundTripMicros      uint32
	minRoundTripStamp       uint32
	probeRoundTripDone      uint32
	bandwidth               goMinMax
	roundTripCount          uint32
	nextRoundDelivered      uint32
	cycleStamp              int64
	mode                    uint8
	previousCAState         uint8
	packetConservation      bool
	roundStart              bool
	idleRestart             bool
	probeRoundTripRoundDone bool
	longTermSampling        bool
	longTermRounds          uint32
	longTermUseBandwidth    bool
	longTermBandwidth       uint32
	longTermLastDelivered   uint32
	longTermLastStamp       int64
	longTermLastLost        uint32
	pacingGain              uint32
	windowGain              uint32
	fullBandwidthReached    bool
	fullBandwidthCount      uint32
	cycleIndex              uint32
	seenRoundTrip           bool
	priorWindow             uint32
	fullBandwidth           uint32
	ackEpochStamp           int64
	extraAcked              [2]uint32
	ackEpochAcked           uint32
	extraAckedWindowRounds  uint32
	extraAckedWindowIndex   int
}

func goBBRJiffies(c *GoConn) uint32 {
	return uint32(c.engine.coarseTime.Load() / int64(time.Millisecond))
}

func goBBRAfter(a uint32, b uint32) bool {
	return int32(a-b) > 0
}

func (s *goBBRState) currentBandwidth() uint32 {
	if s.longTermUseBandwidth {
		return s.longTermBandwidth
	}
	return s.bandwidth.get()
}

func (s *goBBRState) extraAckedMax() uint32 {
	return max(s.extraAcked[0], s.extraAcked[1])
}

func goBBRRateBytesPerSecond(c *GoConn, rate uint64, gain uint32) uint64 {
	rate *= uint64(c.effectiveMSS.Load())
	rate *= uint64(gain)
	rate >>= goBBRScale
	rate *= uint64(time.Second/time.Microsecond) / 100 * (100 - goBBRPacingMarginPercent)
	return rate >> goBBRBandwidthScale
}

func goBBRInitPacingRateFromRoundTrip(c *GoConn, s *goBBRState) {
	roundTrip := uint64(time.Millisecond / time.Microsecond)
	if c.smoothedRoundTrip > 0 {
		roundTrip = uint64(max(c.smoothedRoundTrip, 1))
		s.seenRoundTrip = true
	}
	bandwidth := uint64(c.congestionWindow) * goBBRBandwidthUnit / roundTrip
	c.pacingRate.Store(goBBRRateBytesPerSecond(c, bandwidth, goBBRHighGain))
}

func goBBRSetPacingRate(c *GoConn, s *goBBRState, bandwidth uint32, gain uint32) {
	rate := goBBRRateBytesPerSecond(c, uint64(bandwidth), gain)
	if !s.seenRoundTrip && c.smoothedRoundTrip > 0 {
		goBBRInitPacingRateFromRoundTrip(c, s)
	}
	if s.fullBandwidthReached || rate > c.pacingRate.Load() {
		c.pacingRate.Store(rate)
	}
}

func goBBRMinTSOSegments(c *GoConn) uint32 {
	if c.pacingRate.Load() < goBBRMinTSORate>>3 {
		return 1
	}
	return 2
}

func goBBRTSOSegmentsGoal(c *GoConn) uint32 {
	bytes := min(c.pacingRate.Load()>>goPacingShift, uint64(0xffff-1-goHeaderScratchSize))
	segments := max(uint32(bytes/uint64(c.effectiveMSS.Load())), goBBRMinTSOSegments(c))
	return min(segments, 0x7f)
}

func (s *goBBRState) saveWindow(c *GoConn) {
	if s.previousCAState < goCongestionRecovery && s.mode != goBBRModeProbeRoundTrip {
		s.priorWindow = c.congestionWindow
	} else {
		s.priorWindow = max(s.priorWindow, c.congestionWindow)
	}
}

func goBBRTxStart(c *GoConn, _ int64) {
	s := c.congestionPrivate.(*goBBRState)
	if c.appLimited.Load() != 0 {
		s.idleRestart = true
		s.ackEpochStamp = c.engine.coarseTime.Load()
		s.ackEpochAcked = 0
		switch s.mode {
		case goBBRModeProbeBandwidth:
			goBBRSetPacingRate(c, s, s.currentBandwidth(), goBBRUnit)
		case goBBRModeProbeRoundTrip:
			s.checkProbeRoundTripDone(c)
		}
	}
}

func (s *goBBRState) bandwidthDelayProduct(bandwidth uint32, gain uint32) uint32 {
	if s.minRoundTripMicros == ^uint32(0) {
		return goInitialWindow
	}
	w := uint64(bandwidth) * uint64(s.minRoundTripMicros)
	return uint32((((w * uint64(gain)) >> goBBRScale) + goBBRBandwidthUnit - 1) / goBBRBandwidthUnit)
}

func (s *goBBRState) quantizationBudget(c *GoConn, window uint32) uint32 {
	window += 3 * goBBRTSOSegmentsGoal(c)
	window = (window + 1) &^ 1
	if s.mode == goBBRModeProbeBandwidth && s.cycleIndex == 0 {
		window += 2
	}
	return window
}

func (s *goBBRState) inflight(c *GoConn, bandwidth uint32, gain uint32) uint32 {
	return s.quantizationBudget(c, s.bandwidthDelayProduct(bandwidth, gain))
}

func (s *goBBRState) packetsInNetAtDeparture(c *GoConn, inflightNow uint32) uint32 {
	now := c.engine.coarseTime.Load()
	departure := max(c.pacingStamp.Load(), now)
	intervalMicros := uint64(departure-now) / uint64(time.Microsecond)
	intervalDelivered := uint32(uint64(s.currentBandwidth()) * intervalMicros >> goBBRBandwidthScale)
	inflightAtDeparture := inflightNow
	if s.pacingGain > goBBRUnit {
		inflightAtDeparture += goBBRTSOSegmentsGoal(c)
	}
	if intervalDelivered >= inflightAtDeparture {
		return 0
	}
	return inflightAtDeparture - intervalDelivered
}

func (s *goBBRState) ackAggregationWindow() uint32 {
	if goBBRExtraAckedGain == 0 || !s.fullBandwidthReached {
		return 0
	}
	maxAggregation := uint32(uint64(s.currentBandwidth()) * goBBRExtraAckedMaxMicros / goBBRBandwidthUnit)
	aggregation := (goBBRExtraAckedGain * s.extraAckedMax()) >> goBBRScale
	return min(aggregation, maxAggregation)
}

func (s *goBBRState) setWindowToRecoverOrRestore(c *GoConn, sample *goRateSample, acked uint32) (uint32, bool) {
	previousState := s.previousCAState
	state := c.congestionState
	window := c.congestionWindow
	inFlight := c.flight.inFlight()
	if sample.losses > 0 {
		window = uint32(max(int64(window)-int64(sample.losses), 1))
	}
	if state == goCongestionRecovery && previousState != goCongestionRecovery {
		s.packetConservation = true
		s.nextRoundDelivered = c.delivered
		window = inFlight + acked
	} else if previousState >= goCongestionRecovery && state < goCongestionRecovery {
		window = max(window, s.priorWindow)
		s.packetConservation = false
	}
	s.previousCAState = state
	if s.packetConservation {
		return max(window, inFlight+acked), true
	}
	return window, false
}

func (s *goBBRState) setWindow(c *GoConn, sample *goRateSample, acked uint32, bandwidth uint32, gain uint32) {
	window := c.congestionWindow
	if acked != 0 {
		var conserving bool
		window, conserving = s.setWindowToRecoverOrRestore(c, sample, acked)
		if !conserving {
			target := s.bandwidthDelayProduct(bandwidth, gain)
			target += s.ackAggregationWindow()
			target = s.quantizationBudget(c, target)
			if s.fullBandwidthReached {
				window = min(window+acked, target)
			} else if window < target || c.delivered < goInitialWindow {
				window += acked
			}
			window = max(window, goBBRWindowMinTarget)
		}
	}
	c.setCongestionWindow(window)
	if s.mode == goBBRModeProbeRoundTrip {
		c.setCongestionWindow(min(c.congestionWindow, goBBRWindowMinTarget))
	}
}

func (s *goBBRState) isNextCyclePhase(c *GoConn, sample *goRateSample) bool {
	fullLength := c.deliveredTime-s.cycleStamp > int64(s.minRoundTripMicros)*int64(time.Microsecond)
	if s.pacingGain == goBBRUnit {
		return fullLength
	}
	inflight := s.packetsInNetAtDeparture(c, sample.priorInFlight)
	bandwidth := s.bandwidth.get()
	if s.pacingGain > goBBRUnit {
		return fullLength && (sample.losses > 0 || inflight >= s.inflight(c, bandwidth, s.pacingGain))
	}
	return fullLength || inflight <= s.inflight(c, bandwidth, goBBRUnit)
}

func (s *goBBRState) advanceCyclePhase(c *GoConn) {
	s.cycleIndex = (s.cycleIndex + 1) & (goBBRCycleLength - 1)
	s.cycleStamp = c.deliveredTime
}

func (s *goBBRState) updateCyclePhase(c *GoConn, sample *goRateSample) {
	if s.mode == goBBRModeProbeBandwidth && s.isNextCyclePhase(c, sample) {
		s.advanceCyclePhase(c)
	}
}

func (s *goBBRState) resetProbeBandwidthMode(c *GoConn) {
	s.mode = goBBRModeProbeBandwidth
	s.cycleIndex = goBBRCycleLength - 1 - rand.Uint32N(goBBRCycleRandom)
	s.advanceCyclePhase(c)
}

func (s *goBBRState) resetMode(c *GoConn) {
	if !s.fullBandwidthReached {
		s.mode = goBBRModeStartup
	} else {
		s.resetProbeBandwidthMode(c)
	}
}

func (s *goBBRState) resetLongTermInterval(c *GoConn) {
	s.longTermLastStamp = c.deliveredTime
	s.longTermLastDelivered = c.delivered
	s.longTermLastLost = c.lost
	s.longTermRounds = 0
}

func (s *goBBRState) resetLongTermSampling(c *GoConn) {
	s.longTermBandwidth = 0
	s.longTermUseBandwidth = false
	s.longTermSampling = false
	s.resetLongTermInterval(c)
}

func (s *goBBRState) longTermIntervalDone(c *GoConn, bandwidth uint32) {
	if s.longTermBandwidth != 0 {
		var diff uint32
		if bandwidth > s.longTermBandwidth {
			diff = bandwidth - s.longTermBandwidth
		} else {
			diff = s.longTermBandwidth - bandwidth
		}
		if uint64(diff)*goBBRUnit <= uint64(goBBRLongTermBandwidthRatio)*uint64(s.longTermBandwidth) ||
			goBBRRateBytesPerSecond(c, uint64(diff), goBBRUnit) <= goBBRLongTermBandwidthDiff {
			s.longTermBandwidth = (bandwidth + s.longTermBandwidth) >> 1
			s.longTermUseBandwidth = true
			s.pacingGain = goBBRUnit
			s.longTermRounds = 0
			return
		}
	}
	s.longTermBandwidth = bandwidth
	s.resetLongTermInterval(c)
}

func (s *goBBRState) longTermSample(c *GoConn, sample *goRateSample) {
	if s.longTermUseBandwidth {
		if s.mode == goBBRModeProbeBandwidth && s.roundStart {
			s.longTermRounds++
			if s.longTermRounds >= goBBRLongTermMaxRounds {
				s.resetLongTermSampling(c)
				s.resetProbeBandwidthMode(c)
			}
		}
		return
	}
	if !s.longTermSampling {
		if sample.losses == 0 {
			return
		}
		s.resetLongTermInterval(c)
		s.longTermSampling = true
	}
	if sample.appLimited {
		s.resetLongTermSampling(c)
		return
	}
	if s.roundStart {
		s.longTermRounds++
	}
	if s.longTermRounds < goBBRLongTermMinRounds {
		return
	}
	if s.longTermRounds > 4*goBBRLongTermMinRounds {
		s.resetLongTermSampling(c)
		return
	}
	if sample.losses == 0 {
		return
	}
	lost := c.lost - s.longTermLastLost
	delivered := c.delivered - s.longTermLastDelivered
	if delivered == 0 || uint64(lost)<<goBBRScale < goBBRLongTermLossThresh*uint64(delivered) {
		return
	}
	t := (c.deliveredTime - s.longTermLastStamp) / int64(time.Millisecond)
	if t < 1 {
		return
	}
	if t >= int64(^uint32(0))/1000 {
		s.resetLongTermSampling(c)
		return
	}
	bandwidth := uint64(delivered) * goBBRBandwidthUnit / (uint64(t) * 1000)
	s.longTermIntervalDone(c, uint32(bandwidth))
}

func (s *goBBRState) updateBandwidth(c *GoConn, sample *goRateSample) {
	s.roundStart = false
	if sample.delivered < 0 || sample.intervalMicros <= 0 {
		return
	}
	if int32(sample.priorDelivered-s.nextRoundDelivered) >= 0 {
		s.nextRoundDelivered = c.delivered
		s.roundTripCount++
		s.roundStart = true
		s.packetConservation = false
	}
	s.longTermSample(c, sample)
	bandwidth := uint64(sample.delivered) * goBBRBandwidthUnit / uint64(sample.intervalMicros)
	if !sample.appLimited || bandwidth >= uint64(s.bandwidth.get()) {
		s.bandwidth.runningMax(goBBRBandwidthRounds, s.roundTripCount, uint32(min(bandwidth, uint64(^uint32(0)))))
	}
}

func (s *goBBRState) updateAckAggregation(c *GoConn, sample *goRateSample) {
	if goBBRExtraAckedGain == 0 || sample.ackedSacked == 0 || sample.delivered < 0 || sample.intervalMicros <= 0 {
		return
	}
	if s.roundStart {
		s.extraAckedWindowRounds = min(0x1f, s.extraAckedWindowRounds+1)
		if s.extraAckedWindowRounds >= goBBRExtraAckedWindowRounds {
			s.extraAckedWindowRounds = 0
			s.extraAckedWindowIndex = 1 - s.extraAckedWindowIndex
			s.extraAcked[s.extraAckedWindowIndex] = 0
		}
	}
	epochMicros := (c.deliveredTime - s.ackEpochStamp) / int64(time.Microsecond)
	high, low := bits.Mul64(uint64(s.currentBandwidth()), uint64(max(epochMicros, 0)))
	expectedAcked := uint32(goBBRAckEpochResetThresh)
	if high == 0 && low < uint64(goBBRAckEpochResetThresh)*goBBRBandwidthUnit {
		expectedAcked = uint32(low / goBBRBandwidthUnit)
	}
	if s.ackEpochAcked <= expectedAcked || s.ackEpochAcked+sample.ackedSacked >= goBBRAckEpochResetThresh {
		s.ackEpochAcked = 0
		s.ackEpochStamp = c.deliveredTime
		expectedAcked = 0
	}
	s.ackEpochAcked = min(0xfffff, s.ackEpochAcked+sample.ackedSacked)
	extraAcked := min(s.ackEpochAcked-expectedAcked, c.congestionWindow)
	if extraAcked > s.extraAcked[s.extraAckedWindowIndex] {
		s.extraAcked[s.extraAckedWindowIndex] = extraAcked
	}
}

func (s *goBBRState) checkFullBandwidthReached(sample *goRateSample) {
	if s.fullBandwidthReached || !s.roundStart || sample.appLimited {
		return
	}
	threshold := uint32(uint64(s.fullBandwidth) * goBBRFullBandwidthThresh >> goBBRScale)
	if s.bandwidth.get() >= threshold {
		s.fullBandwidth = s.bandwidth.get()
		s.fullBandwidthCount = 0
		return
	}
	s.fullBandwidthCount++
	s.fullBandwidthReached = s.fullBandwidthCount >= goBBRFullBandwidthCount
}

func (s *goBBRState) checkDrain(c *GoConn) {
	if s.mode == goBBRModeStartup && s.fullBandwidthReached {
		s.mode = goBBRModeDrain
		c.slowStartThreshold = s.inflight(c, s.bandwidth.get(), goBBRUnit)
	}
	if s.mode == goBBRModeDrain && s.packetsInNetAtDeparture(c, c.flight.inFlight()) <= s.inflight(c, s.bandwidth.get(), goBBRUnit) {
		s.resetProbeBandwidthMode(c)
	}
}

func (s *goBBRState) checkProbeRoundTripDone(c *GoConn) {
	if s.probeRoundTripDone == 0 || !goBBRAfter(goBBRJiffies(c), s.probeRoundTripDone) {
		return
	}
	s.minRoundTripStamp = goBBRJiffies(c)
	c.setCongestionWindow(max(c.congestionWindow, s.priorWindow))
	s.resetMode(c)
}

func (s *goBBRState) updateMinRoundTrip(c *GoConn, sample *goRateSample) {
	now := goBBRJiffies(c)
	filterExpired := goBBRAfter(now, s.minRoundTripStamp+goBBRMinRoundTripWindowMs)
	if sample.roundTripMicros >= 0 && (uint32(sample.roundTripMicros) < s.minRoundTripMicros || (filterExpired && !sample.ackDelayed)) {
		s.minRoundTripMicros = uint32(sample.roundTripMicros)
		s.minRoundTripStamp = now
	}
	if goBBRProbeRoundTripModeMs > 0 && filterExpired && !s.idleRestart && s.mode != goBBRModeProbeRoundTrip {
		s.mode = goBBRModeProbeRoundTrip
		s.saveWindow(c)
		s.probeRoundTripDone = 0
	}
	if s.mode == goBBRModeProbeRoundTrip {
		inFlight := c.flight.inFlight()
		c.appLimited.Store(max(c.delivered+inFlight, 1))
		if s.probeRoundTripDone == 0 && inFlight <= goBBRWindowMinTarget {
			s.probeRoundTripDone = now + goBBRProbeRoundTripModeMs
			s.probeRoundTripRoundDone = false
			s.nextRoundDelivered = c.delivered
		} else if s.probeRoundTripDone != 0 {
			if s.roundStart {
				s.probeRoundTripRoundDone = true
			}
			if s.probeRoundTripRoundDone {
				s.checkProbeRoundTripDone(c)
			}
		}
	}
	if sample.delivered > 0 {
		s.idleRestart = false
	}
}

func (s *goBBRState) updateGains() {
	switch s.mode {
	case goBBRModeStartup:
		s.pacingGain = goBBRHighGain
		s.windowGain = goBBRHighGain
	case goBBRModeDrain:
		s.pacingGain = goBBRDrainGain
		s.windowGain = goBBRHighGain
	case goBBRModeProbeBandwidth:
		if s.longTermUseBandwidth {
			s.pacingGain = goBBRUnit
		} else {
			s.pacingGain = goBBRPacingGains[s.cycleIndex]
		}
		s.windowGain = goBBRWindowGain
	case goBBRModeProbeRoundTrip:
		s.pacingGain = goBBRUnit
		s.windowGain = goBBRUnit
	}
}

func goBBRMain(c *GoConn, _ goAckFlags, sample *goRateSample) {
	s := c.congestionPrivate.(*goBBRState)
	s.updateBandwidth(c, sample)
	s.updateAckAggregation(c, sample)
	s.updateCyclePhase(c, sample)
	s.checkFullBandwidthReached(sample)
	s.checkDrain(c)
	s.updateMinRoundTrip(c, sample)
	s.updateGains()
	bandwidth := s.currentBandwidth()
	goBBRSetPacingRate(c, s, bandwidth, s.pacingGain)
	s.setWindow(c, sample, sample.ackedSacked, bandwidth, s.windowGain)
}

func goBBRInit(c *GoConn) {
	s := new(goBBRState)
	c.congestionPrivate = s
	c.slowStartThreshold = goInfiniteSlowStartThreshold
	s.nextRoundDelivered = c.delivered
	s.previousCAState = goCongestionOpen
	s.minRoundTripMicros = c.roundTripMin.get()
	s.minRoundTripStamp = goBBRJiffies(c)
	s.bandwidth.reset(s.roundTripCount, 0)
	goBBRInitPacingRateFromRoundTrip(c, s)
	s.resetLongTermSampling(c)
	s.mode = goBBRModeStartup
	s.ackEpochStamp = c.engine.coarseTime.Load()
}

func goBBRUndoWindow(c *GoConn) uint32 {
	s := c.congestionPrivate.(*goBBRState)
	s.fullBandwidth = 0
	s.fullBandwidthCount = 0
	s.resetLongTermSampling(c)
	return c.congestionWindow
}

func goBBRSlowStartThreshold(c *GoConn) uint32 {
	s := c.congestionPrivate.(*goBBRState)
	s.saveWindow(c)
	return c.slowStartThreshold
}

func goBBRSetState(c *GoConn, newState uint8) {
	if newState == goCongestionLoss {
		s := c.congestionPrivate.(*goBBRState)
		s.previousCAState = goCongestionLoss
		s.fullBandwidth = 0
		s.roundStart = true
		s.longTermSample(c, &goRateSample{losses: 1})
	}
}

var goBBROps = goCongestionOps{
	name:               "bbr",
	init:               goBBRInit,
	congControl:        goBBRMain,
	undoWindow:         goBBRUndoWindow,
	windowEventTxStart: goBBRTxStart,
	slowStartThreshold: goBBRSlowStartThreshold,
	minTSOSegments:     goBBRMinTSOSegments,
	setState:           goBBRSetState,
	pacing:             true,
}
