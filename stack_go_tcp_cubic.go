package tun

import (
	"math/bits"
	"time"
)

// Mirrors net/ipv4/tcp_cubic.c with HZ = 1000.

const (
	goCubicBetaScale         = 1024
	goCubicHZ                = 10
	goCubicBeta              = 717
	goCubicScale             = 41
	goCubicHystartAckTrain   = 1
	goCubicHystartDelay      = 2
	goCubicHystartDetect     = goCubicHystartAckTrain | goCubicHystartDelay
	goCubicHystartMinSamples = 8
	goCubicHystartDelayMin   = 4000
	goCubicHystartDelayMax   = 16000
	goCubicHystartLowWindow  = 16
	goCubicHystartAckDelta   = 2000
	goCubicJiffiesPerSecond  = 1000
	goCubicUpdateInterval    = goCubicJiffiesPerSecond / 32
)

var (
	goCubicBetaScaleFactor = uint32(8 * (goCubicBetaScale + goCubicBeta) / 3 / (goCubicBetaScale - goCubicBeta))
	goCubicRoundTripScale  = uint64(goCubicScale * 10)
	goCubicFactor          = (uint64(1) << (10 + 3*goCubicHZ)) / (goCubicScale * 10)
)

type goCubicState struct {
	count            uint32
	lastMaxWindow    uint32
	lastWindow       uint32
	lastTime         uint32
	originPoint      uint32
	timeToOrigin     uint32
	minDelay         uint32
	epochStart       uint32
	ackCount         uint32
	renoWindow       uint32
	sampleCount      uint8
	found            bool
	roundStart       int64
	endOffset        uint64
	lastAck          int64
	currentRoundTrip uint32
}

func goCubicClamp(value uint32) uint32 {
	return min(max(value, goCubicHystartDelayMin), goCubicHystartDelayMax)
}

func (s *goCubicState) reset() {
	s.count = 0
	s.lastMaxWindow = 0
	s.lastWindow = 0
	s.lastTime = 0
	s.originPoint = 0
	s.timeToOrigin = 0
	s.minDelay = 0
	s.epochStart = 0
	s.ackCount = 0
	s.renoWindow = 0
	s.found = false
}

func goCubicJiffies(c *GoConn) uint32 {
	return uint32(c.engine.coarseTime.Load()/int64(time.Millisecond)) + 1
}

func goCubicMicros(c *GoConn) int64 {
	return c.engine.coarseTime.Load() / int64(time.Microsecond)
}

func (s *goCubicState) hystartReset(c *GoConn) {
	now := goCubicMicros(c)
	s.roundStart = now
	s.lastAck = now
	s.endOffset = c.sentTail.Load()
	s.currentRoundTrip = ^uint32(0)
	s.sampleCount = 0
}

func goCubicInit(c *GoConn) {
	state := new(goCubicState)
	state.reset()
	state.hystartReset(c)
	c.congestionPrivate = state
}

func goCubicTxStart(c *GoConn, idleNanos int64) {
	state := c.congestionPrivate.(*goCubicState)
	delta := idleNanos / int64(time.Millisecond)
	if state.epochStart != 0 && delta > 0 {
		now := goCubicJiffies(c)
		state.epochStart += uint32(delta)
		if int32(state.epochStart-now) > 0 {
			state.epochStart = now
		}
	}
}

var goCubicRootTable = [64]uint8{
	0, 54, 54, 54, 118, 118, 118, 118,
	123, 129, 134, 138, 143, 147, 151, 156,
	157, 161, 164, 168, 170, 173, 176, 179,
	181, 185, 187, 190, 192, 194, 197, 199,
	200, 202, 204, 206, 209, 211, 213, 215,
	217, 219, 221, 222, 224, 225, 227, 229,
	231, 232, 234, 236, 237, 239, 240, 242,
	244, 245, 246, 248, 250, 251, 252, 254,
}

func goCubicRoot(a uint64) uint32 {
	b := uint32(bits.Len64(a))
	if b < 7 {
		return (uint32(goCubicRootTable[a]) + 35) >> 6
	}
	b = ((b * 84) >> 8) - 1
	shift := a >> (b * 3)
	x := ((uint32(goCubicRootTable[shift]) + 10) << b) >> 6
	x = 2*x + uint32(a/(uint64(x)*uint64(x-1)))
	x = (x * 341) >> 10
	return x
}

func (s *goCubicState) update(c *GoConn, window uint32, acked uint32) {
	now := goCubicJiffies(c)
	s.ackCount += acked
	if s.lastWindow == window && int32(now-s.lastTime) <= goCubicUpdateInterval {
		return
	}
	if s.epochStart == 0 || now != s.lastTime {
		s.lastWindow = window
		s.lastTime = now
		if s.epochStart == 0 {
			s.epochStart = now
			s.ackCount = acked
			s.renoWindow = window
			if s.lastMaxWindow <= window {
				s.timeToOrigin = 0
				s.originPoint = window
			} else {
				s.timeToOrigin = goCubicRoot(goCubicFactor * uint64(s.lastMaxWindow-window))
				s.originPoint = s.lastMaxWindow
			}
		}
		t := uint64(now - s.epochStart)
		t += (uint64(s.minDelay) + 999) / 1000
		t <<= goCubicHZ
		t /= goCubicJiffiesPerSecond
		var offset uint64
		if t < uint64(s.timeToOrigin) {
			offset = uint64(s.timeToOrigin) - t
		} else {
			offset = t - uint64(s.timeToOrigin)
		}
		delta := uint32((goCubicRoundTripScale * offset * offset * offset) >> (10 + 3*goCubicHZ))
		var target uint32
		if t < uint64(s.timeToOrigin) {
			target = s.originPoint - delta
		} else {
			target = s.originPoint + delta
		}
		if target > window {
			s.count = window / (target - window)
		} else {
			s.count = 100 * window
		}
		if s.lastMaxWindow == 0 && s.count > 20 {
			s.count = 20
		}
	}
	friendlyDelta := (window * goCubicBetaScaleFactor) >> 3
	for s.ackCount > friendlyDelta {
		s.ackCount -= friendlyDelta
		s.renoWindow++
	}
	if s.renoWindow > window {
		maxCount := window / (s.renoWindow - window)
		if s.count > maxCount {
			s.count = maxCount
		}
	}
	s.count = max(s.count, 2)
}

func goCubicCongAvoid(c *GoConn, acked uint32) {
	state := c.congestionPrivate.(*goCubicState)
	if !c.isWindowLimited() {
		return
	}
	if c.inSlowStart() {
		acked = c.slowStart(acked)
		if acked == 0 {
			return
		}
	}
	state.update(c, c.congestionWindow, acked)
	c.congAvoidAI(state.count, acked)
}

func goCubicSlowStartThreshold(c *GoConn) uint32 {
	state := c.congestionPrivate.(*goCubicState)
	state.epochStart = 0
	window := c.congestionWindow
	if window < state.lastMaxWindow {
		state.lastMaxWindow = (window * (goCubicBetaScale + goCubicBeta)) / (2 * goCubicBetaScale)
	} else {
		state.lastMaxWindow = window
	}
	return max((window*goCubicBeta)/goCubicBetaScale, 2)
}

func goCubicSetState(c *GoConn, newState uint8) {
	if newState == goCongestionLoss {
		state := c.congestionPrivate.(*goCubicState)
		state.reset()
		state.hystartReset(c)
	}
}

func goCubicHystartAckDelay(c *GoConn) uint32 {
	rate := c.pacingRate.Load()
	if rate == 0 {
		return 0
	}
	return uint32(min(uint64(time.Second/time.Microsecond)/1000, uint64(c.gsoMaxSize(c.effectiveMSS.Load()))*4*uint64(time.Second/time.Microsecond)/rate))
}

func (s *goCubicState) hystartUpdate(c *GoConn, delay uint32) {
	if c.sendUnacked.Load() > s.endOffset {
		s.hystartReset(c)
	}
	if c.congestionWindow < goCubicHystartLowWindow {
		return
	}
	if goCubicHystartDetect&goCubicHystartAckTrain != 0 {
		now := goCubicMicros(c)
		if now-s.lastAck <= goCubicHystartAckDelta {
			s.lastAck = now
			threshold := int64(s.minDelay + goCubicHystartAckDelay(c))
			if !c.congestion.pacing {
				threshold >>= 1
			}
			if now-s.roundStart > threshold {
				s.found = true
				c.slowStartThreshold = c.congestionWindow
			}
		}
	}
	if goCubicHystartDetect&goCubicHystartDelay != 0 {
		if s.currentRoundTrip > delay {
			s.currentRoundTrip = delay
		}
		if s.sampleCount < goCubicHystartMinSamples {
			s.sampleCount++
		} else if s.currentRoundTrip > s.minDelay+goCubicClamp(s.minDelay>>3) {
			s.found = true
			c.slowStartThreshold = c.congestionWindow
		}
	}
}

func goCubicAcked(c *GoConn, sample *goAckSample) {
	state := c.congestionPrivate.(*goCubicState)
	if sample.roundTripMicros < 0 {
		return
	}
	if state.epochStart != 0 && int32(goCubicJiffies(c)-state.epochStart) < goCubicJiffiesPerSecond {
		return
	}
	delay := uint32(max(sample.roundTripMicros, 1))
	if state.minDelay == 0 || state.minDelay > delay {
		state.minDelay = delay
	}
	if !state.found && c.inSlowStart() {
		state.hystartUpdate(c, delay)
	}
}

var goCubicOps = goCongestionOps{
	name:               "cubic",
	init:               goCubicInit,
	slowStartThreshold: goCubicSlowStartThreshold,
	congAvoid:          goCubicCongAvoid,
	setState:           goCubicSetState,
	undoWindow:         goRenoUndoWindow,
	windowEventTxStart: goCubicTxStart,
	packetsAcked:       goCubicAcked,
}
