package tun

import "time"

// Mirrors the delivery rate estimator of net/ipv4/tcp_input.c (formerly tcp_rate.c).

func goStampMicros(units int32) int64 {
	return int64(units) * goTimeUnit / int64(time.Microsecond)
}

func goStampAfter(stamp1 int32, stamp2 int32, offset1 uint64, offset2 uint64) bool {
	delta := stamp1 - stamp2
	return delta > 0 || (delta == 0 && offset1 > offset2)
}

func goPackDelivery(delivered uint32, stamp int32) uint64 {
	return uint64(delivered)<<32 | uint64(uint32(stamp))
}

func goUnpackDelivery(state uint64) (uint32, int32) {
	return uint32(state >> 32), int32(uint32(state))
}

func (c *GoConn) snapshotDelivery(sentAt int32, flightEmpty bool) (uint32, int32, int32, bool) {
	if flightEmpty {
		for {
			state := c.deliveryState.Load()
			delivered, _ := goUnpackDelivery(state)
			if c.deliveryState.CompareAndSwap(state, goPackDelivery(delivered, sentAt)) {
				break
			}
		}
		c.firstSentStamp.Store(sentAt)
	}
	delivered, deliveredStamp := goUnpackDelivery(c.deliveryState.Load())
	return delivered, deliveredStamp, c.firstSentStamp.Load(), c.appLimited.Load() != 0
}

func (e *goEngine) rateDescriptorDelivered(conn *GoConn, descriptor *goSentDescriptor, sample *goRateSample) {
	if descriptor.flags&goDescriptorRated == 0 || descriptor.flags&(goDescriptorNoSample|goDescriptorDropped) != 0 {
		return
	}
	if !sample.valid || goStampAfter(descriptor.sentAt, conn.firstSentStamp.Load(), descriptor.endOffset, sample.lastEndOffset) {
		sample.valid = true
		sample.priorDelivered = descriptor.delivered
		sample.priorStamp = descriptor.deliveredStamp
		sample.appLimited = descriptor.flags&goDescriptorAppLimited != 0
		sample.retransmitted = descriptor.flags&goDescriptorRetransmitted != 0
		sample.lastEndOffset = descriptor.endOffset
		conn.firstSentStamp.Store(descriptor.sentAt)
		sample.sendIntervalMicros = goStampMicros(descriptor.sentAt - descriptor.firstSentStamp)
	}
	if descriptor.flags&goDescriptorSacked != 0 {
		descriptor.flags &^= goDescriptorRated
	}
}

func (e *goEngine) rateGenerate(conn *GoConn, sample *goRateSample, delivered uint32, lost uint32, now int64) {
	appLimited := conn.appLimited.Load()
	if appLimited != 0 && int32(conn.delivered-appLimited) > 0 {
		conn.appLimited.CompareAndSwap(appLimited, 0)
	}
	stamp := conn.stamp(now)
	if delivered > 0 {
		conn.deliveredTime = now
		conn.deliveredStamp = stamp
		conn.publishDelivery()
	}
	sample.ackedSacked = delivered
	sample.losses = lost
	if !sample.valid || conn.sackReneging {
		sample.delivered = -1
		sample.intervalMicros = -1
		return
	}
	sample.delivered = int64(conn.delivered - sample.priorDelivered)
	sendMicros := sample.sendIntervalMicros
	receiveMicros := goStampMicros(stamp - sample.priorStamp)
	sample.intervalMicros = max(sendMicros, receiveMicros)
	sample.receiveIntervalMicros = receiveMicros
	if sample.intervalMicros < int64(conn.minRoundTripMicros()) {
		sample.intervalMicros = -1
		return
	}
	if !sample.appLimited || uint64(sample.delivered)*uint64(conn.rateIntervalMicros) >= uint64(conn.rateDelivered)*uint64(sample.intervalMicros) {
		conn.rateDelivered = uint32(sample.delivered)
		conn.rateIntervalMicros = uint32(sample.intervalMicros)
		conn.rateAppLimited = sample.appLimited
	}
}

func (c *GoConn) countDelivered(packets uint32) {
	c.delivered += packets
	c.deliveredTime = c.engine.now()
	c.deliveredStamp = c.stamp(c.deliveredTime)
	c.publishDelivery()
}

func (c *GoConn) publishDelivery() {
	for {
		state := c.deliveryState.Load()
		_, stamp := goUnpackDelivery(state)
		if c.deliveredStamp-stamp > 0 {
			stamp = c.deliveredStamp
		}
		if c.deliveryState.CompareAndSwap(state, goPackDelivery(c.delivered, stamp)) {
			return
		}
	}
}

func (c *GoConn) checkAppLimited(pending uint64, permit uint64, sent uint64) {
	segments := c.dataSegmentsOut.Load()
	if pending >= uint64(c.effectiveMSS) || permit <= sent || int32(c.sendPacketPermit.Load()-segments) <= 0 || c.writerActive.Load() != 0 || c.writerParked.Load() {
		return
	}
	inFlight := segments - c.packetCreditBase.Load()
	delivered, _ := goUnpackDelivery(c.deliveryState.Load())
	c.appLimited.Store(max(delivered+inFlight, 1))
}
