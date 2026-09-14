package tun

import (
	"syscall"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
)

// Mirrors the ACK processing and loss recovery state machine of net/ipv4/tcp_input.c.

type goSackState struct {
	firstStamp int32
	lastStamp  int32
	sampled    bool
}

func (e *goEngine) drainDescriptors(conn *GoConn) {
	before := len(conn.scoreboard.entries)
	conn.scoreboard.drain(&conn.descriptors, conn.sendUnacked.Load())
	entries := conn.scoreboard.entries
	for index := before; index < len(entries); index++ {
		descriptor := &entries[index]
		sentAt := conn.descriptorSentTime(descriptor)
		if descriptor.flags&goDescriptorTxStart != 0 {
			descriptor.flags &^= goDescriptorTxStart
			conn.rackEndOffset = 0
			conn.rackAdvanced = false
			if conn.congestion.windowEventTxStart != nil {
				var idle int64
				if conn.lastSendStamp >= 0 {
					idle = max(sentAt-conn.lastSendStamp, 0)
				}
				conn.congestion.windowEventTxStart(conn, idle)
			}
		}
		conn.lastSendStamp = sentAt
	}
	e.refreshPacketsOut(conn)
}

func (e *goEngine) summarizeFlight(conn *GoConn) {
	var summary goFlightSummary
	for index := range conn.scoreboard.entries {
		descriptor := &conn.scoreboard.entries[index]
		if descriptor.flags&goDescriptorRetransmitted != 0 {
			summary.retransmitted++
		}
		if descriptor.flags&goDescriptorSacked != 0 {
			summary.sackedOut++
			continue
		}
		if descriptor.flags&goDescriptorLost != 0 {
			summary.lostOut++
		}
		if descriptor.flags&goDescriptorRetransmitOut != 0 {
			summary.retransmitOut++
		}
	}
	if !conn.sackPermitted {
		summary.sackedOut = conn.renoSacked
	}
	conn.flight = summary
	e.refreshPacketsOut(conn)
}

func (e *goEngine) refreshPacketsOut(conn *GoConn) {
	entries := conn.scoreboard.entries
	start := conn.sendUnacked.Load()
	if len(entries) > 0 {
		start = entries[len(entries)-1].endOffset
	}
	sent := conn.sentTail.Load()
	if sent > start {
		start = sent
	}
	conn.flight.packetsOut = conn.dataSegmentsOut.Load() - conn.packetCreditBase.Load()
	conn.flight.packetsEnd = start
}

func (e *goEngine) accountRemoved(conn *GoConn, flags uint16) {
	conn.packetCreditBase.Add(1)
	if flags&goDescriptorRetransmitted != 0 {
		conn.flight.retransmitted--
	}
	if flags&goDescriptorSacked != 0 {
		conn.flight.sackedOut--
		return
	}
	if flags&goDescriptorLost != 0 {
		conn.flight.lostOut--
	}
	if flags&goDescriptorRetransmitOut != 0 {
		conn.flight.retransmitOut--
	}
}

func (e *goEngine) processAck(conn *GoConn, tcpHdr header.TCP, segOffset int64, payloadLength int, flags header.TCPFlags, timestampEcho uint32, hasTimestamp bool) bool {
	e.refreshCoarseTime()
	e.drainDescriptors(conn)
	ackOffset := conn.sendOffset(tcpHdr.AckNumber())
	limit := int64(conn.sentTail.Load())
	if conn.finSent {
		limit++
	}
	if ackOffset > limit {
		e.markAck(conn, true)
		return false
	}
	priorUnacked := conn.sendUnacked.Load()
	segmentAck := ackOffset
	if ackOffset < int64(priorUnacked) {
		ackOffset = int64(priorUnacked)
	}
	if conn.state == goTCPSynReceived {
		if conn.connState.Load() != goConnStateEngaged {
			return false
		}
		if segmentAck != int64(conn.sentTail.Load()) {
			e.sendReset(conn)
			e.detachConn(conn, E.New("go: handshake ack out of range"), goDeathImmediate)
			return false
		}
		e.establishConn(conn)
	}
	if hasTimestamp {
		conn.lastTimestampEcho = timestampEcho
	}
	var ackFlags goAckFlags
	if payloadLength > 0 || flags&(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
		ackFlags |= goAckData
	}
	rawCount := 0
	if conn.sackPermitted {
		rawCount = goParseSackBlocks(tcpHdr, int(tcpHdr.DataOffset()), conn, &e.sackRaw)
	}
	if segmentAck < int64(priorUnacked) {
		if rawCount > 0 {
			e.processOldAckSack(conn, priorUnacked, segmentAck, rawCount)
		}
		return true
	}
	windowRaw := tcpHdr.WindowSize()
	newWindow := uint64(windowRaw) << conn.peerWindowShift
	if segmentAck > int64(priorUnacked) || segOffset > conn.windowLeft1 || (segOffset == conn.windowLeft1 && (newWindow > conn.peerWindow || newWindow == 0)) {
		ackFlags |= goAckWindowUpdate
		conn.windowLeft1 = segOffset
		conn.windowLeft2 = segmentAck
		conn.peerWindow = newWindow
		conn.maxPeerWindow = max(conn.maxPeerWindow, newWindow)
		conn.lastPeerWindow = windowRaw
	}
	if ackOffset > int64(priorUnacked) {
		ackFlags |= goAckUnackedAdvanced
		conn.retransmitAttempts = 0
	}
	priorFack := conn.highestSacked
	hadOutstanding := conn.hasOutstanding()
	priorDelivered := conn.delivered
	priorLost := conn.lost
	sample := &e.rateSample
	*sample = goRateSample{roundTripMicros: -1, priorInFlight: conn.flight.inFlight()}
	var sackState goSackState
	if rawCount > 0 {
		raw := e.sackRaw[:rawCount]
		if goIsDuplicateSack(raw, ackOffset) {
			e.applyDuplicateSack(conn, raw[0], priorUnacked, &ackFlags)
			raw = raw[1:]
		}
		sackCount := goSelectSackBlocks(raw, uint64(ackOffset), conn.sentTail.Load(), &e.sackScratch)
		if sackCount > 0 {
			e.applySackBlocks(conn, e.sackScratch[:sackCount], &ackFlags, sample, &sackState)
		}
	}
	ackFlags |= e.cleanRetransmitQueue(conn, uint64(ackOffset), priorFack, priorUnacked, sample, &sackState, timestampEcho, hasTimestamp)
	e.rackUpdateReorderWindow(conn, sample)
	if conn.probeHighSeq != 0 {
		e.processProbeAck(conn, uint64(ackOffset), ackFlags)
	}
	rexmit := goRexmitNone
	if !hadOutstanding {
		if ackFlags&goAckDSACK != 0 {
			rexmit = e.fastretransAlert(conn, priorUnacked, 0, &ackFlags)
		}
	} else {
		if ackFlags&goAckNotDuplicate == 0 || ackFlags&goAckAlert != 0 || conn.congestionState != goCongestionOpen {
			numDupack := uint32(0)
			if ackFlags&(goAckUnackedAdvanced|goAckNotDuplicate|goAckDSACK) == 0 {
				numDupack = 1
			}
			rexmit = e.fastretransAlert(conn, priorUnacked, numDupack, &ackFlags)
		}
		sample.ackDelayed = ackFlags&goAckMaybeDelayed != 0
		delivered := conn.delivered - priorDelivered
		e.rateGenerate(conn, sample, delivered, conn.lost-priorLost, e.now())
		e.validateWindow(conn)
		e.congestionControl(conn, delivered, ackFlags, sample)
		e.updateFrameLimit(conn)
	}
	if ackFlags&goAckUnackedAdvanced != 0 {
		e.advanceFinState(conn)
		if conn.connState.Load() >= goConnStateAborted {
			return true
		}
		if len(conn.scoreboard.entries) == 0 && conn.sendUnacked.Load() == conn.sentTail.Load() {
			e.armIdleRestart(conn)
		}
		if ackFlags&goAckKeepTimer == 0 {
			e.rearmRetransmit(conn)
		}
	}
	e.xmitRecovery(conn, rexmit)
	e.updatePersist(conn)
	conn.releaseIdleDescriptors()
	conn.publishPermit(uint64(ackOffset))
	return true
}

func (e *goEngine) processOldAckSack(conn *GoConn, priorUnacked uint64, ackOffset int64, rawCount int) {
	var ackFlags goAckFlags
	sample := goRateSample{roundTripMicros: -1, priorInFlight: conn.flight.inFlight()}
	var sackState goSackState
	raw := e.sackRaw[:rawCount]
	if goIsDuplicateSack(raw, ackOffset) {
		e.applyDuplicateSack(conn, raw[0], priorUnacked, &ackFlags)
		raw = raw[1:]
	}
	sackCount := goSelectSackBlocks(raw, priorUnacked, conn.sentTail.Load(), &e.sackScratch)
	if sackCount > 0 {
		e.applySackBlocks(conn, e.sackScratch[:sackCount], &ackFlags, &sample, &sackState)
	}
	e.refreshPacketsOut(conn)
	rexmit := e.fastretransAlert(conn, priorUnacked, 0, &ackFlags)
	e.xmitRecovery(conn, rexmit)
	conn.publishPermit(priorUnacked)
}

func (e *goEngine) applyDuplicateSack(conn *GoConn, block goRawSackBlock, priorUnacked uint64, flags *goAckFlags) {
	if block.start < 1 || block.end <= block.start || uint64(block.end) > conn.sentTail.Load() {
		return
	}
	start := uint64(block.start)
	end := uint64(block.end)
	if end-start > conn.maxPeerWindow {
		return
	}
	packets := (end - start + uint64(conn.effectiveMSS) - 1) / uint64(conn.effectiveMSS)
	conn.duplicateSegments += packets
	if conn.duplicateSegments > conn.totalRetransmits {
		return
	}
	*flags |= goAckDSACK
	if end-start <= uint64(conn.effectiveMSS) && conn.probeHighSeq != 0 && conn.probeRetransmitted && end == conn.probeHighSeq {
		*flags |= goAckDSACKProbe
	}
	if conn.reorderingSeen != 0 && *flags&goAckDSACKProbe == 0 {
		conn.rackDSACKSeen = true
	}
	if end <= priorUnacked {
		if conn.undoMarker != 0 && conn.undoRetransmits > 0 && end > conn.undoMarker {
			conn.undoRetransmits -= int32(min(packets, uint64(conn.undoRetransmits)))
		}
		return
	}
	descriptorStart := priorUnacked
	for index := range conn.scoreboard.entries {
		descriptor := &conn.scoreboard.entries[index]
		descriptorEnd := descriptor.endOffset
		if descriptorStart >= end {
			break
		}
		if descriptorStart >= start && descriptorEnd <= end && descriptor.flags&goDescriptorRetransmitted != 0 {
			if conn.undoMarker != 0 && conn.undoRetransmits > 0 && descriptorEnd > conn.undoMarker {
				conn.undoRetransmits--
			}
			if descriptor.flags&goDescriptorRetransmitOut != 0 && descriptor.flags&goDescriptorSacked == 0 {
				conn.flight.retransmitOut--
			}
			descriptor.flags &^= goDescriptorRetransmitOut
		}
		descriptorStart = descriptorEnd
	}
}

func (e *goEngine) applySackBlocks(conn *GoConn, blocks []goSackBlock, flags *goAckFlags, sample *goRateSample, sackState *goSackState) {
	unacked := conn.sendUnacked.Load()
	priorHighest := conn.highestSacked
	reorder := conn.sentTail.Load()
	start := unacked
	scoreboard := &conn.scoreboard
	for index := 0; index < len(scoreboard.entries); index++ {
		descriptor := &scoreboard.entries[index]
		end := descriptor.endOffset
		if descriptor.flags&goDescriptorSacked == 0 {
			for _, block := range blocks {
				if block.start > start || block.end < end {
					continue
				}
				e.rackAdvance(conn, descriptor, end)
				if descriptor.flags&goDescriptorRetransmitted == 0 {
					if start < priorHighest && start < reorder {
						reorder = start
					}
					if end <= conn.highSeq {
						*flags |= goAckOriginalSacked
					}
					if descriptor.flags&(goDescriptorNoSample|goDescriptorDropped) == 0 {
						if !sackState.sampled {
							sackState.firstStamp = descriptor.sentAt
							sackState.sampled = true
						}
						sackState.lastStamp = descriptor.sentAt
					}
				}
				if descriptor.flags&goDescriptorRetransmitOut != 0 {
					if descriptor.flags&goDescriptorLost != 0 {
						descriptor.flags &^= goDescriptorLost | goDescriptorRetransmitOut
						conn.flight.lostOut--
						conn.flight.retransmitOut--
					} else {
						conn.flight.retransmitOut--
					}
				} else if descriptor.flags&goDescriptorLost != 0 {
					descriptor.flags &^= goDescriptorLost
					conn.flight.lostOut--
				}
				descriptor.flags |= goDescriptorSacked
				conn.flight.sackedOut++
				conn.highestSacked = max(conn.highestSacked, end)
				*flags |= goAckDataSacked
				conn.countDelivered(1)
				e.rateDescriptorDelivered(conn, descriptor, sample)
				break
			}
		}
		start = end
	}
	if conn.congestionState != goCongestionLoss || conn.undoMarker != 0 {
		e.checkSackReordering(conn, reorder)
	}
}

func (e *goEngine) cleanRetransmitQueue(conn *GoConn, ackOffset uint64, priorFack uint64, priorUnacked uint64, sample *goRateSample, sackState *goSackState, timestampEcho uint32, hasTimestamp bool) goAckFlags {
	var flags goAckFlags
	sent := conn.sentTail.Load()
	newUnacked := min(ackOffset, sent)
	priorSacked := conn.flight.sackedOut
	var (
		firstStamp   int32
		lastStamp    int32
		sampled      bool
		unsampled    bool
		packetsAcked uint32
	)
	reorder := sent
	start := priorUnacked
	entries := conn.scoreboard.entries
	for index := range entries {
		descriptor := &entries[index]
		if descriptor.endOffset > newUnacked {
			break
		}
		if descriptor.flags&goDescriptorRetransmitted != 0 {
			flags |= goAckRetransmittedAcked
		} else if descriptor.flags&goDescriptorSacked == 0 {
			if descriptor.flags&(goDescriptorNoSample|goDescriptorDropped) != 0 {
				unsampled = true
			} else {
				lastStamp = descriptor.sentAt
				if !sampled {
					firstStamp = descriptor.sentAt
					sampled = true
				}
			}
			if start < reorder {
				reorder = start
			}
			if descriptor.endOffset <= conn.highSeq {
				flags |= goAckOriginalSacked
			}
		}
		if descriptor.flags&goDescriptorSacked == 0 && conn.sackPermitted {
			conn.countDelivered(1)
			if !conn.spuriousRetransmit(descriptor) {
				e.rackAdvance(conn, descriptor, descriptor.endOffset)
			}
		}
		packetsAcked++
		e.rateDescriptorDelivered(conn, descriptor, sample)
		e.accountRemoved(conn, descriptor.flags)
		flags |= goAckDataAcked
		start = descriptor.endOffset
	}
	if conn.finSent && ackOffset > conn.finOffset {
		conn.finAcked = true
	}
	if newUnacked > priorUnacked {
		conn.scoreboard.advance(newUnacked)
		conn.releaseTransmitted(newUnacked)
		conn.sendUnacked.Store(newUnacked)
		if len(conn.scoreboard.entries) > 0 && conn.scoreboard.entries[0].flags&goDescriptorSacked != 0 {
			flags |= goAckReneging
		}
	}
	e.refreshPacketsOut(conn)
	now := e.now()
	nowStamp := conn.stamp(now)
	sequenceRoundTrip := int64(-1)
	sackRoundTrip := int64(-1)
	controlRoundTrip := int64(-1)
	if sampled && !unsampled && flags&goAckRetransmittedAcked == 0 {
		sequenceRoundTrip = goStampMicros(nowStamp - firstStamp)
		controlRoundTrip = goStampMicros(nowStamp - lastStamp)
		if packetsAcked == 1 && priorSacked == 0 && newUnacked-priorUnacked < uint64(conn.effectiveMSS) &&
			sample.priorDelivered+1 == conn.delivered && flags&goAckAlert == 0 {
			flags |= goAckMaybeDelayed
		}
	}
	if sackState.sampled {
		sackRoundTrip = goStampMicros(nowStamp - sackState.firstStamp)
		controlRoundTrip = goStampMicros(nowStamp - sackState.lastStamp)
	}
	e.ackUpdateRoundTrip(conn, flags, sequenceRoundTrip, sackRoundTrip, controlRoundTrip, sample, timestampEcho, hasTimestamp, now)
	if flags&goAckDataAcked != 0 {
		if !conn.sackPermitted {
			e.removeRenoSacks(conn, packetsAcked)
			if flags&goAckRetransmittedAcked != 0 {
				flags &^= goAckOriginalSacked
			}
		} else if reorder < priorFack {
			e.checkSackReordering(conn, reorder)
		}
		conn.probeAttempts = 0
	}
	if conn.congestion.packetsAcked != nil {
		ackSample := &e.ackSample
		*ackSample = goAckSample{
			packetsAcked:    packetsAcked,
			roundTripMicros: sample.roundTripMicros,
			inFlightBytes:   uint64(conn.effectiveMSS) * uint64(conn.delivered-sample.priorDelivered),
		}
		conn.congestion.packetsAcked(conn, ackSample)
	}
	return flags
}

func (e *goEngine) ackUpdateRoundTrip(conn *GoConn, flags goAckFlags, sequenceRoundTrip int64, sackRoundTrip int64, controlRoundTrip int64, sample *goRateSample, timestampEcho uint32, hasTimestamp bool, now int64) {
	if sequenceRoundTrip < 0 {
		sequenceRoundTrip = sackRoundTrip
	}
	if sequenceRoundTrip < 0 && hasTimestamp && timestampEcho != 0 && flags&goAckDataAcked != 0 {
		elapsed := goTimestampAt(now) - timestampEcho
		if int32(elapsed) >= 0 {
			sequenceRoundTrip = max(int64(elapsed)<<goTimestampShift/int64(time.Microsecond), 1)
			controlRoundTrip = sequenceRoundTrip
		}
	}
	sample.roundTripMicros = controlRoundTrip
	if sequenceRoundTrip < 0 {
		return
	}
	e.updateRoundTripMin(conn, uint32(min(controlRoundTrip, goRTOMaxMicros)), flags, now)
	measured := int32(min(sequenceRoundTrip, goRTOMaxMicros))
	if conn.smoothedRoundTrip == 0 {
		conn.smoothedRoundTrip = measured
		conn.roundTripVariance = measured / 2
	} else {
		difference := measured - conn.smoothedRoundTrip
		if difference < 0 {
			difference = -difference
		}
		conn.roundTripVariance += (difference - conn.roundTripVariance) / 4
		conn.smoothedRoundTrip += (measured - conn.smoothedRoundTrip) / 8
	}
	deviation := max(4*conn.roundTripVariance, goRTOGranularity)
	conn.retransmitTimeout = min(max(conn.smoothedRoundTrip+deviation, goRTOFloorMicros), goRTOMaxMicros)
}

func (e *goEngine) updateRoundTripMin(conn *GoConn, roundTripMicros uint32, flags goAckFlags, now int64) {
	if flags&goAckMaybeDelayed != 0 && roundTripMicros > conn.roundTripMin.get() {
		return
	}
	conn.roundTripMin.runningMin(uint32(goMinRoundTripWindow/time.Millisecond), uint32(now/int64(time.Millisecond)), max(roundTripMicros, 1))
}

func (e *goEngine) limitRenoSacked(conn *GoConn) bool {
	holes := min(max(conn.flight.lostOut, 1), conn.flight.packetsOut)
	if conn.renoSacked+holes > conn.flight.packetsOut {
		conn.renoSacked = conn.flight.packetsOut - holes
		conn.flight.sackedOut = conn.renoSacked
		return true
	}
	return false
}

func (e *goEngine) checkRenoReordering(conn *GoConn, addend uint32) {
	if !e.limitRenoSacked(conn) {
		return
	}
	conn.reordering = min(conn.flight.packetsOut+addend, goMaxReordering)
	conn.reorderingSeen++
}

func (e *goEngine) addRenoSack(conn *GoConn, numDupack uint32) {
	if numDupack == 0 {
		return
	}
	prior := conn.renoSacked
	conn.renoSacked += numDupack
	conn.flight.sackedOut = conn.renoSacked
	e.checkRenoReordering(conn, 0)
	if conn.renoSacked > prior {
		conn.countDelivered(conn.renoSacked - prior)
	}
}

func (e *goEngine) removeRenoSacks(conn *GoConn, acked uint32) {
	if acked > 0 {
		conn.countDelivered(max(acked-min(acked, conn.renoSacked), 1))
		if acked-1 >= conn.renoSacked {
			conn.renoSacked = 0
		} else {
			conn.renoSacked -= acked - 1
		}
	}
	conn.flight.sackedOut = conn.renoSacked
	e.checkRenoReordering(conn, acked)
}

func (e *goEngine) processProbeAck(conn *GoConn, ackOffset uint64, flags goAckFlags) {
	if ackOffset < conn.probeHighSeq {
		return
	}
	switch {
	case !conn.probeRetransmitted:
		conn.probeHighSeq = 0
	case flags&goAckDSACKProbe != 0:
		conn.probeHighSeq = 0
	case ackOffset > conn.probeHighSeq:
		e.initWindowReduction(conn)
		conn.setCAState(goCongestionCWR)
		e.endWindowReduction(conn)
		e.tryKeepOpen(conn)
	case flags&(goAckUnackedAdvanced|goAckNotDuplicate|goAckDataSacked) == 0:
		conn.probeHighSeq = 0
	}
}

func (e *goEngine) markLost(conn *GoConn, descriptor *goSentDescriptor) {
	if descriptor.flags&goDescriptorSacked != 0 || descriptor.endOffset > conn.transmittedTail.Load() {
		return
	}
	if descriptor.flags&goDescriptorLost != 0 {
		if descriptor.flags&goDescriptorRetransmitOut != 0 {
			descriptor.flags &^= goDescriptorRetransmitOut
			conn.flight.retransmitOut--
			conn.lost++
		}
		return
	}
	descriptor.flags |= goDescriptorLost
	conn.flight.lostOut++
	conn.lost++
}

func (e *goEngine) accountSplit(conn *GoConn, flags uint16) {
	conn.packetCreditBase.Add(^uint32(0))
	conn.flight.packetsOut++
	if flags&goDescriptorRetransmitted != 0 {
		conn.flight.retransmitted++
	}
	if flags&goDescriptorSacked != 0 {
		conn.flight.sackedOut++
		return
	}
	if flags&goDescriptorLost != 0 {
		conn.flight.lostOut++
	}
	if flags&goDescriptorRetransmitOut != 0 {
		conn.flight.retransmitOut++
	}
}

func (c *GoConn) descriptorSentTime(descriptor *goSentDescriptor) int64 {
	now := c.engine.now()
	units := (now - c.epoch) / goTimeUnit
	age := int64(int32(units) - descriptor.sentAt)
	return c.epoch + (units-age)*goTimeUnit
}

func (c *GoConn) descriptorTimestamp(descriptor *goSentDescriptor) uint32 {
	return goTimestampAt(c.descriptorSentTime(descriptor))
}

func (c *GoConn) spuriousRetransmit(descriptor *goSentDescriptor) bool {
	return descriptor.flags&goDescriptorRetransmitted != 0 && c.echoedTimestampBefore(c.descriptorTimestamp(descriptor))
}

func (e *goEngine) rackAdvance(conn *GoConn, descriptor *goSentDescriptor, endOffset uint64) {
	if descriptor.flags&(goDescriptorNoSample|goDescriptorDropped) != 0 {
		return
	}
	roundTrip := goStampMicros(conn.stamp(e.now()) - descriptor.sentAt)
	if roundTrip < int64(conn.minRoundTripMicros()) && descriptor.flags&goDescriptorRetransmitted != 0 {
		return
	}
	conn.rackAdvanced = true
	conn.rackRoundTripMicros = roundTrip
	if conn.rackEndOffset == 0 || goStampAfter(descriptor.sentAt, conn.rackStamp, endOffset, conn.rackEndOffset) {
		conn.rackStamp = descriptor.sentAt
		conn.rackEndOffset = endOffset
	}
}

func (e *goEngine) rackReorderWindow(conn *GoConn) int64 {
	if conn.reorderingSeen == 0 {
		if conn.congestionState >= goCongestionRecovery {
			return 0
		}
		if conn.flight.sackedOut >= conn.reordering {
			return 0
		}
	}
	return min(int64(conn.minRoundTripMicros()>>2)*int64(conn.reorderWindowSteps), int64(conn.smoothedRoundTrip))
}

func (e *goEngine) rackDescriptorTimeout(conn *GoConn, descriptor *goSentDescriptor, reorderWindow int64, now int64) int64 {
	return conn.rackRoundTripMicros + reorderWindow - goStampMicros(conn.stamp(now)-descriptor.sentAt)
}

func (e *goEngine) rackDetectLoss(conn *GoConn) int64 {
	if conn.rackEndOffset == 0 {
		return 0
	}
	now := e.now()
	reorderWindow := e.rackReorderWindow(conn)
	timeout := int64(0)
	ordered := conn.flight.retransmitted == 0
	for index := range conn.scoreboard.entries {
		descriptor := &conn.scoreboard.entries[index]
		if descriptor.flags&goDescriptorSacked != 0 {
			continue
		}
		if descriptor.flags&goDescriptorLost != 0 && descriptor.flags&goDescriptorRetransmitOut == 0 {
			continue
		}
		if !goStampAfter(conn.rackStamp, descriptor.sentAt, conn.rackEndOffset, descriptor.endOffset) {
			if ordered {
				break
			}
			continue
		}
		remaining := e.rackDescriptorTimeout(conn, descriptor, reorderWindow, now)
		if remaining <= 0 {
			e.markLost(conn, descriptor)
		} else {
			timeout = max(timeout, remaining)
		}
	}
	return timeout
}

func (e *goEngine) rackMarkLost(conn *GoConn) bool {
	if !conn.rackAdvanced {
		return false
	}
	conn.rackAdvanced = false
	timeout := e.rackDetectLoss(conn)
	if timeout == 0 {
		return false
	}
	conn.reorderDeadline = e.now() + (timeout+goRackTimeoutMinMicros)*int64(time.Microsecond)
	e.rearmTimer(conn)
	return true
}

func (e *goEngine) expireReorder(conn *GoConn) {
	conn.reorderDeadline = 0
	if !conn.hasOutstandingData() {
		e.rearmTimer(conn)
		return
	}
	e.drainDescriptors(conn)
	e.summarizeFlight(conn)
	priorInFlight := conn.flight.inFlight()
	priorLost := conn.lost
	e.rackDetectLoss(conn)
	if priorInFlight != conn.flight.inFlight() {
		if conn.congestionState != goCongestionRecovery {
			e.enterRecovery(conn)
			if conn.congestion.congControl == nil {
				e.reduceWindow(conn, 1, conn.lost-priorLost, 0)
			}
		}
		e.xmitRetransmitQueue(conn)
		conn.publishPermit(conn.sendUnacked.Load())
	}
	if conn.retransmitDeadline == 0 {
		e.rearmRetransmit(conn)
	} else {
		e.rearmTimer(conn)
	}
}

func (e *goEngine) rackUpdateReorderWindow(conn *GoConn, sample *goRateSample) {
	if !conn.sackPermitted || !sample.valid {
		return
	}
	if int32(sample.priorDelivered-conn.rackLastDelivered) < 0 {
		conn.rackDSACKSeen = false
	}
	if conn.rackDSACKSeen {
		conn.reorderWindowSteps = min(0xff, conn.reorderWindowSteps+1)
		conn.rackDSACKSeen = false
		conn.rackLastDelivered = conn.delivered
		conn.reorderWindowPersist = goRackRecoveryThreshold
	} else if conn.reorderWindowPersist == 0 {
		conn.reorderWindowSteps = 1
	}
}

func (e *goEngine) identifyPacketLoss(conn *GoConn, flags goAckFlags) {
	entries := conn.scoreboard.entries
	if len(entries) == 0 {
		return
	}
	if !conn.sackPermitted {
		if (conn.congestionState < goCongestionRecovery && conn.renoSacked >= conn.reordering) || (conn.congestionState == goCongestionRecovery && flags&goAckUnackedAdvanced != 0) {
			if entries[0].flags&goDescriptorLost == 0 {
				e.markLost(conn, &entries[0])
			}
		}
	} else {
		e.rackMarkLost(conn)
	}
}

func (e *goEngine) timeToRecover(conn *GoConn) bool {
	return conn.flight.lostOut != 0
}

func (e *goEngine) processLoss(conn *GoConn, flags *goAckFlags, numDupack uint32) uint8 {
	unacked := conn.sendUnacked.Load()
	sent := conn.sentTail.Load()
	recovered := unacked >= conn.highSeq
	if *flags&goAckUnackedAdvanced != 0 && e.tryUndoLoss(conn, *flags, false) {
		return goRexmitNone
	}
	if conn.frto {
		if *flags&goAckOriginalSacked != 0 && e.tryUndoLoss(conn, *flags, true) {
			return goRexmitNone
		}
		if sent > conn.highSeq {
			if *flags&goAckDataSacked != 0 || numDupack > 0 {
				conn.frto = false
			}
		} else if *flags&goAckUnackedAdvanced != 0 && !recovered {
			conn.highSeq = sent
			windowEnd := uint64(max(conn.windowLeft2+int64(conn.peerWindow), 0))
			if conn.hasDataWaiting() && windowEnd > sent {
				return goRexmitNew
			}
			conn.frto = false
		}
	}
	if recovered {
		e.tryUndoRecovery(conn, *flags)
		return goRexmitNone
	}
	if !conn.sackPermitted {
		if sent > conn.highSeq && numDupack > 0 {
			e.addRenoSack(conn, numDupack)
		} else if *flags&goAckUnackedAdvanced != 0 {
			conn.renoSacked = 0
			conn.flight.sackedOut = 0
		}
	}
	return goRexmitLost
}

func (e *goEngine) fastretransAlert(conn *GoConn, priorUnacked uint64, numDupack uint32, flags *goAckFlags) uint8 {
	unacked := conn.sendUnacked.Load()
	if conn.flight.packetsOut == 0 && conn.renoSacked != 0 {
		conn.renoSacked = 0
		conn.flight.sackedOut = 0
	}
	if *flags&goAckReneging != 0 && *flags&goAckUnackedAdvanced != 0 {
		delay := max(int64(conn.smoothedRoundTrip)/2, int64(10*time.Millisecond/time.Microsecond))
		conn.retransmitDeadline = e.now() + delay*int64(time.Microsecond)
		e.rearmTimer(conn)
		*flags |= goAckKeepTimer
		return goRexmitNone
	}
	if conn.congestionState == goCongestionOpen {
		conn.retransmitStamp = 0
	} else if unacked >= conn.highSeq {
		switch conn.congestionState {
		case goCongestionCWR:
			if unacked != conn.highSeq {
				e.endWindowReduction(conn)
				conn.setCAState(goCongestionOpen)
			}
		case goCongestionRecovery:
			if !conn.sackPermitted {
				conn.renoSacked = 0
				conn.flight.sackedOut = 0
			}
			if e.tryUndoRecovery(conn, *flags) {
				return goRexmitNone
			}
			e.endWindowReduction(conn)
		}
	}
	switch conn.congestionState {
	case goCongestionRecovery:
		if *flags&goAckUnackedAdvanced == 0 {
			if !conn.sackPermitted {
				e.addRenoSack(conn, numDupack)
			}
		} else if e.tryUndoPartial(conn, *flags, priorUnacked) {
			return goRexmitNone
		}
		if e.tryUndoDSACK(conn) {
			e.tryToOpen(conn)
		}
		e.identifyPacketLoss(conn, *flags)
		if conn.congestionState != goCongestionRecovery {
			if !e.timeToRecover(conn) {
				return goRexmitNone
			}
			e.enterRecovery(conn)
		}
		return goRexmitLost
	case goCongestionLoss:
		rexmit := e.processLoss(conn, flags, numDupack)
		e.identifyPacketLoss(conn, *flags)
		if conn.congestionState != goCongestionOpen {
			return rexmit
		}
	}
	if !conn.sackPermitted {
		if *flags&goAckUnackedAdvanced != 0 {
			conn.renoSacked = 0
			conn.flight.sackedOut = 0
		}
		e.addRenoSack(conn, numDupack)
	}
	if conn.congestionState <= goCongestionDisorder {
		e.tryUndoDSACK(conn)
	}
	e.identifyPacketLoss(conn, *flags)
	if !e.timeToRecover(conn) {
		e.tryToOpen(conn)
		return goRexmitNone
	}
	e.enterRecovery(conn)
	return goRexmitLost
}

func (e *goEngine) xmitRecovery(conn *GoConn, rexmit uint8) {
	if rexmit == goRexmitNone || rexmit == goRexmitNew {
		return
	}
	e.xmitRetransmitQueue(conn)
}

func (e *goEngine) xmitRetransmitQueue(conn *GoConn) {
	if conn.flight.packetsOut == 0 {
		return
	}
	start := conn.sendUnacked.Load()
	sent := 0
	for index := 0; index < len(conn.scoreboard.entries); index++ {
		descriptor := &conn.scoreboard.entries[index]
		end := descriptor.endOffset
		if conn.congestionWindow <= conn.flight.inFlight() || conn.flight.retransmitOut >= conn.flight.lostOut {
			return
		}
		if descriptor.flags&(goDescriptorSacked|goDescriptorRetransmitOut) != 0 || descriptor.flags&goDescriptorLost == 0 {
			start = end
			continue
		}
		if conn.congestion.pacing {
			stamp := conn.pacingStamp.Load()
			if stamp > e.now()+goWheelTick {
				conn.pacingDeadline = stamp - goWheelTick
				e.rearmTimer(conn)
				return
			}
		}
		if e.transmitRetransmit(conn, start, int(end-start), false) == 0 {
			return
		}
		sent++
		if sent == goRecoveryBurst {
			return
		}
		start = conn.scoreboard.entries[index].endOffset
	}
}

func (e *goEngine) transmitRetransmit(conn *GoConn, offset uint64, length int, probe bool) int {
	windowEnd := uint64(max(conn.windowLeft2+int64(conn.peerWindow), 0))
	limit := min(conn.transmittedTail.Load(), windowEnd)
	if conn.peerWindow == 0 || offset >= limit {
		return 0
	}
	length = int(min(uint64(length), uint64(conn.effectiveMSS), limit-offset))
	for _, descriptor := range conn.scoreboard.entries {
		if descriptor.endOffset > offset {
			length = min(length, int(descriptor.endOffset-offset))
			break
		}
	}
	segment := goSegment{offset: offset, length: length, flags: header.TCPFlagAck | header.TCPFlagPsh}
	if !e.writeConnControl(conn, &segment) {
		return 0
	}
	conn.totalRetransmits++
	conn.advancePacing(e.now(), length)
	end := offset + uint64(length)
	marked := e.markRetransmitted(conn, offset, end, probe)
	if !probe && marked > 0 {
		conn.flight.retransmitOut += marked
		if conn.inWindowReduction() {
			conn.reductionRetransmits += marked
		}
		if conn.undoRetransmits < 0 {
			conn.undoRetransmits = 0
		}
		conn.undoRetransmits += int32(marked)
	}
	if conn.retransmitStamp == 0 {
		conn.retransmitStamp = goTimestampAt(e.now())
	}
	return length
}

func (e *goEngine) markRetransmitted(conn *GoConn, start uint64, end uint64, probe bool) uint32 {
	previous := conn.sendUnacked.Load()
	stamp := conn.stamp(e.now())
	marked := uint32(0)
	appLimited := conn.appLimited.Load() != 0
	scoreboard := &conn.scoreboard
	for index := 0; index < len(scoreboard.entries); index++ {
		descriptor := &scoreboard.entries[index]
		descriptorEnd := descriptor.endOffset
		if previous >= end {
			break
		}
		if descriptorEnd <= start {
			previous = descriptorEnd
			continue
		}
		if previous < start {
			flags := descriptor.flags
			scoreboard.split(index, start)
			e.accountSplit(conn, flags)
			index++
			descriptor = &scoreboard.entries[index]
		}
		if end < descriptorEnd {
			flags := descriptor.flags
			scoreboard.split(index, end)
			e.accountSplit(conn, flags)
			descriptor = &scoreboard.entries[index]
			descriptorEnd = end
		}
		if descriptor.flags&goDescriptorRetransmitted == 0 {
			conn.flight.retransmitted++
		}
		descriptor.flags |= goDescriptorRetransmitted
		descriptor.flags &^= goDescriptorDropped | goDescriptorNoSample
		if !probe && descriptor.flags&goDescriptorRetransmitOut == 0 {
			descriptor.flags |= goDescriptorRetransmitOut
			marked++
		}
		descriptor.sentAt = stamp
		descriptor.delivered = conn.delivered
		descriptor.deliveredStamp = conn.deliveredStamp
		descriptor.firstSentStamp = conn.firstSentStamp.Load()
		descriptor.flags |= goDescriptorRated
		if appLimited {
			descriptor.flags |= goDescriptorAppLimited
		} else {
			descriptor.flags &^= goDescriptorAppLimited
		}
		previous = descriptorEnd
	}
	return marked
}

func (c *GoConn) publishPermit(ackOffset uint64) {
	unacked := c.sendUnacked.Load()
	limit := max(c.flight.packetsEnd, unacked)
	inFlight := c.flight.inFlight()
	if c.congestionWindow > inFlight {
		limit += uint64(c.congestionWindow-inFlight) * uint64(c.effectiveMSS)
	}
	windowEnd := ackOffset + c.peerWindow
	c.permitWindowBound.Store(limit <= windowEnd)
	permit := max(min(limit, windowEnd), unacked)
	c.sendPacketPermit.Store(c.packetCreditBase.Load() + c.congestionWindow + c.flight.leftOut() - c.flight.retransmitOut)
	c.sendPermit.Store(permit)
	c.wakeTransmitter()
	c.wakeWriter()
}

func (c *GoConn) gsoMaxSize() uint32 {
	mss := uint32(c.effectiveMSS)
	if c.engine.platformIO.transmitSegmentOffload() {
		return max(goGSOMaxPayload/mss*mss, mss)
	}
	return max(0xffff/mss*mss, mss)
}

func (e *goEngine) updateFrameLimit(conn *GoConn) {
	rate := conn.pacingRate.Load()
	if rate == 0 {
		conn.frameLimit.Store(0)
		return
	}
	bytes := rate >> goPacingShift
	shift := conn.minRoundTripMicros() >> goTSORoundTripShift
	gsoMax := uint64(conn.gsoMaxSize())
	if shift < 64 {
		bytes += gsoMax >> shift
	}
	bytes = min(bytes, gsoMax)
	minSegments := uint32(goMinTSOSegments)
	if conn.congestion.minTSOSegments != nil {
		minSegments = conn.congestion.minTSOSegments(conn)
	}
	mss := uint64(conn.effectiveMSS)
	segments := max(uint32(bytes/mss), minSegments)
	conn.frameLimit.Store(uint32(min(uint64(segments)*mss, gsoMax)))
}

func (e *goEngine) handlePacingRequest(conn *GoConn) {
	if conn.connState.Load() >= goConnStateAborted {
		return
	}
	conn.pacingDeadline = conn.pacingRequest.Load()
	e.rearmTimer(conn)
}

func (e *goEngine) expirePacing(conn *GoConn) {
	conn.pacingDeadline = 0
	e.rearmTimer(conn)
	if conn.flight.lostOut > conn.flight.retransmitOut && conn.congestionWindow > conn.flight.inFlight() {
		e.xmitRetransmitQueue(conn)
		conn.publishPermit(conn.sendUnacked.Load())
		return
	}
	conn.wakeTransmitter()
}

func (e *goEngine) armProbe(conn *GoConn) {
	if conn.probeAttempts >= goProbeAttempts || !conn.hasOutstanding() || !conn.sackPermitted || (conn.congestionState != goCongestionOpen && conn.congestionState != goCongestionCWR) {
		conn.probeDeadline = 0
		return
	}
	timeout := int32(goProbeNoSampleMicros)
	if conn.smoothedRoundTrip > 0 {
		timeout = max(2*conn.smoothedRoundTrip, goProbeFloorMicros)
	}
	if conn.sentTail.Load()-conn.sendUnacked.Load() <= 2*uint64(conn.effectiveMSS) {
		timeout += goProbeDelayedAck
	}
	if timeout >= conn.retransmitTimeout {
		conn.probeDeadline = 0
		return
	}
	conn.probeDeadline = e.now() + int64(timeout)*int64(time.Microsecond)
}

func (e *goEngine) expireProbe(conn *GoConn, now int64) {
	conn.probeDeadline = 0
	if !conn.hasOutstanding() {
		e.rearmTimer(conn)
		return
	}
	e.drainDescriptors(conn)
	if conn.probeHighSeq != 0 {
		deadline := conn.retransmitDeadline
		if len(conn.scoreboard.entries) > 0 {
			elapsed := goStampMicros(conn.stamp(now) - conn.scoreboard.entries[0].sentAt)
			deadline = now + max(int64(conn.retransmitTimeout)-elapsed, 1)*int64(time.Microsecond)
		}
		if deadline == 0 {
			deadline = now + int64(conn.retransmitTimeout)*int64(time.Microsecond)
		}
		conn.retransmitDeadline = deadline
		e.rearmTimer(conn)
		return
	}
	conn.probeAttempts++
	e.summarizeFlight(conn)
	sent := conn.sentTail.Load()
	committed := min(sent, conn.transmittedTail.Load())
	unacked := conn.sendUnacked.Load()
	pending := conn.bufferedTail.Load() - sent
	windowEnd := uint64(max(conn.windowLeft2+int64(conn.peerWindow), 0))
	switch {
	case pending > 0 && committed == sent && windowEnd > sent && conn.writerActive.Load() == 0:
		length := min(pending, uint64(conn.effectiveMSS), windowEnd-sent)
		conn.probeRetransmitted = false
		conn.probeHighSeq = sent + length
		permit := conn.sendPermit.Load()
		if packets := conn.dataSegmentsOut.Load(); int32(conn.sendPacketPermit.Load()-packets) <= 0 {
			conn.sendPacketPermit.Store(packets + 1)
		}
		if permit < sent+length {
			conn.sendPermit.Store(sent + length)
		}
		conn.wakeTransmitter()
	case committed > unacked:
		entries := conn.scoreboard.entries
		for len(entries) > 0 && entries[len(entries)-1].endOffset > committed {
			entries = entries[:len(entries)-1]
		}
		start := unacked
		end := committed
		if len(entries) > 0 {
			last := len(entries) - 1
			end = entries[last].endOffset
			start = conn.scoreboard.startOf(last, unacked)
			if end < committed {
				start = end
				end = committed
			}
		}
		if end-start > uint64(conn.effectiveMSS) {
			start = end - uint64(conn.effectiveMSS)
		}
		if e.transmitRetransmit(conn, start, int(end-start), true) > 0 {
			conn.probeRetransmitted = true
			conn.probeHighSeq = committed
		}
	case conn.finSent && !conn.finAcked:
		segment := goSegment{offset: conn.finOffset, flags: header.TCPFlagFin | header.TCPFlagAck}
		if e.writeConnControl(conn, &segment) {
			conn.probeRetransmitted = true
			conn.probeHighSeq = conn.sendNext()
		}
	}
	conn.retransmitDeadline = now + int64(conn.retransmitTimeout)*int64(time.Microsecond)
	e.armProbe(conn)
	e.rearmTimer(conn)
}

func (e *goEngine) expireRetransmit(conn *GoConn, now int64) {
	if !conn.hasOutstanding() {
		conn.retransmitDeadline = 0
		conn.retransmitArmed.Store(false)
		e.rearmTimer(conn)
		return
	}
	if conn.persistNeeded() {
		e.updatePersist(conn)
		return
	}
	conn.probeDeadline = 0
	conn.probeAttempts = 0
	conn.reorderDeadline = 0
	if conn.hasOutstandingData() && conn.sendUnacked.Load() >= conn.transmittedTail.Load() {
		conn.retransmitDeadline = now + int64(conn.retransmitTimeout)*int64(time.Microsecond)
		e.rearmTimer(conn)
		return
	}
	if conn.retransmitAttempts+1 >= goRetransmitLimit && conn.persistDeadline == 0 {
		conn.retransmitDeadline = 0
		e.sendReset(conn)
		e.detachConn(conn, E.Cause(syscall.ETIMEDOUT, "go: retransmit limit"), goDeathImmediate)
		return
	}
	e.drainDescriptors(conn)
	e.enterLoss(conn)
	conn.retransmitAttempts++
	unacked := conn.sendUnacked.Load()
	if conn.hasOutstandingData() {
		length := int(min(conn.sentTail.Load()-unacked, uint64(conn.effectiveMSS)))
		e.transmitRetransmit(conn, unacked, length, false)
	} else {
		e.retransmitFrom(conn, unacked)
	}
	conn.retransmitTimeout = min(conn.retransmitTimeout*2, goRTOMaxMicros)
	conn.retransmitDeadline = now + int64(conn.retransmitTimeout)*int64(time.Microsecond)
	e.rearmTimer(conn)
	e.updateFrameLimit(conn)
	conn.publishPermit(unacked)
}
