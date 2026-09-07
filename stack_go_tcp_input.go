package tun

import (
	"encoding/binary"
	"hash/maphash"
	"net"
	"syscall"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// goRTOFloorMicros is above the delayed acknowledgement timer of every kernel that can sit on
// the other side of the device: Linux holds a lone segment's ACK for 40 ms, Darwin for 100 ms and
// Windows for 200 ms, and Windows itself floors its own RTO at 300 ms.
const (
	goRTOFloorMicros      = 300000
	goRTOInitialMicros    = 1000000
	goRTOMaxMicros        = 60000000
	goRTOGranularity      = int32(goWheelTick / int64(time.Microsecond))
	goSynAckRetransmit    = 500 * time.Millisecond
	goSynAckAttempts      = 5
	goPersistInitial      = 500 * time.Millisecond
	goPersistMax          = 60 * time.Second
	goFinLinger           = 5 * time.Second
	goAbortLinger         = time.Second
	goRetransmitLimit     = 8
	goProbeFloorMicros    = 50000
	goProbeDelayedAck     = 200000
	goProbeNoSampleMicros = 1000000
	goProbeAttempts       = 1
	goKeepaliveInterval   = 75 * time.Second
	goKeepaliveCount      = 9
	goFinWait2Timeout     = 60 * time.Second
	goAckRampBytes        = 256 << 10
	goDelayedAckInterval  = 25 * time.Millisecond
	goSweepInterval       = 500 * time.Millisecond
	goReclaimInterval     = 60 * time.Second
	goDyingLeakTimeout    = 30 * time.Second
	goMaxCongestionSize   = 4 << 20
	goResetBurstLimit     = 32
	goRecoveryBurst       = 64
	goDupThresh           = 3
	goInitialWindow       = 10
	goAckCoalesceBytes    = 256 << 10
)

const (
	goFRTOInactive uint8 = iota
	goFRTOAwaitFirstAck
	goFRTOAwaitSecondAck
)

func (p *forwardPacket) isPureTCPSyn() bool {
	return p.protocol == uint8(header.TCPProtocolNumber) &&
		p.tcpFlags&header.TCPFlagSyn != 0 && p.tcpFlags&header.TCPFlagAck == 0
}

func (e *goEngine) initialSequence(key flowKey, now int64) uint32 {
	return uint32(maphash.Comparable(e.sequenceSeed, key)) + uint32(now/goTimeUnit)
}

func (e *goEngine) demuxTCP(packet []byte, parsed *forwardPacket) {
	if len(parsed.transport) < header.TCPMinimumSize {
		return
	}
	if parsed.isPureTCPSyn() {
		e.handleTCPSyn(parsed)
		return
	}
	if parsed.tcpFlags&header.TCPFlagRst != 0 {
		return
	}
	e.answerNoFlow(parsed)
}

func (e *goEngine) answerNoFlow(parsed *forwardPacket) {
	if e.resetBurst >= goResetBurstLimit {
		return
	}
	e.resetBurst++
	e.controlIdent++
	reply, ok := goBuildNoFlowReset(e.controlScratch[:], parsed, uint16(e.controlIdent))
	if !ok {
		return
	}
	err := e.platformIO.writeFrame(e.singleFrame(reply), ForwardFrameMeta{})
	if err != nil {
		e.stack.logger.Trace(E.Cause(err, "go: write reset"))
	}
}

func goBuildNoFlowReset(scratch []byte, parsed *forwardPacket, ident uint16) ([]byte, bool) {
	tcpHdr := header.TCP(parsed.transport)
	dataOffset := int(tcpHdr.DataOffset())
	if dataOffset < header.TCPMinimumSize || dataOffset > len(tcpHdr) {
		return nil, false
	}
	ipHeaderLength := goNetworkHeaderLength(parsed.ipVersion)
	packet := scratch[:ipHeaderLength+header.TCPMinimumSize]
	replyTCP := header.TCP(packet[ipHeaderLength:])
	encodeResetTCP(replyTCP, tcpHdr)
	pseudoSum := goEncodeNetworkHeader(packet, parsed.ipVersion, parsed.destination.Addr(), parsed.source.Addr(), header.TCPMinimumSize, ident)
	replyTCP.SetChecksum(^replyTCP.CalculateChecksum(pseudoSum))
	return packet, true
}

func (e *goEngine) handleTCPSyn(parsed *forwardPacket) {
	key := parsed.flowKey()
	tcpHdr := header.TCP(parsed.transport)
	clientISN := tcpHdr.SequenceNumber()
	existing := e.flows[key]
	if existing != nil {
		if existing.clientISN == clientISN {
			e.handleDuplicateSyn(existing)
			return
		}
		if existing.connState.Load() < goConnStateDead && existing.state != goTCPSynReceived {
			e.markAck(existing, true)
			return
		}
		if existing.connState.Load() < goConnStateDead {
			e.detachConn(existing, E.New("go: connection replaced by new SYN"), goDeathImmediate)
		}
		e.removeFlow(existing)
	}
	if len(e.flows) >= e.flowCapacity && !e.evictFlow() {
		return
	}
	dataOffset := int(tcpHdr.DataOffset())
	if dataOffset < header.TCPMinimumSize || dataOffset > len(tcpHdr) {
		return
	}
	synOptions := header.ParseSynOptions(tcpHdr[header.TCPMinimumSize:dataOffset], false)
	now := e.now()
	conn := new(GoConn)
	source := M.SocksaddrFromNetIP(parsed.source)
	destination := M.SocksaddrFromNetIP(parsed.destination)
	conn.initialize(e, key, source, destination)
	conn.ipVersion = parsed.ipVersion
	conn.clientISN = clientISN
	conn.sendISN = e.initialSequence(key, now)
	conn.state = goTCPSynReceived
	conn.sackPermitted = synOptions.SACKPermitted
	if synOptions.WS >= 0 {
		conn.localWindowShift = goLocalWindowShift
		conn.peerWindowShift = uint8(synOptions.WS)
	}
	localMSS := e.localMSS(parsed.ipVersion)
	conn.peerMSS = synOptions.MSS
	conn.effectiveMSS = min(synOptions.MSS, localMSS)
	if synOptions.TS {
		conn.timestampsEnabled = true
		conn.tsRecent.Store(synOptions.TSVal)
		conn.effectiveMSS -= goTimestampOptionLength
	}
	conn.receiveCapacityMax = min(uint64(goReceiveCapacityMax), uint64(0xffff)<<conn.localWindowShift)
	conn.receiveCapacity = min(goReceiveCapacityBase, conn.receiveCapacityMax)
	conn.receiveNext = 1
	conn.lastAckSent = 1
	conn.lastActivity = now
	conn.publishedEdge = 1 + conn.receiveCapacity
	conn.congestionWindow = goInitialWindow * uint32(conn.effectiveMSS)
	conn.slowStartThreshold = goMaxCongestionSize
	conn.retransmitTimeout = goRTOInitialMicros
	conn.peerWindow = uint64(tcpHdr.WindowSize())
	conn.lastPeerWindow = tcpHdr.WindowSize()
	conn.consumedTail.Store(1)
	conn.receiveAvailable.Store(1)
	conn.receiveNextAck.Store(1)
	conn.receiveEdge.Store(conn.publishedEdge)
	conn.sentEdge.Store(conn.publishedEdge)
	conn.receiveCapacityPublished.Store(conn.receiveCapacity)
	conn.windowUpdateThreshold.Store(min(uint64(conn.effectiveMSS), conn.receiveCapacity/2))
	conn.receiveSpaceConsumed = 1
	conn.receiveSpaceStamp = now
	conn.sentTail.Store(1)
	conn.transmittedTail.Store(1)
	conn.bufferedTail.Store(1)
	conn.sendUnacked.Store(1)
	conn.sendReleased.Store(1)
	conn.sendPermit.Store(1 + min(uint64(conn.congestionWindow), conn.peerWindow))
	conn.buildSynAck(synOptions, localMSS)
	conn.keyed = true
	e.flows[key] = conn
	e.stack.directory.insert(key, conn)
	go e.stack.handler.NewConnectionEx(e.stack.ctx, conn, source, destination, nil)
}

func (e *goEngine) localMSS(ipVersion uint8) uint16 {
	if ipVersion == 4 {
		return uint16(e.stack.mtu - header.IPv4MinimumSize - header.TCPMinimumSize)
	}
	return uint16(e.stack.mtu - header.IPv6MinimumSize - header.TCPMinimumSize)
}

func (e *goEngine) evictFlow() bool {
	visited := 0
	for _, conn := range e.flows {
		if conn.connState.Load() >= goConnStateAborted {
			e.removeFlow(conn)
			return true
		}
		visited++
		if visited >= 64 {
			break
		}
	}
	for _, conn := range e.flows {
		if conn.state == goTCPSynReceived {
			e.detachConn(conn, net.ErrClosed, goDeathImmediate)
			e.removeFlow(conn)
			return true
		}
		visited++
		if visited >= 128 {
			break
		}
	}
	return false
}

func (e *goEngine) handleDuplicateSyn(conn *GoConn) {
	switch {
	case conn.connState.Load() == goConnStateEngaged:
		err := conn.writeSynAck()
		if err != nil {
			e.stack.logger.Trace(E.Cause(err, "go: resend SYN-ACK"))
		}
	case conn.connState.Load() >= goConnStateAborted && conn.deathClass == goDeathAbortLinger:
		e.sendReset(conn)
	}
}

func (e *goEngine) inputTCP(conn *GoConn, parsed *forwardPacket) {
	tcpHdr := header.TCP(parsed.transport)
	dataOffset := int(tcpHdr.DataOffset())
	if dataOffset < header.TCPMinimumSize || dataOffset > len(tcpHdr) {
		return
	}
	if conn.connState.Load() >= goConnStateAborted {
		e.inputTombstone(conn, parsed)
		return
	}
	conn.lastActivity = e.now()
	payload := tcpHdr[dataOffset:]
	flags := tcpHdr.Flags()
	segOffset := conn.receiveOffset(tcpHdr.SequenceNumber())
	segmentLength := int64(len(payload))
	if flags&header.TCPFlagSyn != 0 {
		segmentLength++
	}
	if flags&header.TCPFlagFin != 0 {
		segmentLength++
	}
	if flags&header.TCPFlagRst != 0 {
		e.handleReset(conn, segOffset)
		return
	}
	if len(payload) > 0 && flags&header.TCPFlagSyn == 0 {
		conn.recordDuplicate(segOffset, segOffset+int64(len(payload)))
	}
	var (
		timestampValue  uint32
		timestampEcho   uint32
		timestampRecent uint32
		hasTimestamp    bool
	)
	if conn.timestampsEnabled {
		timestampValue, timestampEcho, hasTimestamp = goParseTimestampOption(tcpHdr[header.TCPMinimumSize:dataOffset])
		timestampRecent = conn.tsRecent.Load()
	}
	if hasTimestamp && int32(timestampValue-timestampRecent) < 0 {
		e.markAck(conn, true)
		return
	}
	if !conn.segmentAcceptable(segOffset, segmentLength) {
		e.markAck(conn, true)
		return
	}
	if hasTimestamp && timestampValue != timestampRecent && segOffset <= int64(conn.lastAckSent) {
		conn.tsRecent.Store(timestampValue)
	}
	if flags&header.TCPFlagSyn != 0 {
		segOffset++
		if len(payload) == 0 && flags&header.TCPFlagFin == 0 {
			e.markAck(conn, true)
			return
		}
	}
	if flags&header.TCPFlagAck == 0 {
		return
	}
	if !e.processAck(conn, tcpHdr, segOffset, len(payload), flags, timestampEcho, hasTimestamp) {
		return
	}
	if conn.connState.Load() >= goConnStateAborted {
		return
	}
	if len(payload) > 0 || flags&header.TCPFlagFin != 0 {
		e.deliverSegment(conn, segOffset, payload, flags&header.TCPFlagFin != 0)
	}
	e.maybeSendFin(conn)
	if conn.splice != nil {
		e.spliceAfterInput(conn)
	}
}

func (e *goEngine) inputTombstone(conn *GoConn, parsed *forwardPacket) {
	if parsed.tcpFlags&header.TCPFlagRst != 0 {
		e.removeFlow(conn)
		return
	}
	switch conn.deathClass {
	case goDeathFinLinger:
		if parsed.tcpFlags&header.TCPFlagFin != 0 {
			e.sendAck(conn)
		}
	case goDeathAbortLinger:
		e.sendReset(conn)
	}
}

func (e *goEngine) handleReset(conn *GoConn, segOffset int64) {
	if segOffset == int64(conn.receiveNext) {
		e.detachConn(conn, errGoReset, goDeathImmediate)
		return
	}
	if conn.state != goTCPSynReceived && conn.segmentAcceptable(segOffset, 0) {
		e.markAck(conn, true)
	}
}

func (c *GoConn) receiveOffset(sequence uint32) int64 {
	current := uint32(uint64(c.clientISN) + c.receiveNext)
	return int64(c.receiveNext) + int64(int32(sequence-current))
}

func (c *GoConn) recordDuplicate(start int64, end int64) {
	if start < 0 || end <= start {
		return
	}
	switch {
	case uint64(end) <= c.receiveNext:
	case uint64(start) < c.receiveNext:
		end = int64(c.receiveNext)
	case c.oooRanges != nil && c.oooRanges.covers(uint64(start), uint64(end)):
	default:
		return
	}
	c.dsackStart = uint64(start)
	c.dsackEnd = uint64(end)
}

func (c *GoConn) sendOffset(acknowledgement uint32) int64 {
	unacked := c.sendUnacked.Load()
	current := uint32(uint64(c.sendISN) + unacked)
	return int64(unacked) + int64(int32(acknowledgement-current))
}

func (c *GoConn) segmentAcceptable(segOffset int64, segmentLength int64) bool {
	receiveNext := int64(c.receiveNext)
	edge := int64(c.publishedEdge)
	if segmentLength == 0 {
		if edge == receiveNext {
			return segOffset == receiveNext
		}
		return segOffset >= receiveNext && segOffset <= edge
	}
	if edge == receiveNext {
		return false
	}
	return segOffset < edge && segOffset+segmentLength > receiveNext
}

func (e *goEngine) processAck(conn *GoConn, tcpHdr header.TCP, segOffset int64, payloadLength int, flags header.TCPFlags, timestampEcho uint32, hasTimestamp bool) bool {
	conn.scoreboard.drain(&conn.descriptors, conn.sendUnacked.Load())
	ackOffset := conn.sendOffset(tcpHdr.AckNumber())
	limit := int64(conn.sentTail.Load())
	if conn.finSent {
		limit++
	}
	if ackOffset > limit {
		e.markAck(conn, true)
		return false
	}
	unacked := int64(conn.sendUnacked.Load())
	segmentAck := ackOffset
	if ackOffset < unacked {
		ackOffset = unacked
	}
	windowRaw := tcpHdr.WindowSize()
	handshakeAck := conn.state == goTCPSynReceived
	if handshakeAck {
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
	rawCount := 0
	if conn.sackPermitted {
		rawCount = goParseSackBlocks(tcpHdr, int(tcpHdr.DataOffset()), conn, &e.sackRaw)
	}
	windowChanged := false
	if segOffset > conn.windowLeft1 || (segOffset == conn.windowLeft1 && segmentAck >= conn.windowLeft2) {
		windowChanged = windowRaw != conn.lastPeerWindow
		conn.lastPeerWindow = windowRaw
		conn.peerWindow = uint64(windowRaw) << conn.peerWindowShift
		conn.windowLeft1 = segOffset
		conn.windowLeft2 = segmentAck
	}
	newSack := false
	if rawCount > 0 {
		raw := e.sackRaw[:rawCount]
		if goIsDuplicateSack(raw, ackOffset) {
			e.applyDuplicateSack(conn, raw[0])
			raw = raw[1:]
		}
		sackCount := goSelectSackBlocks(raw, &e.sackScratch)
		if sackCount > 0 {
			newSack = e.applySackBlocks(conn, e.sackScratch[:sackCount])
		}
	}
	if ackOffset > unacked {
		e.advanceUnacked(conn, uint64(ackOffset), timestampEcho, hasTimestamp)
	} else if segmentAck == unacked && !handshakeAck && conn.hasOutstandingData() && payloadLength == 0 && flags&(header.TCPFlagSyn|header.TCPFlagFin) == 0 && !windowChanged && !newSack {
		e.handleDuplicateAck(conn)
	}
	if conn.frtoState != goFRTOInactive {
		e.stepFRTO(conn, uint64(ackOffset), uint64(unacked), newSack)
	}
	if windowChanged && ackOffset == unacked {
		if conn.inRecovery {
			e.retransmitHoles(conn)
		} else if conn.frtoState == goFRTOInactive {
			e.continueRetransmit(conn, uint64(ackOffset))
		}
	}
	e.updatePersist(conn)
	conn.releaseIdleDescriptors()
	conn.publishPermit(uint64(ackOffset))
	return true
}

func (e *goEngine) establishConn(conn *GoConn) {
	conn.state = goTCPEstablished
	conn.handshakeDeadline = 0
	conn.everEstablished.Store(true)
	conn.connState.CompareAndSwap(goConnStateEngaged, goConnStateEstablished)
	close(conn.establishedSignal)
	e.wokeHandlerThisBurst = true
}

func (e *goEngine) advanceUnacked(conn *GoConn, ackOffset uint64, timestampEcho uint32, hasTimestamp bool) {
	sent := conn.sentTail.Load()
	previous := conn.sendUnacked.Load()
	newUnacked := min(ackOffset, sent)
	acked := newUnacked - previous
	e.sampleRoundTrip(conn, newUnacked, timestampEcho, hasTimestamp)
	conn.scoreboard.advance(newUnacked)
	conn.releaseTransmitted(newUnacked)
	conn.sendUnacked.Store(newUnacked)
	if conn.finSent && ackOffset > conn.finOffset {
		conn.finAcked = true
	}
	if conn.undoMarker != 0 && newUnacked >= conn.undoLimit && conn.frtoState == goFRTOInactive {
		conn.undoMarker = 0
	}
	if acked > 0 {
		conn.duplicateAckCount = 0
		if conn.inRecovery {
			if newUnacked >= conn.recoveryPoint {
				conn.inRecovery = false
				conn.congestionWindow = conn.slowStartThreshold
				conn.pipe = 0
			} else {
				conn.congestionWindow = max(conn.slowStartThreshold, uint32(conn.effectiveMSS))
				if conn.highestSacked <= newUnacked {
					conn.highestRetransmit = newUnacked
					e.retransmitFrom(conn, newUnacked)
				}
				e.retransmitHoles(conn)
			}
		} else {
			conn.growCongestionWindow(acked)
			if conn.frtoState == goFRTOInactive {
				e.continueRetransmit(conn, newUnacked)
			}
		}
		if conn.retransmitAttempts > 0 && conn.finSent && !conn.finAcked && !conn.hasOutstandingData() {
			e.retransmitFrom(conn, newUnacked)
		}
		conn.retransmitAttempts = 0
		conn.probeAttempts = 0
	}
	e.advanceFinState(conn)
	e.rearmRetransmit(conn)
}

func (c *GoConn) growCongestionWindow(acked uint64) {
	mss := uint32(c.effectiveMSS)
	counted := uint32(min(acked, uint64(2*mss)))
	if c.congestionWindow < c.slowStartThreshold {
		c.congestionWindow += counted
		c.ackedBytes = 0
	} else {
		c.ackedBytes += counted
		if c.ackedBytes >= c.congestionWindow {
			c.ackedBytes -= c.congestionWindow
			c.congestionWindow += mss
		}
	}
	c.congestionWindow = min(c.congestionWindow, goMaxCongestionSize)
}

func (e *goEngine) sampleRoundTrip(conn *GoConn, acked uint64, timestampEcho uint32, hasTimestamp bool) {
	var sample int32
	sampled := false
	walked := false
	slept := false
	for index := range conn.scoreboard.entries {
		descriptor := &conn.scoreboard.entries[index]
		if descriptor.endOffset > acked {
			break
		}
		walked = true
		if descriptor.flags&(goDescriptorNoSample|goDescriptorDropped) != 0 {
			slept = true
		} else if descriptor.flags&goDescriptorRetransmitted == 0 {
			sample = descriptor.sentAt
			sampled = true
		}
	}
	now := e.now()
	var measured int32
	switch {
	case sampled:
		units := int64(conn.stamp(now) - sample)
		if units < 0 {
			return
		}
		measured = int32(min(units*goTimeUnit/1000, goRTOMaxMicros))
	case hasTimestamp && walked && !slept && timestampEcho != 0:
		elapsed := goTimestampAt(now) - timestampEcho
		if int32(elapsed) < 0 {
			return
		}
		measured = int32(min(int64(elapsed)<<goTimestampShift/1000, goRTOMaxMicros))
		measured = max(measured, 1)
	default:
		return
	}
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

func (e *goEngine) handleDuplicateAck(conn *GoConn) {
	if conn.inRecovery {
		conn.pipe -= min(conn.pipe, uint64(conn.effectiveMSS))
		return
	}
	conn.duplicateAckCount++
	if conn.duplicateAckCount < 3 {
		return
	}
	e.enterRecovery(conn)
}

func (e *goEngine) enterRecovery(conn *GoConn) {
	if conn.inRecovery {
		return
	}
	unacked := conn.sendUnacked.Load()
	if conn.retransmitPoint > unacked {
		return
	}
	sent := conn.sentTail.Load()
	flight := sent - unacked
	if flight == 0 {
		return
	}
	conn.armCongestionUndo()
	conn.slowStartThreshold = max(uint32(flight/2), 2*uint32(conn.effectiveMSS))
	conn.congestionWindow = conn.slowStartThreshold
	conn.inRecovery = true
	conn.recoveryPoint = sent
	conn.highestRetransmit = unacked
	conn.pipe = flight
	conn.retransmitPoint = 0
	conn.duplicateAckCount = 0
	e.retransmitFrom(conn, unacked)
	e.retransmitHoles(conn)
}

func (c *GoConn) armCongestionUndo() {
	if c.undoMarker != 0 {
		return
	}
	c.undoMarker = c.sendUnacked.Load()
	c.undoLimit = c.sentTail.Load()
	c.undoCongestionWindow = c.congestionWindow
	c.undoSlowStartThreshold = c.slowStartThreshold
	c.undoRetransmits = 0
}

func (e *goEngine) applyDuplicateSack(conn *GoConn, block goRawSackBlock) {
	if conn.undoMarker == 0 || block.start < int64(conn.undoMarker) {
		return
	}
	conn.undoRetransmits--
	if conn.undoRetransmits > 0 {
		return
	}
	conn.undoCongestionReduction()
}

func (c *GoConn) undoCongestionReduction() {
	c.undoMarker = 0
	c.slowStartThreshold = c.undoSlowStartThreshold
	c.congestionWindow = max(c.congestionWindow, c.undoCongestionWindow)
	c.inRecovery = false
	c.duplicateAckCount = 0
	c.retransmitPoint = 0
	c.pipe = 0
}

func goParseTimestampOption(options []byte) (uint32, uint32, bool) {
	for index := 0; index < len(options); {
		switch options[index] {
		case header.TCPOptionEOL:
			return 0, 0, false
		case header.TCPOptionNOP:
			index++
		case header.TCPOptionTS:
			if index+header.TCPOptionTSLength > len(options) || options[index+1] != header.TCPOptionTSLength {
				return 0, 0, false
			}
			return binary.BigEndian.Uint32(options[index+2:]), binary.BigEndian.Uint32(options[index+6:]), true
		default:
			if index+2 > len(options) {
				return 0, 0, false
			}
			optionLength := int(options[index+1])
			if optionLength < 2 || index+optionLength > len(options) {
				return 0, 0, false
			}
			index += optionLength
		}
	}
	return 0, 0, false
}

type goRawSackBlock struct {
	start int64
	end   int64
}

func goParseSackBlocks(tcpHdr header.TCP, dataOffset int, conn *GoConn, blocks *[goMaxSackBlocks]goRawSackBlock) int {
	options := tcpHdr[header.TCPMinimumSize:dataOffset]
	count := 0
	for index := 0; index < len(options); {
		switch options[index] {
		case header.TCPOptionEOL:
			return count
		case header.TCPOptionNOP:
			index++
		case header.TCPOptionSACK:
			if index+2 > len(options) {
				return count
			}
			optionLength := int(options[index+1])
			if optionLength < 2 || index+optionLength > len(options) || (optionLength-2)%8 != 0 {
				return count
			}
			for offset := index + 2; offset+8 <= index+optionLength && count < goMaxSackBlocks; offset += 8 {
				start := conn.sendOffset(binary.BigEndian.Uint32(options[offset:]))
				end := conn.sendOffset(binary.BigEndian.Uint32(options[offset+4:]))
				if end <= start {
					continue
				}
				blocks[count] = goRawSackBlock{start: start, end: end}
				count++
			}
			index += optionLength
		default:
			if index+2 > len(options) {
				return count
			}
			optionLength := int(options[index+1])
			if optionLength < 2 || index+optionLength > len(options) {
				return count
			}
			index += optionLength
		}
	}
	return count
}

func goIsDuplicateSack(blocks []goRawSackBlock, ackOffset int64) bool {
	first := blocks[0]
	if first.end <= ackOffset {
		return true
	}
	for _, block := range blocks[1:] {
		if block.start <= first.start && first.end <= block.end {
			return true
		}
	}
	return false
}

func goSelectSackBlocks(raw []goRawSackBlock, blocks *[goMaxSackBlocks]goSackBlock) int {
	count := 0
	for _, block := range raw {
		if block.start < 0 {
			continue
		}
		blocks[count] = goSackBlock{start: uint64(block.start), end: uint64(block.end)}
		count++
	}
	return count
}

func (e *goEngine) applySackBlocks(conn *GoConn, blocks []goSackBlock) bool {
	unacked := conn.sendUnacked.Load()
	updated := false
	sackedBytes := uint64(0)
	sackedRuns := 0
	previousSacked := false
	start := unacked
	scoreboard := &conn.scoreboard
	for index := 0; index < len(scoreboard.entries); index++ {
		descriptor := &scoreboard.entries[index]
		end := descriptor.endOffset
		if descriptor.flags&goDescriptorSacked == 0 {
			for _, block := range blocks {
				if block.end <= start || block.start >= end {
					continue
				}
				if block.start > start {
					scoreboard.split(index, block.start)
					index++
					descriptor = &scoreboard.entries[index]
					start = block.start
				}
				if block.end < end {
					scoreboard.split(index, block.end)
					descriptor = &scoreboard.entries[index]
					end = block.end
				}
				descriptor.flags |= goDescriptorSacked
				updated = true
				break
			}
		}
		if descriptor.flags&goDescriptorSacked == 0 {
			previousSacked = false
		} else {
			sackedBytes += end - start
			if !previousSacked {
				sackedRuns++
			}
			previousSacked = true
		}
		start = end
	}
	for _, block := range blocks {
		if block.end > conn.highestSacked {
			conn.highestSacked = block.end
		}
	}
	if conn.inRecovery {
		if updated {
			e.retransmitHoles(conn)
		}
		return updated
	}
	if sackedBytes > uint64(goDupThresh-1)*uint64(conn.effectiveMSS) || sackedRuns >= goDupThresh {
		e.enterRecovery(conn)
	}
	return updated
}

func (c *GoConn) lostEdge(unacked uint64) uint64 {
	threshold := uint64(goDupThresh-1) * uint64(c.effectiveMSS)
	sackedBytes := uint64(0)
	sackedRuns := 0
	previousSacked := false
	entries := c.scoreboard.entries
	for index := len(entries); index > 0; {
		index--
		descriptor := &entries[index]
		if descriptor.flags&goDescriptorSacked == 0 {
			previousSacked = false
			if sackedBytes > threshold || sackedRuns >= goDupThresh {
				return descriptor.endOffset
			}
			continue
		}
		sackedBytes += descriptor.endOffset - c.scoreboard.startOf(index, unacked)
		if !previousSacked {
			sackedRuns++
		}
		previousSacked = true
	}
	return 0
}

func (c *GoConn) estimatePipe(unacked uint64, lostEdge uint64) uint64 {
	pipe := uint64(0)
	start := unacked
	for index := range c.scoreboard.entries {
		descriptor := &c.scoreboard.entries[index]
		end := descriptor.endOffset
		if descriptor.flags&goDescriptorSacked == 0 {
			if start >= lostEdge {
				pipe += end - start
			}
			if start < c.highestRetransmit {
				pipe += min(end, c.highestRetransmit) - start
			}
		}
		start = end
	}
	sent := c.sentTail.Load()
	if sent > start {
		pipe += sent - start
	}
	return pipe
}

func (e *goEngine) retransmitHoles(conn *GoConn) {
	unacked := conn.sendUnacked.Load()
	lostEdge := conn.lostEdge(unacked)
	conn.pipe = conn.estimatePipe(unacked, lostEdge)
	if lostEdge <= unacked {
		return
	}
	window := uint64(conn.congestionWindow)
	mss := uint64(conn.effectiveMSS)
	sent := 0
	start := unacked
	for index := 0; index < len(conn.scoreboard.entries); index++ {
		descriptor := &conn.scoreboard.entries[index]
		end := descriptor.endOffset
		if start >= lostEdge {
			return
		}
		if descriptor.flags&goDescriptorSacked != 0 || end <= conn.highestRetransmit {
			start = end
			continue
		}
		for offset := max(start, conn.highestRetransmit); offset < end; sent++ {
			if sent == goRecoveryBurst {
				conn.pipe = max(conn.pipe, window)
				return
			}
			if conn.pipe+mss > window {
				return
			}
			length := int(min(end-offset, mss))
			length = e.transmitRetransmit(conn, offset, length)
			if length == 0 {
				return
			}
			offset += uint64(length)
			conn.pipe += uint64(length)
		}
		start = end
	}
}

func (c *GoConn) publishPermit(ackOffset uint64) {
	unacked := c.sendUnacked.Load()
	limit := unacked + uint64(c.congestionWindow)
	switch {
	case c.frtoState == goFRTOAwaitSecondAck:
		limit = c.frtoSendLimit
	case c.inRecovery:
		limit = c.sentTail.Load()
		if uint64(c.congestionWindow) > c.pipe {
			limit += uint64(c.congestionWindow) - c.pipe
		}
	}
	permit := max(min(limit, ackOffset+c.peerWindow), unacked)
	c.sendPermit.Store(permit)
	c.wakeTransmitter()
	c.wakeWriter()
}

func (c *GoConn) releaseTransmitted(unacked uint64) {
	edge := min(unacked, c.transmittedTail.Load())
	if edge <= c.sendReleased.Load() {
		return
	}
	c.transmitStore.releaseBelow(edge)
	if edge == c.bufferedTail.Load() {
		c.transmitStore.releaseDrained(edge)
	}
	c.sendReleased.Store(edge)
}

func (c *GoConn) releaseIdleDescriptors() {
	if len(c.scoreboard.entries) != 0 || !c.transmitOwner.CompareAndSwap(0, 1) {
		return
	}
	if c.sendUnacked.Load() == c.sentTail.Load() && !c.blockedValid {
		c.descriptors.release()
	}
	c.transmitOwner.Store(0)
	// A writer can publish data while we own the transmitter. Resume it if its
	// attempt to transmit raced with this cleanup.
	if c.nextTransmitLength() != 0 {
		c.wakeTransmitter()
	}
}

func (c *GoConn) releaseDrainedSlabs() {
	consumed := c.consumedTail.Load()
	if consumed == c.receiveAvailable.Load() && (c.oooRanges == nil || c.oooRanges.count == 0) {
		c.receiveChain.releaseDrained(consumed)
	}
	buffered := c.bufferedTail.Load()
	if min(c.sendUnacked.Load(), c.transmittedTail.Load()) == buffered {
		c.transmitStore.releaseDrained(buffered)
	}
}

func (c *GoConn) wakeTransmitter() {
	if c.splice != nil {
		c.engine.spliceResume(c)
		return
	}
	if c.nextTransmitLength() == 0 {
		return
	}
	if goEngineInlineTransmit && c.transmitOnEngine() {
		return
	}
	c.wakeTransmitterGoroutine()
	c.engine.wokeHandlerThisBurst = true
}

func (c *GoConn) wakeWriter() {
	if !c.writerParked.Load() {
		return
	}
	if !c.writeReady(int(max(c.writerNeeds.Load(), 1))) {
		return
	}
	c.signalWriter()
}

func (c *GoConn) signalWriter() {
	if c.writeSignal.notify() {
		c.engine.wokeHandlerThisBurst = true
	}
}

func (c *GoConn) signalReader() {
	if c.readSignal.notify() {
		c.engine.wokeHandlerThisBurst = true
	}
}

func (e *goEngine) deliverSegment(conn *GoConn, segOffset int64, payload []byte, fin bool) {
	conn.receiveChain.releaseBelow(conn.consumedTail.Load())
	receiveNext := int64(conn.receiveNext)
	edge := int64(conn.publishedEdge)
	start := max(segOffset, receiveNext)
	end := min(segOffset+int64(len(payload)), edge)
	finOffset := segOffset + int64(len(payload))
	if end <= start {
		if fin && finOffset == receiveNext {
			e.acceptFin(conn)
			return
		}
		e.markAck(conn, true)
		return
	}
	data := payload[start-segOffset : end-segOffset]
	if start == receiveNext {
		e.deliverInOrder(conn, data)
		if fin && finOffset == int64(conn.receiveNext) {
			e.acceptFin(conn)
			return
		}
		e.mergeOutOfOrder(conn)
		e.measureReceiveRoundTrip(conn)
		conn.ackPending += uint64(len(data))
		conn.ackCovered += uint64(len(data))
		e.markAck(conn, conn.ackPending >= conn.ackThreshold())
		return
	}
	if conn.discardReceive {
		e.markAck(conn, true)
		return
	}
	if conn.oooRanges == nil {
		conn.oooRanges = new(goRangeSet)
	}
	if conn.oooRanges.bytes()+uint64(len(data)) > conn.receiveCapacity {
		e.markAck(conn, true)
		return
	}
	conn.receiveChain.reserve(uint64(start), len(data))
	conn.receiveChain.writeAt(uint64(start), data)
	if !conn.oooRanges.insert(uint64(start), uint64(end), fin && finOffset == end) {
		e.markAck(conn, true)
		return
	}
	e.markAck(conn, true)
}

func (e *goEngine) deliverInOrder(conn *GoConn, data []byte) {
	if conn.discardReceive {
		conn.receiveNext += uint64(len(data))
		conn.receiveNextAck.Store(conn.receiveNext)
		conn.publishReceiveWindow()
		return
	}
	if conn.splice != nil {
		e.spliceDeliver(conn, data)
		return
	}
	conn.receiveChain.reserve(conn.receiveNext, len(data))
	direct := 0
	taken := false
	if conn.receiveAvailable.Load() == conn.consumedTail.Load() {
		target := conn.postedTarget.Swap(nil)
		if target != nil {
			direct = copy(target.target, data)
			target.filled = direct
			taken = true
		}
	}
	if direct < len(data) {
		conn.receiveChain.writeAt(conn.receiveNext+uint64(direct), data[direct:])
	}
	conn.receiveNext += uint64(len(data))
	conn.receiveNextAck.Store(conn.receiveNext)
	conn.receiveAvailable.Store(conn.receiveNext)
	conn.publishReceiveWindow()
	if taken {
		conn.targetDone.Store(true)
	}
	if conn.readerParked.Load() || taken {
		conn.signalReader()
	}
}

func (e *goEngine) mergeOutOfOrder(conn *GoConn) {
	if conn.oooRanges == nil {
		return
	}
	for {
		front, ok := conn.oooRanges.first()
		if !ok || front.start > conn.receiveNext {
			return
		}
		if front.end > conn.receiveNext {
			conn.receiveNext = front.end
			conn.receiveNextAck.Store(conn.receiveNext)
			if !conn.discardReceive {
				conn.receiveAvailable.Store(conn.receiveNext)
				if conn.readerParked.Load() {
					conn.signalReader()
				}
			}
			conn.publishReceiveWindow()
		}
		fin := front.fin
		conn.oooRanges.removeBelow(conn.receiveNext)
		e.markAck(conn, true)
		if fin {
			e.acceptFin(conn)
			return
		}
	}
}

func (e *goEngine) acceptFin(conn *GoConn) {
	if conn.finReceived {
		e.markAck(conn, true)
		return
	}
	conn.finReceived = true
	conn.receiveNext++
	conn.receiveNextAck.Store(conn.receiveNext)
	conn.receiveShutdown.Store(true)
	conn.publishReceiveWindow()
	if conn.readerParked.Load() {
		conn.signalReader()
	}
	switch conn.state {
	case goTCPEstablished:
		conn.state = goTCPCloseWait
	case goTCPFinWait1:
		if conn.finAcked {
			conn.state = goTCPFinWait2
			conn.finWait2Since = e.now()
			e.markAck(conn, true)
			e.finishClose(conn)
			return
		}
		conn.state = goTCPClosing
	case goTCPFinWait2:
		e.markAck(conn, true)
		e.finishClose(conn)
		return
	}
	e.markAck(conn, true)
}

func (e *goEngine) advanceFinState(conn *GoConn) {
	if !conn.finSent || !conn.finAcked {
		return
	}
	switch conn.state {
	case goTCPFinWait1:
		if conn.finReceived {
			e.finishClose(conn)
			return
		}
		conn.state = goTCPFinWait2
		conn.finWait2Since = e.now()
	case goTCPClosing, goTCPLastAck:
		e.finishClose(conn)
	}
}

func (e *goEngine) finishClose(conn *GoConn) {
	conn.state = goTCPClosed
	e.detachConn(conn, nil, goDeathFinLinger)
}

func (c *GoConn) publishReceiveWindow() {
	base := c.consumedTail.Load()
	if c.discardReceive {
		base = c.receiveNext
	}
	edge := base + c.receiveCapacity
	if edge <= c.publishedEdge {
		return
	}
	if base < c.receiveNext && edge-c.sentEdge.Load() < c.windowUpdateThreshold.Load() {
		return
	}
	c.publishedEdge = edge
	c.receiveEdge.Store(edge)
}

func (e *goEngine) measureReceiveRoundTrip(conn *GoConn) {
	now := e.now()
	if conn.receiveRoundTripMark == 0 {
		conn.receiveRoundTripMark = conn.receiveNext + conn.receiveCapacity
		conn.receiveRoundTripStamp = now
		return
	}
	if conn.receiveNext < conn.receiveRoundTripMark {
		return
	}
	sample := max(int32(min((now-conn.receiveRoundTripStamp)/int64(time.Microsecond), goRTOMaxMicros)), 1)
	if conn.receiveRoundTrip == 0 || sample < conn.receiveRoundTrip {
		conn.receiveRoundTrip = sample
	}
	conn.receiveRoundTripMark = conn.receiveNext + conn.receiveCapacity
	conn.receiveRoundTripStamp = now
}

func (e *goEngine) moderateReceiveCapacity(conn *GoConn) {
	if conn.receiveRoundTrip == 0 {
		return
	}
	now := e.now()
	if now-conn.receiveSpaceStamp < int64(conn.receiveRoundTrip)*int64(time.Microsecond) {
		return
	}
	consumed := conn.consumedTail.Load()
	copied := consumed - conn.receiveSpaceConsumed
	previous := conn.receiveSpaceCopied
	conn.receiveSpaceConsumed = consumed
	conn.receiveSpaceCopied = copied
	conn.receiveSpaceStamp = now
	capacity := min(max(2*max(copied, previous), conn.receiveCapacity), e.receiveCapacityLimit(conn))
	if capacity == conn.receiveCapacity {
		return
	}
	conn.receiveCapacity = capacity
	conn.receiveCapacityPublished.Store(capacity)
	conn.windowUpdateThreshold.Store(min(uint64(conn.effectiveMSS), capacity/2))
}

func (e *goEngine) receiveCapacityLimit(conn *GoConn) uint64 {
	share := e.slabPool.shareBytes()
	if share == 0 {
		return conn.receiveCapacityMax
	}
	transmitHeld := conn.transmitStore.chain.heldBytes()
	if share <= transmitHeld {
		return min(goReceiveCapacityBase, conn.receiveCapacityMax)
	}
	return min(max(share-transmitHeld, goReceiveCapacityBase), conn.receiveCapacityMax)
}

func (e *goEngine) markAck(conn *GoConn, forced bool) {
	if forced {
		conn.ackForced = true
	}
	if conn.ackDirty {
		return
	}
	conn.ackDirty = true
	conn.ackNext = e.ackList
	e.ackList = conn
}

func (e *goEngine) expireDelayedAckTick(now int64) {
	e.drainAckList(now, false)
}

func (e *goEngine) drainAckList(now int64, allowDefer bool) {
	var kept *GoConn
	for conn := e.ackList; conn != nil; {
		next := conn.ackNext
		conn.ackNext = nil
		if allowDefer && !conn.ackForced && conn.ackPending < conn.ackThreshold() && conn.ackCovered >= goAckRampBytes {
			conn.ackNext = kept
			kept = conn
			conn = next
			continue
		}
		conn.ackDirty = false
		if !e.sendAck(conn) {
			conn.ackDirty = true
			conn.ackNext = kept
			kept = conn
		}
		conn = next
	}
	e.ackList = kept
	if kept != nil && e.delayedAckTickNode.slot == nil {
		e.wheel.schedule(&e.delayedAckTickNode, now+int64(goDelayedAckInterval))
	}
}

func (e *goEngine) sendAck(conn *GoConn) bool {
	e.moderateReceiveCapacity(conn)
	conn.receiveChain.releaseBelow(conn.consumedTail.Load())
	conn.publishReceiveWindow()

	segment := goSegment{offset: conn.sendNext(), flags: header.TCPFlagAck}
	if conn.sackPermitted && (conn.dsackEnd != 0 || conn.oooRanges != nil && conn.oooRanges.count > 0) {
		count := 0
		if conn.dsackEnd != 0 {
			e.sackScratch[0] = goSackBlock{start: conn.dsackStart, end: conn.dsackEnd}
			count = 1
		}
		if conn.oooRanges != nil {
			count = conn.oooRanges.blocks(&e.sackScratch, count)
		}
		segment.sackBlocks = e.sackScratch[:count]
	}
	if !e.writeConnControl(conn, &segment) {
		return false
	}
	conn.dsackStart = 0
	conn.dsackEnd = 0
	conn.ackPending = 0
	conn.ackForced = false
	conn.lastAckSent = conn.receiveNext
	return true
}

func (e *goEngine) sendReset(conn *GoConn) bool {
	segment := goSegment{offset: conn.sendNext(), flags: header.TCPFlagRst | header.TCPFlagAck}
	return e.writeConnControl(conn, &segment)
}

func (e *goEngine) writeConnControl(conn *GoConn, segment *goSegment) bool {
	frame, _ := conn.buildFrame(e.controlScratch[:], e.controlSegments[:0], segment, &conn.transmitStore, false)
	e.controlSegments = frame
	err := e.platformIO.writeFrame(frame, ForwardFrameMeta{})
	if err != nil {
		e.stack.logger.Trace(E.Cause(err, "go: write control frame"))
		return false
	}
	return true
}

func (e *goEngine) maybeSendFin(conn *GoConn) {
	if !conn.finPending || conn.finSent || conn.state == goTCPSynReceived {
		return
	}
	if conn.connState.Load() >= goConnStateAborted {
		return
	}
	if conn.writerActive.Load() != 0 {
		return
	}
	buffered := conn.bufferedTail.Load()
	if conn.sentTail.Load() != buffered || conn.transmittedTail.Load() != buffered {
		return
	}
	conn.finOffset = buffered
	conn.finSent = true
	segment := goSegment{offset: conn.finOffset, flags: header.TCPFlagFin | header.TCPFlagAck}
	e.writeConnControl(conn, &segment)
	switch conn.state {
	case goTCPCloseWait:
		conn.state = goTCPLastAck
	default:
		conn.state = goTCPFinWait1
	}
	e.rearmRetransmit(conn)
}

func (e *goEngine) handleCloseRequest(conn *GoConn) {
	if conn.connState.Load() >= goConnStateDead {
		if conn.userClosed.Load() || conn.closeMode.Load() == goCloseModeAbort {
			conn.receiveDrainable.Store(false)
			e.spliceDetach(conn, conn.loadError())
		}
		return
	}
	if conn.connState.Load() == goConnStateAborted {
		e.detachConn(conn, nil, goDeathAbortLinger)
		return
	}
	if conn.closeMode.Load() == goCloseModeAbort || conn.splice != nil || conn.splicePending.Load() != nil {
		e.sendReset(conn)
		e.detachConn(conn, net.ErrClosed, goDeathAbortLinger)
		return
	}
	conn.finPending = true
	e.maybeSendFin(conn)
}

func (e *goEngine) handleReadShut(conn *GoConn) {
	if conn.connState.Load() >= goConnStateAborted {
		return
	}
	conn.discardReceive = true
	conn.oooRanges = nil
	if conn.readAccess.TryLock() {
		conn.consumedTail.Store(conn.receiveAvailable.Load())
		conn.readAccess.Unlock()
		conn.releaseDrainedSlabs()
	}
	conn.publishReceiveWindow()
	if conn.readerParked.Load() {
		conn.signalReader()
	}
}

func (e *goEngine) handleWindowUpdate(conn *GoConn) {
	if conn.connState.Load() >= goConnStateAborted {
		return
	}
	conn.receiveChain.releaseBelow(conn.consumedTail.Load())
	conn.publishReceiveWindow()
	if conn.publishedEdge > conn.sentEdge.Load() || conn.ackPending > 0 {
		e.markAck(conn, true)
	}
}

func (e *goEngine) handleRetransmitArm(conn *GoConn) {
	if conn.connState.Load() >= goConnStateAborted {
		return
	}
	e.rearmRetransmit(conn)
}

func (e *goEngine) handleDroppedFrames(conn *GoConn) {
	if conn.connState.Load() >= goConnStateAborted {
		return
	}
	conn.scoreboard.drain(&conn.descriptors, conn.sendUnacked.Load())
	unacked := conn.sendUnacked.Load()
	start := unacked
	for index := range conn.scoreboard.entries {
		descriptor := &conn.scoreboard.entries[index]
		end := descriptor.endOffset
		if descriptor.flags&goDescriptorDropped != 0 && descriptor.flags&goDescriptorSacked == 0 {
			if e.transmitRetransmit(conn, start, int(end-start)) == 0 {
				break
			}
		}
		start = end
	}
	e.rearmRetransmit(conn)
}

func (e *goEngine) handleTransmitBlocked(conn *GoConn) {
	if conn.connState.Load() >= goConnStateAborted {
		conn.transmitSignal.notify()
		return
	}
	if !conn.onBlockedList {
		conn.onBlockedList = true
		conn.blockedNext = e.blockedList
		e.blockedList = conn
	}
	armed, err := e.platformIO.armTransmitWritable()
	if err != nil {
		e.stack.logger.Trace(E.Cause(err, "go: arm transmit writable"))
	}
	if !armed {
		e.releaseBlockedWriters()
	}
}

func (e *goEngine) releaseBlockedWriters() {
	blocked := e.blockedList
	e.blockedList = nil
	for conn := blocked; conn != nil; {
		next := conn.blockedNext
		conn.blockedNext = nil
		conn.onBlockedList = false
		if conn.splice != nil {
			e.spliceRetryBlocked(conn)
		} else {
			conn.transmitSignal.notify()
			e.wokeHandlerThisBurst = true
		}
		conn = next
	}
}

func (c *GoConn) hasOutstandingData() bool {
	return c.sendUnacked.Load() < c.sentTail.Load()
}

func (c *GoConn) hasOutstanding() bool {
	if c.state == goTCPSynReceived {
		return false
	}
	return c.sendUnacked.Load() < c.sentTail.Load() || (c.finSent && !c.finAcked)
}

func (e *goEngine) rearmRetransmit(conn *GoConn) {
	if !conn.hasOutstanding() {
		conn.retransmitDeadline = 0
		conn.retransmitArmed.Store(false)
		if !conn.hasOutstanding() {
			e.rearmTimer(conn)
			return
		}
		conn.retransmitArmed.Store(true)
	}
	if conn.persistNeeded() {
		e.updatePersist(conn)
		return
	}
	conn.retransmitDeadline = e.now() + int64(conn.retransmitTimeout)*int64(time.Microsecond)
	e.armProbe(conn)
	e.rearmTimer(conn)
}

func (e *goEngine) armProbe(conn *GoConn) {
	if conn.probeAttempts >= goProbeAttempts || !conn.hasOutstanding() || conn.frtoState != goFRTOInactive || conn.inRecovery {
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

func (c *GoConn) persistNeeded() bool {
	return c.peerWindow == 0 && (c.bufferedTail.Load() > c.sendUnacked.Load() || (c.finSent && !c.finAcked))
}

func (e *goEngine) updatePersist(conn *GoConn) {
	if conn.persistNeeded() {
		conn.retransmitDeadline = 0
		conn.probeDeadline = 0
		if conn.persistDeadline == 0 {
			conn.persistAttempts = 0
			conn.persistDeadline = e.now() + int64(goPersistInitial)
		}
		e.rearmTimer(conn)
		return
	}
	if conn.persistDeadline != 0 {
		conn.persistDeadline = 0
		conn.persistAttempts = 0
		if conn.hasOutstanding() {
			e.retransmitFrom(conn, conn.sendUnacked.Load())
			e.rearmRetransmit(conn)
		} else {
			e.rearmTimer(conn)
		}
	}
}

func (e *goEngine) rearmTimer(conn *GoConn) {
	next := int64(0)
	for _, deadline := range [5]int64{conn.retransmitDeadline, conn.probeDeadline, conn.persistDeadline, conn.lingerDeadline, conn.handshakeDeadline} {
		if deadline == 0 {
			continue
		}
		if next == 0 || deadline < next {
			next = deadline
		}
	}
	if next == 0 {
		e.wheel.cancel(&conn.timerNode)
		return
	}
	e.wheel.schedule(&conn.timerNode, next)
}

func (c *GoConn) expireTimer(now int64) {
	c.engine.fireConnTimer(c, now)
}

func (e *goEngine) fireConnTimer(conn *GoConn, now int64) {
	if conn.lingerDeadline != 0 && conn.lingerDeadline <= now {
		conn.lingerDeadline = 0
		e.removeFlow(conn)
		return
	}
	if conn.handshakeDeadline != 0 && conn.handshakeDeadline <= now {
		e.expireHandshake(conn, now)
		return
	}
	if conn.persistDeadline != 0 && conn.persistDeadline <= now {
		e.expirePersist(conn, now)
		return
	}
	if conn.probeDeadline != 0 && conn.probeDeadline <= now {
		e.expireProbe(conn, now)
		return
	}
	if conn.retransmitDeadline != 0 && conn.retransmitDeadline <= now {
		e.expireRetransmit(conn, now)
		return
	}
	e.rearmTimer(conn)
}

func (e *goEngine) expireHandshake(conn *GoConn, now int64) {
	conn.handshakeAttempts++
	if conn.handshakeAttempts >= goSynAckAttempts {
		conn.handshakeDeadline = 0
		e.detachConn(conn, E.New("go: handshake timeout"), goDeathAbortLinger)
		return
	}
	err := conn.writeSynAck()
	if err != nil {
		e.stack.logger.Trace(E.Cause(err, "go: resend SYN-ACK"))
	}
	conn.handshakeDeadline = now + int64(goSynAckRetransmit)<<conn.handshakeAttempts
	e.rearmTimer(conn)
}

func (e *goEngine) expirePersist(conn *GoConn, now int64) {
	if !conn.persistNeeded() {
		conn.persistDeadline = 0
		conn.persistAttempts = 0
		e.rearmTimer(conn)
		return
	}
	segment := goSegment{offset: conn.sendUnacked.Load() - 1, flags: header.TCPFlagAck}
	e.writeConnControl(conn, &segment)
	conn.persistAttempts = min(conn.persistAttempts+1, 8)
	backoff := min(int64(goPersistInitial)<<conn.persistAttempts, int64(goPersistMax))
	conn.persistDeadline = now + backoff
	e.rearmTimer(conn)
}

func (e *goEngine) expireProbe(conn *GoConn, now int64) {
	conn.probeDeadline = 0
	sent := conn.sentTail.Load()
	unacked := conn.sendUnacked.Load()
	if !conn.hasOutstanding() {
		e.rearmTimer(conn)
		return
	}
	conn.probeAttempts++
	conn.scoreboard.drain(&conn.descriptors, conn.sendUnacked.Load())
	switch {
	case sent > unacked:
		offset := unacked
		if sent-unacked > uint64(conn.effectiveMSS) {
			offset = sent - uint64(conn.effectiveMSS)
		}
		e.transmitRetransmit(conn, offset, int(sent-offset))
	case conn.finSent && !conn.finAcked:
		segment := goSegment{offset: conn.finOffset, flags: header.TCPFlagFin | header.TCPFlagAck}
		e.writeConnControl(conn, &segment)
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
	conn.retransmitAttempts++
	if conn.retransmitAttempts >= goRetransmitLimit && conn.persistDeadline == 0 {
		conn.retransmitDeadline = 0
		e.sendReset(conn)
		e.detachConn(conn, E.Cause(syscall.ETIMEDOUT, "go: retransmit limit"), goDeathImmediate)
		return
	}
	conn.scoreboard.drain(&conn.descriptors, conn.sendUnacked.Load())
	unacked := conn.sendUnacked.Load()
	sent := conn.sentTail.Load()
	recovering := conn.inRecovery || (conn.retransmitPoint > unacked && conn.frtoState != goFRTOAwaitFirstAck)
	flight := sent - unacked
	if flight > 0 {
		conn.armCongestionUndo()
		conn.slowStartThreshold = max(uint32(flight/2), 2*uint32(conn.effectiveMSS))
	}
	conn.congestionWindow = uint32(conn.effectiveMSS)
	conn.inRecovery = false
	conn.duplicateAckCount = 0
	conn.highestRetransmit = unacked
	conn.pipe = 0
	conn.retransmitPoint = sent
	conn.retransmitHighWater = unacked
	conn.highestSacked = unacked
	for index := range conn.scoreboard.entries {
		conn.scoreboard.entries[index].flags &^= goDescriptorSacked
	}
	if conn.sackPermitted && !recovering && flight > 0 {
		conn.frtoState = goFRTOAwaitFirstAck
	} else {
		conn.frtoState = goFRTOInactive
	}
	e.continueRetransmit(conn, unacked)
	if !conn.hasOutstandingData() {
		e.retransmitFrom(conn, unacked)
	}
	conn.retransmitTimeout = min(conn.retransmitTimeout*2, goRTOMaxMicros)
	conn.retransmitDeadline = now + int64(conn.retransmitTimeout)*int64(time.Microsecond)
	e.rearmTimer(conn)
	conn.publishPermit(unacked)
}

func (e *goEngine) stepFRTO(conn *GoConn, ackOffset uint64, previousUnacked uint64, newSack bool) {
	advanced := ackOffset > previousUnacked
	switch conn.frtoState {
	case goFRTOAwaitFirstAck:
		if !advanced {
			return
		}
		conn.frtoRecoveryPoint = conn.sentTail.Load()
		conn.frtoSendLimit = conn.frtoRecoveryPoint + 2*uint64(conn.effectiveMSS)
		windowEnd := uint64(max(conn.windowLeft2+int64(conn.peerWindow), 0))
		if ackOffset < conn.retransmitHighWater || ackOffset >= conn.frtoRecoveryPoint || !conn.hasDataWaiting() || windowEnd < conn.frtoSendLimit {
			e.abandonFRTO(conn, 2)
			return
		}
		conn.frtoState = goFRTOAwaitSecondAck
	case goFRTOAwaitSecondAck:
		if !advanced && !newSack {
			return
		}
		if ackOffset > conn.frtoRecoveryPoint || conn.highestSacked > conn.frtoRecoveryPoint {
			e.abandonFRTO(conn, 3)
			return
		}
		conn.frtoState = goFRTOInactive
		conn.retransmitHighWater = 0
		conn.undoCongestionReduction()
	}
}

func (e *goEngine) abandonFRTO(conn *GoConn, segments uint32) {
	conn.frtoState = goFRTOInactive
	conn.congestionWindow = min(conn.congestionWindow, segments*uint32(conn.effectiveMSS))
	e.continueRetransmit(conn, conn.sendUnacked.Load())
}

func (e *goEngine) continueRetransmit(conn *GoConn, unacked uint64) {
	if conn.retransmitPoint <= unacked {
		conn.retransmitPoint = 0
		return
	}
	offset := max(unacked, conn.retransmitHighWater)
	limit := min(conn.retransmitPoint, unacked+uint64(conn.congestionWindow))
	entries := conn.scoreboard.entries
	index := 0
	for sent := 0; offset < limit && sent < goRecoveryBurst; {
		for index < len(entries) && entries[index].endOffset <= offset {
			index++
		}
		end := limit
		if index < len(entries) {
			descriptor := &entries[index]
			if descriptor.flags&goDescriptorSacked != 0 {
				offset = min(descriptor.endOffset, limit)
				continue
			}
			end = min(end, descriptor.endOffset)
		}
		length := int(min(end-offset, uint64(conn.effectiveMSS)))
		length = e.transmitRetransmit(conn, offset, length)
		if length == 0 {
			break
		}
		offset += uint64(length)
		sent++
	}
	conn.retransmitHighWater = offset
}

func (e *goEngine) retransmitFrom(conn *GoConn, offset uint64) {
	sent := conn.sentTail.Load()
	offset = max(offset, 1)
	if offset < sent {
		e.transmitRetransmit(conn, offset, int(min(sent-offset, uint64(conn.effectiveMSS))))
		return
	}
	if conn.finSent && !conn.finAcked {
		segment := goSegment{offset: conn.finOffset, flags: header.TCPFlagFin | header.TCPFlagAck}
		e.writeConnControl(conn, &segment)
	}
}

func (e *goEngine) transmitRetransmit(conn *GoConn, offset uint64, length int) int {
	windowEnd := uint64(max(conn.windowLeft2+int64(conn.peerWindow), 0))
	limit := min(conn.sentTail.Load(), windowEnd)
	if conn.peerWindow == 0 || offset >= limit {
		return 0
	}
	length = int(min(uint64(length), uint64(conn.effectiveMSS), limit-offset))
	segment := goSegment{offset: offset, length: length, flags: header.TCPFlagAck | header.TCPFlagPsh}
	if !e.writeConnControl(conn, &segment) {
		return 0
	}
	end := offset + uint64(length)
	if end > conn.highestRetransmit {
		conn.highestRetransmit = end
	}
	if conn.undoMarker != 0 && offset >= conn.undoMarker {
		conn.undoRetransmits++
	}
	e.markRetransmitted(conn, offset, end)
	return length
}

func (e *goEngine) markRetransmitted(conn *GoConn, start uint64, end uint64) {
	previous := conn.sendUnacked.Load()
	for index := range conn.scoreboard.entries {
		descriptor := &conn.scoreboard.entries[index]
		if previous < end && descriptor.endOffset > start {
			descriptor.flags |= goDescriptorRetransmitted
			descriptor.flags &^= goDescriptorDropped
		}
		previous = descriptor.endOffset
	}
}

func (e *goEngine) detachConn(conn *GoConn, err error, class uint8) {
	if conn.connState.Load() >= goConnStateDead {
		return
	}
	if err != nil {
		conn.storeError(err)
	}
	if class == goDeathFinLinger && conn.receiveAvailable.Load() > conn.consumedTail.Load() {
		conn.receiveDrainable.Store(true)
	}
	conn.connState.Store(goConnStateDead)
	conn.deathClass = class
	conn.state = goTCPClosed
	if class == goDeathFinLinger && conn.splice != nil && !conn.splice.uploadClosed {
		e.spliceMarkDirty(conn)
	} else {
		e.spliceDetach(conn, conn.loadError())
	}
	if !conn.everEstablished.Load() {
		close(conn.establishedSignal)
	}
	close(conn.closeSignal)
	conn.retransmitDeadline = 0
	conn.probeDeadline = 0
	conn.persistDeadline = 0
	conn.handshakeDeadline = 0
	conn.finPending = false
	switch class {
	case goDeathFinLinger:
		conn.lingerDeadline = e.now() + int64(goFinLinger)
	case goDeathAbortLinger:
		conn.lingerDeadline = e.now() + int64(goAbortLinger)
	default:
		conn.lingerDeadline = 0
	}
	e.rearmTimer(conn)
	if class == goDeathImmediate {
		e.removeFlowKey(conn)
	}
	if !conn.onDyingList {
		conn.onDyingList = true
		conn.dyingSince = e.now()
		conn.dyingNext = e.dyingList
		e.dyingList = conn
	}
	if conn.onBlockedList {
		conn.transmitSignal.notify()
	}
	conn.wakeUser()
	e.wokeHandlerThisBurst = true
}

func (e *goEngine) removeFlow(conn *GoConn) {
	if conn.connState.Load() < goConnStateDead {
		e.detachConn(conn, net.ErrClosed, goDeathImmediate)
		return
	}
	conn.lingerDeadline = 0
	e.wheel.cancel(&conn.timerNode)
	e.removeFlowKey(conn)
}

func (e *goEngine) removeFlowKey(conn *GoConn) {
	if !conn.keyed {
		return
	}
	conn.keyed = false
	delete(e.flows, conn.key)
	e.stack.directory.remove(conn.key, conn)
	reason := FlowCloseReset
	if conn.finReceived && conn.finSent {
		reason = FlowCloseFinished
	}
	e.dispatchStage.teardownFlow(conn.key, reason)
}

func (e *goEngine) reapDying() {
	var kept *GoConn
	now := e.now()
	for conn := e.dyingList; conn != nil; {
		next := conn.dyingNext
		conn.dyingNext = nil
		if conn.reclaimable() {
			conn.releaseResources()
			conn.onDyingList = false
		} else {
			if now-conn.dyingSince > int64(goDyingLeakTimeout) {
				conn.dyingSince = now
				e.stack.logger.Warn("go: connection stuck in teardown: ", conn.destination)
			}
			conn.dyingNext = kept
			kept = conn
		}
		conn = next
	}
	e.dyingList = kept
}

func (c *GoConn) reclaimable() bool {
	if c.spliced.Load() || c.writerActive.Load() != 0 || c.transmitterActive.Load() != 0 || c.postedTarget.Load() != nil {
		return false
	}
	if c.receiveDrainable.Load() && !c.userClosed.Load() && c.receiveAvailable.Load() > c.consumedTail.Load() {
		return false
	}
	c.receiveReleased.Store(true)
	if c.readerActive.Load() != 0 {
		c.receiveReleased.Store(false)
		return false
	}
	return true
}

func (c *GoConn) releaseResources() {
	c.receiveChain.releaseAll()
	c.transmitStore.releaseAll()
	c.oooRanges = nil
	c.descriptors.release()
	c.scoreboard.reset()
	if c.receiveTarget.buffer != nil {
		c.receiveTarget.buffer.Release()
		c.receiveTarget.buffer = nil
	}
}

func (e *goEngine) closeAllFlows() []*GoConn {
	var unreset []*GoConn
	for _, conn := range e.flows {
		if conn.connState.Load() < goConnStateDead && !e.sendReset(conn) {
			unreset = append(unreset, conn)
		}
		e.detachConn(conn, net.ErrClosed, goDeathImmediate)
		e.removeFlowKey(conn)
	}
	return unreset
}

func (e *goEngine) expireSweepTick(now int64) {
	for _, conn := range e.flows {
		if conn.connState.Load() >= goConnStateDead {
			continue
		}
		sent := conn.sentTail.Load()
		if sent != conn.sweepSentTail {
			conn.sweepSentTail = sent
			conn.lastActivity = now
		}
		e.keepalive(conn, now)
		conn.receiveChain.releaseBelow(conn.consumedTail.Load())
		conn.releaseTransmitted(conn.sendUnacked.Load())
		conn.releaseDrainedSlabs()
		conn.releaseIdleDescriptors()
		conn.wakeWriter()
		e.maybeSendFin(conn)
		e.updatePersist(conn)
		if conn.hasOutstanding() && conn.retransmitDeadline == 0 {
			e.rearmRetransmit(conn)
		}
	}
	e.wheel.schedule(&e.sweepTickNode, now+int64(goSweepInterval))
}

func (e *goEngine) keepalive(conn *GoConn, now int64) {
	if conn.state == goTCPFinWait2 && conn.userClosed.Load() && now-conn.finWait2Since > int64(goFinWait2Timeout) {
		e.sendReset(conn)
		e.detachConn(conn, E.Cause(syscall.ETIMEDOUT, "go: orphaned FIN_WAIT_2"), goDeathImmediate)
		return
	}
	idle := now - conn.lastActivity
	if idle < int64(tcpEstablishedTimeout) {
		conn.keepaliveProbes = 0
		return
	}
	if conn.state == goTCPSynReceived || conn.hasOutstanding() {
		return
	}
	sinceIdle := idle - int64(tcpEstablishedTimeout)
	due := int64(conn.keepaliveProbes) * int64(goKeepaliveInterval)
	if sinceIdle < due {
		return
	}
	if conn.keepaliveProbes >= goKeepaliveCount {
		e.sendReset(conn)
		e.detachConn(conn, E.Cause(syscall.ETIMEDOUT, "go: keepalive timeout"), goDeathImmediate)
		return
	}
	conn.keepaliveProbes++
	segment := goSegment{offset: conn.sendNext() - 1, flags: header.TCPFlagAck}
	e.writeConnControl(conn, &segment)
}

func (e *goEngine) expireReclaimTick(now int64) {
	e.reclaim()
	e.wheel.schedule(&e.reclaimTickNode, now+int64(goReclaimInterval))
}

func (e *goEngine) reclaim() {
	e.slabPool.trim()
	e.descriptorPool.trim()
	for index := range e.reassemblyEntries {
		entry := &e.reassemblyEntries[index]
		if !entry.active {
			entry.buffer.Release()
			entry.buffer = nil
		}
	}
}
