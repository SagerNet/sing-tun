package tun

import (
	"context"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing-tun/gtcpip/seqnum"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	goHeaderScratchSize = 128
	goGSOMaxPayload     = 61440
	goEngineInlineBurst = 256 << 10
	goTransmitReadAhead = 64 << 10
)

const goTimestampOptionLength = 2 + header.TCPOptionTSLength

// include/uapi/linux/virtio_net.h
const (
	goGSOTypeIPv4 uint8 = 1
	goGSOTypeIPv6 uint8 = 4
)

type goSegment struct {
	offset     uint64
	length     int
	flags      header.TCPFlags
	sackBlocks []goSackBlock
	gsoSize    uint16
}

func (c *GoConn) Write(p []byte) (int, error) {
	err := c.awaitHandshake(context.Background(), c.writeDeadline.Wait())
	if err != nil {
		return 0, err
	}
	c.writeAccess.Lock()
	var n int
	if c.enterWriter() {
		n, err = c.writeLocked(p)
		c.exitWriter()
	} else {
		err = net.ErrClosed
	}
	c.writeAccess.Unlock()
	c.engine.reapAfterExit()
	return n, err
}

func (c *GoConn) WriteBuffer(buffer *buf.Buffer) error {
	err := c.awaitHandshake(context.Background(), c.writeDeadline.Wait())
	if err != nil {
		buffer.Release()
		return err
	}
	c.writeAccess.Lock()
	if c.enterWriter() {
		err = c.writeBufferLocked(buffer)
		c.exitWriter()
	} else {
		buffer.Release()
		err = net.ErrClosed
	}
	c.writeAccess.Unlock()
	c.engine.reapAfterExit()
	return err
}

func (c *GoConn) enterWriter() bool {
	c.access.Lock()
	defer c.access.Unlock()
	if c.dead || c.spliced || c.splicePending != nil {
		return false
	}
	c.writing = true
	return true
}

func (c *GoConn) exitWriter() {
	c.access.Lock()
	c.writing = false
	dead := c.dead
	finRequested := c.finRequested
	c.access.Unlock()
	if !dead {
		sent := c.sentTail.Load()
		if c.bufferedTail.Load() > sent {
			c.transmitPublished()
		} else {
			c.checkAppLimited(0, c.sendPermit.Load()&^goPermitWindowBit, sent)
		}
	}
	if finRequested {
		c.engine.postMessage(&c.closeMessage)
	}
}

func (c *GoConn) writeLocked(p []byte) (int, error) {
	total := 0
	for {
		c.access.Lock()
		dead := c.dead
		writeShut := c.writeShut
		capacity := c.transmitCapacity
		c.access.Unlock()
		if dead {
			return total, c.closeError()
		}
		if writeShut {
			return total, net.ErrClosed
		}
		select {
		case <-c.writeDeadline.Wait():
			return total, os.ErrDeadlineExceeded
		default:
		}
		if len(p) == 0 {
			return total, nil
		}
		budget := c.writeBudget(len(p), capacity)
		if budget <= 0 {
			err := c.parkWriter(1)
			if err != nil {
				return total, err
			}
			continue
		}
		buffered := c.bufferedTail.Load()
		c.transmitStore.reserve(buffered, budget)
		c.transmitStore.writeAt(buffered, p[:budget])
		c.publishBuffered(buffered + uint64(budget))
		total += budget
		p = p[budget:]
		if len(p) == 0 {
			return total, nil
		}
	}
}

func (c *GoConn) writeBufferLocked(buffer *buf.Buffer) error {
	length := buffer.Len()
	for {
		c.access.Lock()
		dead := c.dead
		writeShut := c.writeShut
		capacity := c.transmitCapacity
		c.access.Unlock()
		if dead {
			buffer.Release()
			return c.closeError()
		}
		if writeShut {
			buffer.Release()
			return net.ErrClosed
		}
		if uint64(length) > capacity {
			defer buffer.Release()
			_, err := c.writeLocked(buffer.Bytes())
			return err
		}
		select {
		case <-c.writeDeadline.Wait():
			buffer.Release()
			return os.ErrDeadlineExceeded
		default:
		}
		if length == 0 {
			buffer.Release()
			return nil
		}
		budget := c.writeBudget(length, capacity)
		if budget < length {
			if budget > 0 && c.storeEmpty() {
				defer buffer.Release()
				_, err := c.writeLocked(buffer.Bytes())
				return err
			}
			err := c.parkWriter(length)
			if err != nil {
				buffer.Release()
				return err
			}
			continue
		}
		buffered := c.bufferedTail.Load()
		if !c.transmitStore.adopt(buffered, buffer) {
			defer buffer.Release()
			_, err := c.writeLocked(buffer.Bytes())
			return err
		}
		c.publishBuffered(buffered + uint64(length))
		return nil
	}
}

func (c *GoConn) FrontHeadroom() int {
	return header.IPv6MinimumSize + header.TCPMinimumSize + goTimestampOptionLength
}

func (c *GoConn) WriterMTU() int {
	return int(c.gsoMaxSize(c.effectiveMSS.Load()))
}

func (c *GoConn) publishBuffered(tail uint64) {
	c.bufferedTail.Store(tail)
	c.transmitPublished()
}

func (c *GoConn) transmitPublished() {
	if goEngineTransmits {
		c.engine.postMessage(&c.transmitMessage)
		return
	}
	for {
		if !c.transmitAccess.TryLock() {
			c.transmitSignal.notify()
			return
		}
		_, result, armed := c.transmitLoop(false, 0)
		c.transmitAccess.Unlock()
		c.afterTransmit(armed)
		switch result {
		case goTransmitBlocked:
			c.wakeTransmitterGoroutine()
			return
		case goTransmitPaced, goTransmitThrottled:
			return
		}
		if c.closed() || c.nextTransmitLength(c.effectiveMSS.Load()) == 0 {
			return
		}
	}
}

func (c *GoConn) afterTransmit(armed bool) {
	if armed {
		c.engine.postMessage(&c.retransmitMessage)
	}
	c.access.Lock()
	finRequested := c.finRequested
	c.access.Unlock()
	if finRequested && c.sentTail.Load() == c.bufferedTail.Load() {
		c.engine.postMessage(&c.closeMessage)
	}
}

func (e *goEngine) transmitOnEngine(conn *GoConn, budget int) {
	if !conn.transmitAccess.TryLock() {
		conn.transmitSignal.notify()
		return
	}
	written, result, armed := conn.transmitLoop(false, budget)
	conn.transmitAccess.Unlock()
	if budget > 0 {
		e.inlineTransmitBudget = budget - written
	}
	if conn.retransmitDeadline == 0 && (armed || conn.hasOutstanding()) {
		e.rearmRetransmit(conn)
	}
	e.maybeSendFin(conn)
	switch result {
	case goTransmitBlocked:
		e.handleTransmitBlocked(conn)
	case goTransmitDone:
		if !conn.dead && conn.nextTransmitLength(conn.effectiveMSS.Load()) != 0 {
			e.postMessage(&conn.transmitMessage)
		}
	}
}

func (e *goEngine) handleTransmitRequest(conn *GoConn) {
	if conn.dead {
		return
	}
	if conn.splice != nil {
		e.spliceResume(conn)
		return
	}
	e.transmitOnEngine(conn, 0)
}

func (e *goEngine) retryBlockedOnEngine(conn *GoConn) {
	if conn.dead {
		return
	}
	if !conn.transmitAccess.TryLock() {
		conn.transmitSignal.notify()
		return
	}
	if !conn.blockedValid {
		conn.transmitAccess.Unlock()
		return
	}
	segment := conn.blockedSegment
	end := segment.offset + uint64(segment.length)
	err := conn.transmitFrame(&segment)
	switch err {
	case nil:
	case errGoTransmitBlocked:
		conn.amendDescriptors(segment.offset, segment.length, goDescriptorNoSample)
		conn.transmitAccess.Unlock()
		e.handleTransmitBlocked(conn)
		return
	case errGoFrameDropped:
		conn.amendDescriptors(segment.offset, segment.length, goDescriptorDropped)
		conn.blockedValid = false
		conn.blockedFrame = nil
		conn.transmitted(end)
		conn.transmitAccess.Unlock()
		e.handleDroppedFrames(conn)
		return
	default:
		conn.transmitAccess.Unlock()
		e.abortConn(conn, E.Cause(err, "go: write tun"))
		return
	}
	if conn.congestion.pacing {
		conn.advancePacing(e.coarseTime.Load(), segment.length)
	}
	conn.blockedValid = false
	conn.blockedFrame = nil
	conn.transmitted(end)
	conn.transmitAccess.Unlock()
	if conn.splice != nil {
		e.spliceResume(conn)
		if conn.splice != nil && conn.splice.downloadClosed {
			e.maybeSendFin(conn)
			e.spliceMaybeFinish(conn)
		}
		return
	}
	e.transmitOnEngine(conn, 0)
}

func (c *GoConn) wakeTransmitterGoroutine() {
	c.access.Lock()
	spawn := !c.transmitterRunning && !c.dead
	if spawn {
		c.transmitterRunning = true
	}
	c.access.Unlock()
	if spawn {
		go c.runTransmitter()
		return
	}
	c.transmitSignal.notify()
}

func (c *GoConn) hasDataWaiting() bool {
	return c.bufferedTail.Load() > c.sentTail.Load() || c.writerWaiting.Load() != 0
}

func (c *GoConn) runTransmitter() {
	defer func() {
		c.access.Lock()
		c.transmitterRunning = false
		c.access.Unlock()
		c.engine.reapAfterExit()
	}()
	for {
		if c.closed() {
			return
		}
		if c.transmitAccess.TryLock() {
			_, _, armed := c.transmitLoop(true, 0)
			c.transmitAccess.Unlock()
			c.afterTransmit(armed)
		}
		select {
		case <-c.transmitSignal:
		case <-c.closeSignal:
			return
		}
	}
}

func (c *GoConn) nextTransmitLength(mss uint32) int {
	sent := c.sentTail.Load()
	pending := c.bufferedTail.Load() - sent
	if pending == 0 {
		return 0
	}
	permit := c.sendPermit.Load()
	if permit&^goPermitWindowBit <= sent {
		if permit&goPermitWindowBit != 0 {
			c.windowLimitedSince.Store(true)
		}
		return 0
	}
	permit &^= goPermitWindowBit
	packets := int32(c.sendPacketPermit.Load() - c.dataSegmentsOut.Load())
	if packets <= 0 {
		c.windowLimitedSince.Store(true)
		return 0
	}
	length := int(min(pending, permit-sent, uint64(packets)*uint64(mss)))
	if pending < uint64(mss) && sent > c.sendUnacked.Load() {
		c.access.Lock()
		held := c.writing || c.nagle && !c.finRequested
		c.access.Unlock()
		if held {
			return 0
		}
	}
	// Windows delays the ACK of a lone segment by 40 ms and its receive window auto-tuning never
	// grows while every window is drained by one segment, so a window narrower than two segments is
	// always covered by two frames.
	allowance := permit - c.sendUnacked.Load()
	if allowance < 2*uint64(mss) && packets > 1 {
		length = min(length, int((allowance+1)/2))
	}
	return c.frameLength(length, mss)
}

func (c *GoConn) writeBudget(pending int, capacity uint64) int {
	released := c.sendReleased.Load()
	buffered := c.bufferedTail.Load()
	stored := buffered - released
	if stored >= capacity {
		return 0
	}
	if stored >= goTransmitReadAhead {
		share := c.engine.slabPool.shareBytes()
		if share > 0 && c.slabHolder.heldBytes() >= share {
			return 0
		}
	}
	unacked := c.sendUnacked.Load()
	permit := max(c.sendPermit.Load()&^goPermitWindowBit, unacked)
	limit := min(permit+max(permit-unacked, goTransmitReadAhead), released+capacity)
	budget := int64(limit) - int64(buffered)
	if pending > 0 {
		budget = min(budget, int64(pending))
	}
	if budget <= 0 {
		return 0
	}
	return int(budget)
}

func (c *GoConn) storeEmpty() bool {
	return c.bufferedTail.Load() == c.sendReleased.Load()
}

func (c *GoConn) loadTransmitCapacity() uint64 {
	c.access.Lock()
	defer c.access.Unlock()
	return c.transmitCapacity
}

func (c *GoConn) writeReady(required int) bool {
	budget := c.writeBudget(required, c.loadTransmitCapacity())
	return budget >= required || (budget > 0 && c.storeEmpty())
}

func (c *GoConn) parkWriter(required int) error {
	c.writerWaiting.Store(int32(required))
	c.writeSignal.drain()
	if c.writeReady(required) {
		c.writerWaiting.Store(0)
		return nil
	}
	c.access.Lock()
	dead := c.dead
	writeShut := c.writeShut
	c.access.Unlock()
	if dead {
		c.writerWaiting.Store(0)
		return c.closeError()
	}
	if writeShut {
		c.writerWaiting.Store(0)
		return net.ErrClosed
	}
	deadlineSignal := c.writeDeadline.Wait()
	select {
	case <-c.writeSignal:
	case <-deadlineSignal:
		c.writerWaiting.Store(0)
		return os.ErrDeadlineExceeded
	case <-c.closeSignal:
		c.writerWaiting.Store(0)
		return c.closeError()
	}
	c.writerWaiting.Store(0)
	if c.closed() {
		return c.closeError()
	}
	return nil
}

func (c *GoConn) parkTransmitBlocked() error {
	c.engine.postMessage(&c.blockedMessage)
	select {
	case <-c.transmitSignal:
	case <-c.closeSignal:
		return c.closeError()
	}
	if c.closed() {
		return c.closeError()
	}
	return nil
}

type goTransmitResult uint8

const (
	goTransmitDone goTransmitResult = iota
	goTransmitBlocked
	goTransmitPaced
	goTransmitThrottled
)

func (c *GoConn) transmitLoop(transmitter bool, budget int) (int, goTransmitResult, bool) {
	if transmitter {
		defer c.engine.platformIO.flush()
	}
	written := 0
	armed := false
	if c.blockedValid {
		if !transmitter {
			return written, goTransmitBlocked, armed
		}
		if !c.retryBlocked() {
			return written, goTransmitDone, armed
		}
	}
	paced := c.congestion.pacing
	result := goTransmitDone
	for !c.closed() {
		if budget > 0 && written >= budget {
			break
		}
		mss := c.effectiveMSS.Load()
		length := c.nextTransmitLength(mss)
		if length == 0 {
			sent := c.sentTail.Load()
			pending := c.bufferedTail.Load() - sent
			permit := c.sendPermit.Load()
			c.checkAppLimited(pending, permit&^goPermitWindowBit, sent)
			if pending > 0 && permit&goPermitWindowBit == 0 && sent == c.sendUnacked.Load() {
				armed = true
			}
			break
		}
		var now int64
		if paced {
			now = int64(time.Since(c.engine.epoch))
			if stamp := c.pacingStamp.Load(); c.dataSegmentsOut.Load() >= goPacingUnpacedSegments && stamp > now+goWheelTick {
				c.requestPacing(stamp - goWheelTick)
				result = goTransmitPaced
				break
			}
		}
		if c.queueThrottle(length) {
			result = goTransmitThrottled
			break
		}
		written += length
		sent := c.sentTail.Load()
		segment := goSegment{offset: sent, length: length, flags: header.TCPFlagAck | header.TCPFlagPsh}
		if length > int(mss) {
			segment.gsoSize = uint16(mss)
		}
		var flags uint16
		unacked := c.sendUnacked.Load()
		flightEmpty := sent == unacked
		if flightEmpty {
			flags |= goDescriptorTxStart
			armed = true
		}
		if !paced {
			now = int64(time.Since(c.engine.epoch))
		}
		c.pushDescriptors(sent, length, mss, c.stamp(now), flags, flightEmpty)
		c.sentTail.Store(sent + uint64(length))
		if !armed && c.sendUnacked.Load() == sent {
			armed = true
		}
		creditBase := c.packetCreditBase.Load()
		flight := uint64(c.dataSegmentsOut.Load() - creditBase)
		if flight > c.peakFlight.Load() {
			c.peakFlight.Store(flight)
		}
		permit := c.sendPermit.Load()
		if int32(c.sendPacketPermit.Load()-c.dataSegmentsOut.Load()) <= 0 ||
			sent+uint64(length) >= permit&^goPermitWindowBit && permit&goPermitWindowBit != 0 {
			c.windowLimitedSince.Store(true)
		}
		err := c.transmitFrame(&segment)
		if paced && err != errGoTransmitBlocked {
			c.advancePacing(now, length)
		}
		switch err {
		case nil:
			c.transmitted(sent + uint64(length))
		case errGoTransmitBlocked:
			c.amendDescriptors(segment.offset, segment.length, goDescriptorNoSample)
			c.blockedSegment = segment
			c.blockedValid = true
			if !transmitter {
				return written, goTransmitBlocked, armed
			}
			if !c.retryBlocked() {
				return written, goTransmitDone, armed
			}
		case errGoFrameDropped:
			c.amendDescriptors(segment.offset, segment.length, goDescriptorDropped)
			c.transmitted(sent + uint64(length))
			c.engine.postMessage(&c.droppedMessage)
		default:
			if !c.closed() {
				c.fail(E.Cause(err, "go: write tun"))
			}
			return written, goTransmitDone, armed
		}
	}
	return written, result, armed
}

func (c *GoConn) retryBlocked() bool {
	for {
		parkErr := c.parkTransmitBlocked()
		if parkErr != nil {
			return false
		}
		end := c.blockedSegment.offset + uint64(c.blockedSegment.length)
		err := c.transmitFrame(&c.blockedSegment)
		switch err {
		case nil:
		case errGoTransmitBlocked:
			c.amendDescriptors(c.blockedSegment.offset, c.blockedSegment.length, goDescriptorNoSample)
			continue
		case errGoFrameDropped:
			c.amendDescriptors(c.blockedSegment.offset, c.blockedSegment.length, goDescriptorDropped)
		default:
			if !c.closed() {
				c.fail(E.Cause(err, "go: write tun"))
			}
			return false
		}
		if c.congestion.pacing {
			c.advancePacing(int64(time.Since(c.engine.epoch)), c.blockedSegment.length)
		}
		c.blockedValid = false
		c.transmitted(end)
		if err == errGoFrameDropped {
			c.engine.postMessage(&c.droppedMessage)
		}
		return true
	}
}

func (c *GoConn) amendDescriptors(offset uint64, length int, flags uint16) {
	c.descriptors.push(goSentDescriptor{endOffset: offset + uint64(length), sentAt: int32(length), flags: goDescriptorAmend | flags})
}

func (c *GoConn) pushDescriptors(offset uint64, length int, mss uint32, sentAt int32, flags uint16, flightEmpty bool) {
	delivered, deliveredStamp, firstSentStamp, appLimited := c.snapshotDelivery(sentAt, flightEmpty)
	flags |= goDescriptorRated
	if appLimited {
		flags |= goDescriptorAppLimited
	}
	step := int(mss)
	for length > 0 {
		span := min(length, step)
		offset += uint64(span)
		length -= span
		c.dataSegmentsOut.Add(1)
		c.descriptors.push(goSentDescriptor{
			endOffset:      offset,
			sentAt:         sentAt,
			deliveredStamp: deliveredStamp,
			firstSentStamp: firstSentStamp,
			delivered:      delivered,
			flags:          flags,
		})
		flags &^= goDescriptorTxStart
	}
}

func (c *GoConn) frameLength(pending int, mss uint32) int {
	limit := int(mss)
	if c.engine.platformIO.transmitSegmentOffload() {
		limit = int(c.gsoMaxSize(mss))
		if frameLimit := int(c.frameLimit.Load()); frameLimit > 0 {
			limit = min(limit, max(frameLimit, int(mss)))
		}
	}
	return min(pending, limit)
}

func (c *GoConn) advancePacing(now int64, length int) {
	rate := c.pacingRate.Load()
	if rate == 0 || c.dataSegmentsOut.Load() < goPacingUnpacedSegments {
		c.pacingStamp.Store(now)
		return
	}
	for {
		prior := c.pacingStamp.Load()
		stamp := max(prior, now)
		lengthNanos := int64(uint64(length) * uint64(time.Second) / rate)
		credit := stamp - prior
		lengthNanos -= min(lengthNanos/2, credit)
		if c.pacingStamp.CompareAndSwap(prior, stamp+lengthNanos) {
			return
		}
	}
}

const goQueueLimitShift = 8

func (c *GoConn) queueThrottle(length int) bool {
	limit := max(2*int64(length), int64(c.pacingRate.Load()>>goQueueLimitShift))
	if c.queuedBytes.Load()+int64(length) <= limit || c.engine.platformIO.transmitBacklogBelowBatch() {
		return false
	}
	if c.sentTail.Load() == c.sendUnacked.Load() {
		return false
	}
	c.queueThrottled.Store(true)
	if c.queuedBytes.Load()+int64(length) <= limit {
		c.queueThrottled.Store(false)
		return false
	}
	return true
}

func (c *GoConn) frameEnqueued(length int) {
	c.queuedBytes.Add(int64(length))
}

func (c *GoConn) frameDequeued(length int, segmentEnd uint64) {
	c.queuedBytes.Add(-int64(length))
	if segmentEnd > c.departedTail.Load() {
		c.departedTail.Store(segmentEnd)
	}
	if c.queueThrottled.Swap(false) {
		c.engine.postMessage(&c.throttleMessage)
	}
}

func (c *GoConn) flightHeadQueued() bool {
	return c.queuedBytes.Load() > 0 && c.sendUnacked.Load() >= c.departedTail.Load()
}

func (c *GoConn) requestPacing(deadline int64) {
	c.pacingRequest.Store(deadline)
	c.engine.postMessage(&c.pacingMessage)
}

func (c *GoConn) transmitFrame(segment *goSegment) error {
	var (
		frame [][]byte
		meta  ForwardFrameMeta
	)
	if c.blockedValid && c.blockedFrame != nil && segment.offset == c.blockedSegment.offset && segment.length == c.blockedSegment.length {
		frame, meta = c.blockedFrame, c.blockedMeta
	} else {
		offload := c.engine.platformIO.transmitChecksumOffload()
		buffer, payload, contiguous := c.transmitStore.leadingRun(segment.offset, segment.length)
		if contiguous && buffer.Start() >= c.FrontHeadroom() {
			var packet []byte
			packet, meta = c.buildContiguousFrame(buffer, payload, segment, offload)
			c.transmitSegments = append(c.transmitSegments[:0], packet)
			frame = c.transmitSegments
		} else {
			frame, meta = c.buildFrame(c.transmitScratch[:], c.transmitSegments[:0], segment, &c.transmitStore, offload, false)
			c.transmitSegments = frame
		}
	}
	err := c.engine.platformIO.writeData(frame, meta, c, segment.offset+uint64(segment.length))
	switch err {
	case nil, errGoFrameDropped:
		c.blockedFrame = nil
		clear(c.transmitSegments[:cap(c.transmitSegments)])
	case errGoTransmitBlocked:
		c.blockedFrame = frame
		c.blockedMeta = meta
	}
	return err
}

type goFrameLayout struct {
	ipHeaderLength  int
	tcpHeaderLength int
	timestampLength int
	sackBlocks      []goSackBlock
}

func (l *goFrameLayout) headerLength() int {
	return l.ipHeaderLength + l.tcpHeaderLength
}

func (c *GoConn) frameLayout(segment *goSegment) goFrameLayout {
	var layout goFrameLayout
	if c.timestampsEnabled {
		layout.timestampLength = goTimestampOptionLength
	}
	layout.sackBlocks = segment.sackBlocks
	if len(layout.sackBlocks) > goMaxSackBlocksSent {
		layout.sackBlocks = layout.sackBlocks[:goMaxSackBlocksSent]
	}
	sackLength := 0
	if len(layout.sackBlocks) > 0 {
		sackLength = 4 + 8*len(layout.sackBlocks)
	}
	layout.tcpHeaderLength = header.TCPMinimumSize + layout.timestampLength + sackLength
	layout.ipHeaderLength = goNetworkHeaderLength(c.ipVersion)
	return layout
}

func (c *GoConn) encodeHeaders(packet []byte, layout *goFrameLayout, segment *goSegment, control bool) uint16 {
	tcpHdr := header.TCP(packet[layout.ipHeaderLength:])
	receiveAck := c.receiveNextAck.Load()
	edge := c.receiveEdge.Load()
	var window uint16
	if edge > receiveAck {
		window = uint16(min((edge-receiveAck)>>c.localWindowShift, 0xffff))
	}
	if control {
		c.sentEdge = max(c.sentEdge, edge)
	} else if edge > c.dataSentEdge.Load() {
		c.dataSentEdge.Store(edge)
	}
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    c.local.Port,
		DstPort:    c.peer.Port,
		SeqNum:     uint32(uint64(c.sendISN) + segment.offset),
		AckNum:     uint32(uint64(c.clientISN) + receiveAck),
		DataOffset: uint8(layout.tcpHeaderLength),
		Flags:      segment.flags,
		WindowSize: window,
	})
	options := packet[layout.ipHeaderLength+header.TCPMinimumSize:]
	if layout.timestampLength > 0 {
		goEncodeTimestampOption(options, goTimestampAt(int64(time.Since(c.engine.epoch))), c.tsRecent.Load())
	}
	if len(layout.sackBlocks) > 0 {
		goEncodeSackOption(options[layout.timestampLength:], layout.sackBlocks, c.clientISN)
	}
	return goEncodeNetworkHeader(packet, c.ipVersion, header.TCPProtocolNumber, c.local.Addr, c.peer.Addr, layout.tcpHeaderLength+segment.length, uint16(c.ident.Add(1)))
}

func goNetworkHeaderLength(ipVersion uint8) int {
	if ipVersion == 4 {
		return header.IPv4MinimumSize
	}
	return header.IPv6MinimumSize
}

func goEncodeNetworkHeader(packet []byte, ipVersion uint8, protocol tcpip.TransportProtocolNumber, source netip.Addr, destination netip.Addr, transportLength int, ident uint16) uint16 {
	if ipVersion == 4 {
		ipHdr := header.IPv4(packet)
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + transportLength),
			ID:          ident,
			TTL:         synthesizedTTL,
			Protocol:    uint8(protocol),
			SrcAddr:     source,
			DstAddr:     destination,
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		return header.PseudoHeaderChecksum(protocol, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), uint16(transportLength))
	}
	ipHdr := header.IPv6(packet)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(transportLength),
		TransportProtocol: protocol,
		HopLimit:          synthesizedTTL,
		SrcAddr:           source,
		DstAddr:           destination,
	})
	return header.PseudoHeaderChecksum(protocol, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), uint16(transportLength))
}

func (c *GoConn) offloadMeta(tcpHdr header.TCP, pseudoSum uint16, layout *goFrameLayout, segment *goSegment) ForwardFrameMeta {
	tcpHdr.SetChecksum(pseudoSum)
	meta := ForwardFrameMeta{
		needsChecksum:  true,
		checksumStart:  uint16(layout.ipHeaderLength),
		checksumOffset: header.TCPChecksumOffset,
	}
	if segment.gsoSize > 0 {
		meta.gsoSize = segment.gsoSize
		meta.gsoType = goGSOType(c.ipVersion)
	}
	return meta
}

func (c *GoConn) buildFrame(scratch []byte, segments [][]byte, segment *goSegment, store *goTransmitStore, offload bool, control bool) ([][]byte, ForwardFrameMeta) {
	layout := c.frameLayout(segment)
	packet := scratch[:layout.headerLength()]
	pseudoSum := c.encodeHeaders(packet, &layout, segment, control)
	segments = append(segments, packet)
	if segment.length > 0 {
		segments = store.appendRuns(segments, segment.offset, segment.length)
	}
	tcpHdr := header.TCP(packet[layout.ipHeaderLength:])
	if offload {
		return segments, c.offloadMeta(tcpHdr, pseudoSum, &layout, segment)
	}
	tcpHdr.SetChecksum(0)
	sum := checksum.Checksum(tcpHdr, pseudoSum)
	sum = goChecksumRuns(sum, segments[1:], layout.tcpHeaderLength%2 == 1)
	tcpHdr.SetChecksum(^sum)
	return segments, ForwardFrameMeta{}
}

func (c *GoConn) buildContiguousFrame(buffer *buf.Buffer, payload []byte, segment *goSegment, offload bool) ([]byte, ForwardFrameMeta) {
	layout := c.frameLayout(segment)
	headerLength := layout.headerLength()
	packet := buffer.ExtendHeader(headerLength)
	packet = packet[:headerLength+len(payload)]
	pseudoSum := c.encodeHeaders(packet[:headerLength], &layout, segment, false)
	tcpHdr := header.TCP(packet[layout.ipHeaderLength:])
	if offload {
		return packet, c.offloadMeta(tcpHdr, pseudoSum, &layout, segment)
	}
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^checksum.Checksum(packet[layout.ipHeaderLength:], pseudoSum))
	return packet, ForwardFrameMeta{}
}

func goChecksumRuns(initial uint16, runs [][]byte, odd bool) uint16 {
	sum := initial
	for _, run := range runs {
		if odd {
			partial := checksum.Checksum(run, 0)
			sum = checksum.Combine(sum, partial>>8|partial<<8)
		} else {
			sum = checksum.Checksum(run, sum)
		}
		if len(run)%2 == 1 {
			odd = !odd
		}
	}
	return sum
}

func goTimestampAt(now int64) uint32 {
	return uint32(now >> goTimestampShift)
}

func goEncodeTimestampOption(options []byte, timestampValue uint32, timestampEcho uint32) {
	options[0] = header.TCPOptionNOP
	options[1] = header.TCPOptionNOP
	header.EncodeTSOption(timestampValue, timestampEcho, options[2:goTimestampOptionLength])
}

func goEncodeSackOption(options []byte, blocks []goSackBlock, base uint32) {
	var sackBlocks [goMaxSackBlocksSent]header.SACKBlock
	for index, block := range blocks {
		sackBlocks[index] = header.SACKBlock{
			Start: seqnum.Value(uint64(base) + block.start),
			End:   seqnum.Value(uint64(base) + block.end),
		}
	}
	options[0] = header.TCPOptionNOP
	options[1] = header.TCPOptionNOP
	optionsLength := 2 + header.EncodeSACKBlocks(sackBlocks[:len(blocks)], options[2:])
	header.AddTCPOptionPadding(options, optionsLength)
}

func (c *GoConn) buildHandshake(localMSS uint16, windowScale bool, sackPermitted bool, flags header.TCPFlags, ackNumber uint32) {
	ipHeaderLength := goNetworkHeaderLength(c.ipVersion)
	optionsStorage := c.handshakeImage[ipHeaderLength+header.TCPMinimumSize:]
	optionsLength := header.EncodeMSSOption(uint32(localMSS), optionsStorage)
	if windowScale {
		optionsLength += header.EncodeWSOption(int(c.localWindowShift), optionsStorage[optionsLength:])
	}
	if sackPermitted {
		optionsLength += header.EncodeSACKPermittedOption(optionsStorage[optionsLength:])
	}
	if c.timestampsEnabled {
		optionsLength += header.EncodeTSOption(goTimestampAt(int64(time.Since(c.engine.epoch))), c.tsRecent.Load(), optionsStorage[optionsLength:])
	}
	optionsLength += header.AddTCPOptionPadding(optionsStorage, optionsLength)
	tcpHeaderLength := header.TCPMinimumSize + optionsLength
	totalLength := ipHeaderLength + tcpHeaderLength
	c.handshakeLength = uint8(totalLength)
	packet := c.handshakeImage[:totalLength]
	tcpHdr := header.TCP(packet[ipHeaderLength:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    c.local.Port,
		DstPort:    c.peer.Port,
		SeqNum:     c.sendISN,
		AckNum:     ackNumber,
		DataOffset: uint8(tcpHeaderLength),
		Flags:      flags,
		WindowSize: uint16(min(c.receiveCapacity, 0xffff)),
	})
	pseudoSum := goEncodeNetworkHeader(packet, c.ipVersion, header.TCPProtocolNumber, c.local.Addr, c.peer.Addr, tcpHeaderLength, uint16(c.ident.Add(1)))
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^checksum.Checksum(tcpHdr, pseudoSum))
}

var errGoTransmitBlocked = E.New("go: transmit blocked")

func goGSOType(ipVersion uint8) uint8 {
	if ipVersion == 4 {
		return goGSOTypeIPv4
	}
	return goGSOTypeIPv6
}
