package tun

import (
	"context"
	"net"
	"net/netip"
	"os"

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
	defer c.writeAccess.Unlock()
	if !c.enterWriter() {
		return 0, net.ErrClosed
	}
	defer c.exitWriter()
	return c.writeLocked(p)
}

func (c *GoConn) writeLocked(p []byte) (int, error) {
	total := 0
	for {
		if c.connState.Load() >= goConnStateAborted {
			return total, c.closeError()
		}
		if c.writeShut.Load() {
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
		budget := c.writeBudget(len(p))
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

func (c *GoConn) WriteBuffer(buffer *buf.Buffer) error {
	err := c.awaitHandshake(context.Background(), c.writeDeadline.Wait())
	if err != nil {
		buffer.Release()
		return err
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if !c.enterWriter() {
		buffer.Release()
		return net.ErrClosed
	}
	defer c.exitWriter()
	length := buffer.Len()
	if length > goTransmitCapacityMax {
		defer buffer.Release()
		_, err = c.writeLocked(buffer.Bytes())
		return err
	}
	for {
		if c.connState.Load() >= goConnStateAborted {
			buffer.Release()
			return c.closeError()
		}
		if c.writeShut.Load() {
			buffer.Release()
			return net.ErrClosed
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
		budget := c.writeBudget(length)
		if budget < length {
			if budget > 0 && c.storeEmpty() {
				defer buffer.Release()
				_, err = c.writeLocked(buffer.Bytes())
				return err
			}
			err = c.parkWriter(length)
			if err != nil {
				buffer.Release()
				return err
			}
			continue
		}
		buffered := c.bufferedTail.Load()
		if !c.transmitStore.adopt(buffered, buffer) {
			defer buffer.Release()
			_, err = c.writeLocked(buffer.Bytes())
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
	mss := int(c.effectiveMSS)
	if c.engine.platformIO.transmitSegmentOffload() {
		return max(goGSOMaxPayload/mss*mss, mss)
	}
	return max(0xffff/mss*mss, mss)
}

func (c *GoConn) publishBuffered(tail uint64) {
	c.bufferedTail.Store(tail)
	if c.transmitterActive.Load() != 0 {
		c.transmitSignal.notify()
		return
	}
	c.transmitInline()
}

func (c *GoConn) transmitInline() {
	for {
		if !c.transmitOwner.CompareAndSwap(0, 1) {
			c.transmitSignal.notify()
			return
		}
		_, blocked := c.transmitLoop(false, 0)
		c.transmitOwner.Store(0)
		if blocked {
			c.wakeTransmitterGoroutine()
			return
		}
		if c.connState.Load() >= goConnStateAborted || c.nextTransmitLength() == 0 {
			return
		}
	}
}

func (c *GoConn) transmitOnEngine() bool {
	budget := c.engine.inlineTransmitBudget
	if budget <= 0 {
		return false
	}
	if !c.transmitOwner.CompareAndSwap(0, 1) {
		c.transmitSignal.notify()
		return true
	}
	written, blocked := c.transmitLoop(false, budget)
	c.transmitOwner.Store(0)
	c.engine.inlineTransmitBudget = budget - written
	if blocked {
		return false
	}
	return c.connState.Load() >= goConnStateAborted || c.nextTransmitLength() == 0
}

func (c *GoConn) wakeTransmitterGoroutine() {
	if c.transmitterActive.CompareAndSwap(0, 1) {
		go c.runTransmitter()
		return
	}
	c.transmitSignal.notify()
}

func (c *GoConn) hasDataWaiting() bool {
	return c.bufferedTail.Load() > c.sentTail.Load() || c.writerParked.Load()
}

func (c *GoConn) runTransmitter() {
	defer func() {
		c.transmitterActive.Store(0)
		c.engine.reapAfterExit()
	}()
	for {
		if c.connState.Load() >= goConnStateAborted {
			return
		}
		if c.transmitOwner.CompareAndSwap(0, 1) {
			c.transmitLoop(true, 0)
			c.transmitOwner.Store(0)
		}
		select {
		case <-c.transmitSignal:
		case <-c.closeSignal:
			return
		}
	}
}

func (c *GoConn) nextTransmitLength() int {
	sent := c.sentTail.Load()
	pending := c.bufferedTail.Load() - sent
	if pending == 0 {
		return 0
	}
	permit := c.sendPermit.Load()
	if permit <= sent {
		return 0
	}
	return c.frameLength(int(min(pending, permit-sent)))
}

func (c *GoConn) writeBudget(pending int) int {
	released := c.sendReleased.Load()
	buffered := c.bufferedTail.Load()
	stored := buffered - released
	if stored >= goTransmitCapacityMax {
		return 0
	}
	if stored >= goTransmitReadAhead {
		share := c.engine.slabPool.shareBytes()
		if share > 0 && c.slabHolder.heldBytes() >= share {
			return 0
		}
	}
	unacked := c.sendUnacked.Load()
	permit := max(c.sendPermit.Load(), unacked)
	limit := min(permit+max(permit-unacked, goTransmitReadAhead), released+goTransmitCapacityMax)
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

func (c *GoConn) writeReady(required int) bool {
	budget := c.writeBudget(required)
	return budget >= required || (budget > 0 && c.storeEmpty())
}

func (c *GoConn) parkWriter(required int) error {
	c.writerNeeds.Store(int32(required))
	c.writerParked.Store(true)
	c.writeSignal.drain()
	if c.writeReady(required) {
		c.writerParked.Store(false)
		return nil
	}
	if c.connState.Load() >= goConnStateAborted {
		c.writerParked.Store(false)
		return c.closeError()
	}
	if c.writeShut.Load() {
		c.writerParked.Store(false)
		return net.ErrClosed
	}
	deadlineSignal := c.writeDeadline.Wait()
	select {
	case <-c.writeSignal:
	case <-deadlineSignal:
		c.writerParked.Store(false)
		return os.ErrDeadlineExceeded
	case <-c.closeSignal:
		c.writerParked.Store(false)
		return c.closeError()
	}
	c.writerParked.Store(false)
	if c.connState.Load() >= goConnStateAborted {
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
	if c.connState.Load() >= goConnStateAborted {
		return c.closeError()
	}
	return nil
}

func (c *GoConn) transmitLoop(transmitter bool, budget int) (int, bool) {
	if transmitter {
		defer c.engine.platformIO.flush()
	}
	sentAny := false
	written := 0
	if c.blockedValid {
		if !transmitter {
			return written, true
		}
		if !c.retryBlocked() {
			return written, false
		}
		sentAny = true
	}
	for c.connState.Load() < goConnStateAborted {
		if budget > 0 && written >= budget {
			break
		}
		length := c.nextTransmitLength()
		if length == 0 {
			break
		}
		written += length
		sent := c.sentTail.Load()
		segment := goSegment{offset: sent, length: length, flags: header.TCPFlagAck | header.TCPFlagPsh}
		if length > int(c.effectiveMSS) {
			segment.gsoSize = c.effectiveMSS
		}
		var flags uint8
		if c.engine.engineState.Load() == goEngineParked {
			flags |= goDescriptorNoSample
		}
		c.pushDescriptors(sent, length, c.stamp(c.engine.now()), flags)
		c.sentTail.Store(sent + uint64(length))
		sentAny = true
		err := c.transmitFrame(&segment)
		switch err {
		case nil:
			c.transmittedTail.Store(sent + uint64(length))
		case errGoTransmitBlocked:
			c.amendDescriptors(segment.offset, segment.length, goDescriptorNoSample)
			c.blockedSegment = segment
			c.blockedValid = true
			if !transmitter {
				c.finishTransmit(sentAny)
				return written, true
			}
			if !c.retryBlocked() {
				return written, false
			}
		case errGoFrameDropped:
			c.amendDescriptors(segment.offset, segment.length, goDescriptorDropped)
			c.engine.postMessage(&c.droppedMessage)
			c.transmittedTail.Store(sent + uint64(length))
		default:
			if c.connState.Load() < goConnStateAborted {
				c.requestAbort(E.Cause(err, "go: write tun"))
			}
			return written, false
		}
	}
	c.finishTransmit(sentAny)
	return written, false
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
			c.engine.postMessage(&c.droppedMessage)
		default:
			if c.connState.Load() < goConnStateAborted {
				c.requestAbort(E.Cause(err, "go: write tun"))
			}
			return false
		}
		c.blockedValid = false
		c.blockedFrame = nil
		c.transmittedTail.Store(end)
		return true
	}
}

func (c *GoConn) finishTransmit(sentAny bool) {
	if !sentAny {
		return
	}
	if c.spliced.Load() {
		if c.retransmitDeadline == 0 {
			c.engine.rearmRetransmit(c)
		}
		return
	}
	c.armRetransmitIfIdle()
	if c.finRequested.Load() && c.sentTail.Load() == c.bufferedTail.Load() {
		c.engine.postMessage(&c.closeMessage)
	}
}

func (c *GoConn) amendDescriptors(offset uint64, length int, flags uint8) {
	c.descriptors.push(offset+uint64(length), int32(length), goDescriptorAmend|flags)
}

func (c *GoConn) pushDescriptors(offset uint64, length int, sentAt int32, flags uint8) {
	step := int(c.effectiveMSS)
	for length > 0 {
		span := min(length, step)
		offset += uint64(span)
		length -= span
		c.descriptors.push(offset, sentAt, flags)
	}
}

func (c *GoConn) frameLength(pending int) int {
	limit := int(c.effectiveMSS)
	if c.engine.platformIO.transmitSegmentOffload() {
		limit = max(goGSOMaxPayload/limit*limit, limit)
	}
	return min(pending, limit)
}

func (c *GoConn) transmitFrame(segment *goSegment) error {
	if c.blockedValid && c.blockedFrame != nil && segment.offset == c.blockedSegment.offset && segment.length == c.blockedSegment.length {
		return c.engine.platformIO.writeData(c.blockedFrame, c.blockedMeta)
	}
	offload := c.engine.platformIO.transmitChecksumOffload()
	buffer, payload, contiguous := c.transmitStore.leadingRun(segment.offset, segment.length)
	var (
		frame [][]byte
		meta  ForwardFrameMeta
	)
	if contiguous && buffer.Start() >= c.FrontHeadroom() {
		var packet []byte
		packet, meta = c.buildContiguousFrame(buffer, payload, segment, offload)
		c.transmitSegments = append(c.transmitSegments[:0], packet)
		frame = c.transmitSegments
	} else {
		frame, meta = c.buildFrame(c.transmitScratch[:], c.transmitSegments[:0], segment, &c.transmitStore, offload)
		c.transmitSegments = frame
	}
	err := c.engine.platformIO.writeData(frame, meta)
	if err == errGoTransmitBlocked {
		c.blockedFrame = frame
		c.blockedMeta = meta
	}
	return err
}

func (c *GoConn) armRetransmitIfIdle() {
	if c.retransmitArmed.CompareAndSwap(false, true) {
		c.engine.postMessage(&c.retransmitMessage)
	}
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

func (c *GoConn) encodeHeaders(packet []byte, layout *goFrameLayout, segment *goSegment) uint16 {
	tcpHdr := header.TCP(packet[layout.ipHeaderLength:])
	receiveAck := c.receiveNextAck.Load()
	edge := c.receiveEdge.Load()
	var window uint16
	if edge > receiveAck {
		window = uint16(min((edge-receiveAck)>>c.localWindowShift, 0xffff))
	}
	for {
		sent := c.sentEdge.Load()
		if edge <= sent || c.sentEdge.CompareAndSwap(sent, edge) {
			break
		}
	}
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    c.destination.Port,
		DstPort:    c.source.Port,
		SeqNum:     uint32(uint64(c.sendISN) + segment.offset),
		AckNum:     uint32(uint64(c.clientISN) + receiveAck),
		DataOffset: uint8(layout.tcpHeaderLength),
		Flags:      segment.flags,
		WindowSize: window,
	})
	options := packet[layout.ipHeaderLength+header.TCPMinimumSize:]
	if layout.timestampLength > 0 {
		goEncodeTimestampOption(options, goTimestampAt(c.engine.now()), c.tsRecent.Load())
	}
	if len(layout.sackBlocks) > 0 {
		goEncodeSackOption(options[layout.timestampLength:], layout.sackBlocks, c.clientISN)
	}
	return goEncodeNetworkHeader(packet, c.ipVersion, c.destination.Addr, c.source.Addr, layout.tcpHeaderLength+segment.length, uint16(c.ident.Add(1)))
}

func goNetworkHeaderLength(ipVersion uint8) int {
	if ipVersion == 4 {
		return header.IPv4MinimumSize
	}
	return header.IPv6MinimumSize
}

func goEncodeNetworkHeader(packet []byte, ipVersion uint8, source netip.Addr, destination netip.Addr, tcpLength int, ident uint16) uint16 {
	var network header.Network
	if ipVersion == 4 {
		ipHdr := header.IPv4(packet)
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + tcpLength),
			ID:          ident,
			TTL:         synthesizedTTL,
			Protocol:    uint8(header.TCPProtocolNumber),
			SrcAddr:     source,
			DstAddr:     destination,
		})
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		network = ipHdr
	} else {
		ipHdr := header.IPv6(packet)
		ipHdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(tcpLength),
			TransportProtocol: header.TCPProtocolNumber,
			HopLimit:          synthesizedTTL,
			SrcAddr:           source,
			DstAddr:           destination,
		})
		network = ipHdr
	}
	return header.PseudoHeaderChecksum(header.TCPProtocolNumber, network.SourceAddressSlice(), network.DestinationAddressSlice(), uint16(tcpLength))
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

func (c *GoConn) buildFrame(scratch []byte, segments [][]byte, segment *goSegment, store *goTransmitStore, offload bool) ([][]byte, ForwardFrameMeta) {
	layout := c.frameLayout(segment)
	packet := scratch[:layout.headerLength()]
	pseudoSum := c.encodeHeaders(packet, &layout, segment)
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
	pseudoSum := c.encodeHeaders(packet[:headerLength], &layout, segment)
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

func (c *GoConn) buildSynAck(synOptions header.TCPSynOptions, localMSS uint16) {
	ipHeaderLength := goNetworkHeaderLength(c.ipVersion)
	optionsStorage := c.synAckImage[ipHeaderLength+header.TCPMinimumSize:]
	optionsLength := header.EncodeMSSOption(uint32(localMSS), optionsStorage)
	if synOptions.WS >= 0 {
		optionsLength += header.EncodeWSOption(int(c.localWindowShift), optionsStorage[optionsLength:])
	}
	if synOptions.SACKPermitted {
		optionsLength += header.EncodeSACKPermittedOption(optionsStorage[optionsLength:])
	}
	if c.timestampsEnabled {
		optionsLength += header.EncodeTSOption(goTimestampAt(c.engine.now()), c.tsRecent.Load(), optionsStorage[optionsLength:])
	}
	optionsLength += header.AddTCPOptionPadding(optionsStorage, optionsLength)
	tcpHeaderLength := header.TCPMinimumSize + optionsLength
	totalLength := ipHeaderLength + tcpHeaderLength
	c.synAckLength = uint8(totalLength)
	packet := c.synAckImage[:totalLength]
	tcpHdr := header.TCP(packet[ipHeaderLength:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    c.destination.Port,
		DstPort:    c.source.Port,
		SeqNum:     c.sendISN,
		AckNum:     c.clientISN + 1,
		DataOffset: uint8(tcpHeaderLength),
		Flags:      header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize: uint16(min(c.receiveCapacity, 0xffff)),
	})
	pseudoSum := goEncodeNetworkHeader(packet, c.ipVersion, c.destination.Addr, c.source.Addr, tcpHeaderLength, uint16(c.ident.Add(1)))
	tcpHdr.SetChecksum(0)
	tcpHdr.SetChecksum(^checksum.Checksum(tcpHdr, pseudoSum))
}

func (c *GoConn) writeSynAck() error {
	var frame [1][]byte
	frame[0] = c.synAckImage[:c.synAckLength]
	return goIgnoreDropped(c.engine.platformIO.writeFrame(frame[:], ForwardFrameMeta{}))
}

func (c *GoConn) writeReset() error {
	var scratch [header.IPv6MinimumSize + header.TCPMinimumSize + goTimestampOptionLength]byte
	var frame [1][]byte
	segment := goSegment{offset: 0, flags: header.TCPFlagRst | header.TCPFlagAck}
	segments, _ := c.buildFrame(scratch[:], frame[:0], &segment, &c.transmitStore, false)
	return goIgnoreDropped(c.engine.platformIO.writeFrame(segments, ForwardFrameMeta{}))
}

var errGoTransmitBlocked = E.New("go: transmit blocked")

func goGSOType(ipVersion uint8) uint8 {
	if ipVersion == 4 {
		return goGSOTypeIPv4
	}
	return goGSOTypeIPv6
}
