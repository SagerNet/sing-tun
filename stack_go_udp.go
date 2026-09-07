package tun

import (
	"context"
	"io"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	goPacketBatchSize   = 32
	goUDPGSOType        = 5
	goUDPChecksumOffset = 6
)

type goUDPFrame struct {
	header  [header.IPv6MinimumSize + header.UDPMinimumSize]byte
	length  int
	payload []byte
	meta    ForwardFrameMeta
}

type goUDPUserData struct {
	engine    *goEngine
	owner     *goEngine
	key       udpNatSessionKey
	packet    []byte
	meta      ForwardFrameMeta
	ipVersion uint8
	created   *GoPacketConn
}

func (e *goEngine) processUDPSegments(frame *goFrame) {
	meta := frame.meta
	packet := frame.buffer.Bytes()
	parsed, parsedOK := parseForwardPacket(packet)
	headerLength := int(meta.checksumStart) + header.UDPMinimumSize
	if !parsedOK || parsed.protocol != uint8(header.UDPProtocolNumber) || parsed.fragment || meta.gsoSize == 0 || headerLength > len(packet) {
		return
	}
	count := (len(packet) - headerLength + int(meta.gsoSize) - 1) / int(meta.gsoSize)
	if count == 0 {
		return
	}
	options := *e.packetReadOptions.Load()
	buffers := newGoReadBuffers(headerLength+int(meta.gsoSize), count, options)
	defer buf.ReleaseMulti(buffers)
	segments := make([][]byte, count)
	sizes := make([]int, count)
	for index, buffer := range buffers {
		segments[index] = buffer.FreeBytes()
	}
	count, err := GSOSplit(packet, GSOOptions{
		GSOType: GSOUDPL4, HdrLen: uint16(headerLength), GSOSize: meta.gsoSize,
		CsumStart: meta.checksumStart, CsumOffset: meta.checksumOffset, NeedsCsum: meta.needsChecksum,
	}, segments, sizes, 0)
	if err != nil {
		e.stack.logger.Trace(E.Cause(err, "go: split UDP segments"))
		return
	}
	for index := range count {
		buffer := buffers[index]
		buffer.Truncate(sizes[index])
		options.PostReturn(buffer)
		e.processFrame(&goFrame{buffer: buffer})
	}
	e.flushPacketUploads()
}

func (e *goEngine) demuxUDP(packetBuffer *buf.Buffer, meta ForwardFrameMeta, parsed *forwardPacket) {
	packet := packetBuffer.Bytes()
	if len(parsed.transport) < header.UDPMinimumSize {
		return
	}
	switch parsed.verdict.Action {
	case ActionReject:
		meta.completeChecksum(packet)
		reply, ok := BuildUnreachable(packet, netip.Addr{}, 0)
		if ok {
			err := e.platformIO.writeFrame(e.singleFrame(reply), ForwardFrameMeta{})
			if err != nil {
				e.stack.logger.Trace(E.Cause(err, "go: write unreachable"))
			}
		}
		return
	case ActionDrop:
		return
	case ActionHijackDNS:
		e.dispatcher.hijackDNSPacket(parsed)
		return
	}
	payload := header.UDP(parsed.transport).Payload()
	source := M.SocksaddrFromNetIP(parsed.source)
	destination := M.SocksaddrFromNetIP(parsed.destination)
	key := e.udpNat.sessionKey(source, destination)
	userData := &e.udpUserData
	*userData = goUDPUserData{
		engine:    e,
		key:       key,
		packet:    packet,
		meta:      meta,
		ipVersion: parsed.ipVersion,
	}
	conn, ok := e.udpNat.getOrCreate(key, source, destination, userData)
	if !ok {
		if userData.owner != nil {
			userData.owner.inject(packet, meta)
		}
		return
	}
	if userData.created != nil {
		e.attachUDPSession(conn, userData.created, &parsed.verdict)
		userData.created = nil
	}
	if writer, isGoPacketConn := conn.writer.(*GoPacketConn); isGoPacketConn {
		if writer.engine != e {
			writer.engine.inject(packet, meta)
			return
		}
		if writer.splice != nil {
			if len(e.packetFlows) < goReadBatch {
				e.packetFlows[parsed.flowKey()] = writer
			}
			e.packetSpliceInput(writer, packetBuffer, parsed)
			return
		}
		trackerPointer := writer.tracker.Load()
		if trackerPointer != nil {
			(*trackerPointer).CountForward(len(packet))
		}
	}
	readWaitOptions := conn.loadReadWaitOptions()
	buffer := readWaitOptions.NewBufferSize(len(payload))
	buffer.Write(payload)
	readWaitOptions.PostReturn(buffer)
	conn.enqueue(buffer, destination)
	e.wokeHandlerThisBurst = true
}

func (e *goEngine) packetSpliceInput(writer *GoPacketConn, packetBuffer *buf.Buffer, parsed *forwardPacket) {
	trackerPointer := writer.tracker.Load()
	if trackerPointer != nil {
		(*trackerPointer).CountForward(packetBuffer.Len())
	}
	headerLength := header.IPv6MinimumSize
	if parsed.ipVersion == 4 {
		headerLength = int(header.IPv4(parsed.network).HeaderLength())
	}
	payloadLength := len(header.UDP(parsed.transport).Payload())
	packetBuffer.Advance(headerLength + header.UDPMinimumSize)
	packetBuffer.Truncate(payloadLength)
	e.packetSpliceUpload(writer, packetBuffer, M.SocksaddrFromNetIP(parsed.destination))
}

func (e *goEngine) attachUDPSession(conn *UDPNatConn, writer *GoPacketConn, verdict *FlowVerdict) {
	writer.conn.Store(conn)
	if verdict.UDPTimeout > 0 {
		conn.SetTimeout(verdict.UDPTimeout)
	}
	if verdict.NewTracker != nil {
		tracker := verdict.NewTracker()
		if tracker != nil {
			writer.tracker.Store(&tracker)
			tracker.AttachFlow(writer)
		}
	}
}

func (s *Go) prepareUDPConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	data := userData.(*goUDPUserData)
	directory := &s.directory
	if directory.udpFlows != nil {
		directory.access.Lock()
		defer directory.access.Unlock()
		if owner := directory.udpFlows[data.key]; owner != nil {
			conn := owner.conn.Load()
			if conn == nil || !conn.isClosed() {
				data.owner = owner.engine
				return false, nil, nil, nil
			}
		}
	}
	writer := &GoPacketConn{
		engine:          data.engine,
		key:             data.key,
		platformIO:      data.engine.platformIO,
		mtu:             s.mtu,
		checksumOffload: data.engine.platformIO.transmitChecksumOffload(),
		snapshot:        slices.Clone(data.packet),
		snapshotMeta:    data.meta,
	}
	writer.spliceMessage = goMessage{kind: goMessagePacketSplice, packet: writer}
	writer.closeMessage = goMessage{kind: goMessagePacketClose, packet: writer}
	writer.buildTemplate(data.ipVersion, source)
	data.created = writer
	if directory.udpFlows != nil {
		directory.udpFlows[data.key] = writer
	}
	return true, s.ctx, writer, writer.handleSessionClose
}

type GoPacketConn struct {
	engine           *goEngine
	key              udpNatSessionKey
	platformIO       goPlatformIO
	splice           *goSplicePacket
	splicePending    atomic.Pointer[goSplicePacket]
	spliceActive     atomic.Bool
	spliceCloseError atomic.Pointer[goConnError]
	spliceMessage    goMessage
	closeMessage     goMessage
	mtu              int
	ipVersion        uint8
	templateLength   int
	checksumOffload  bool
	template         [header.IPv6MinimumSize + header.UDPMinimumSize]byte
	conn             atomic.Pointer[UDPNatConn]
	tracker          atomic.Pointer[FlowTracker]
	trackerClosed    atomic.Bool
	snapshotAccess   sync.Mutex
	snapshot         []byte
	snapshotMeta     ForwardFrameMeta
}

func (w *GoPacketConn) buildTemplate(ipVersion uint8, client M.Socksaddr) {
	w.ipVersion = ipVersion
	clientAddr := client.Addr
	if ipVersion == 4 {
		w.templateLength = header.IPv4MinimumSize + header.UDPMinimumSize
		ipHdr := header.IPv4(w.template[:w.templateLength])
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(w.templateLength),
			TTL:         synthesizedTTL,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     clientAddr,
			DstAddr:     clientAddr,
		})
		header.UDP(ipHdr[header.IPv4MinimumSize:]).Encode(&header.UDPFields{
			DstPort: client.Port,
		})
	} else {
		w.templateLength = header.IPv6MinimumSize + header.UDPMinimumSize
		ipHdr := header.IPv6(w.template[:w.templateLength])
		ipHdr.Encode(&header.IPv6Fields{
			PayloadLength:     header.UDPMinimumSize,
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          synthesizedTTL,
			SrcAddr:           clientAddr,
			DstAddr:           clientAddr,
		})
		header.UDP(ipHdr[header.IPv6MinimumSize:]).Encode(&header.UDPFields{
			DstPort: client.Port,
		})
	}
}

func (w *GoPacketConn) preparePacketHeader(packet []byte, payload []byte, destination M.Socksaddr, checksumOffload bool) (ForwardFrameMeta, error) {
	maximumPayload := 65535 - header.UDPMinimumSize
	if w.ipVersion == 4 {
		maximumPayload -= header.IPv4MinimumSize
	}
	if len(payload) > maximumPayload {
		return ForwardFrameMeta{}, errGoFrameDropped
	}
	if !destination.IsIP() || w.ipVersion == 4 && !destination.IsIPv4() {
		return ForwardFrameMeta{}, E.New("go: invalid packet destination")
	}
	if w.ipVersion == 6 && destination.IsIPv4() {
		destination = M.SocksaddrFrom(netip.AddrFrom16(destination.Addr.As16()), destination.Port)
	}
	var meta ForwardFrameMeta
	copy(packet, w.template[:w.templateLength])
	udpLength := uint16(header.UDPMinimumSize + len(payload))
	var sourceAddress, destinationAddress []byte
	if w.ipVersion == 4 {
		ipHdr := header.IPv4(packet[:header.IPv4MinimumSize])
		ipHdr.SetTotalLength(uint16(w.templateLength + len(payload)))
		ipHdr.SetSourceAddr(destination.Addr)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		sourceAddress = ipHdr.SourceAddressSlice()
		destinationAddress = ipHdr.DestinationAddressSlice()
	} else {
		ipHdr := header.IPv6(packet[:header.IPv6MinimumSize])
		ipHdr.SetPayloadLength(udpLength)
		ipHdr.SetSourceAddr(destination.Addr)
		sourceAddress = ipHdr.SourceAddressSlice()
		destinationAddress = ipHdr.DestinationAddressSlice()
	}
	udpHdr := header.UDP(packet[w.templateLength-header.UDPMinimumSize : w.templateLength])
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(udpLength)
	pseudoSum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, sourceAddress, destinationAddress, udpLength)
	if checksumOffload {
		udpHdr.SetChecksum(pseudoSum)
		meta.needsChecksum = true
		meta.checksumStart = uint16(w.templateLength - header.UDPMinimumSize)
		meta.checksumOffset = goUDPChecksumOffset
	} else {
		sum := ^checksum.Checksum(payload, udpHdr.CalculateChecksum(pseudoSum))
		if sum == 0 {
			sum = 0xffff
		}
		udpHdr.SetChecksum(sum)
	}
	trackerPointer := w.tracker.Load()
	if trackerPointer != nil {
		(*trackerPointer).CountReverse(w.templateLength + len(payload))
	}
	return meta, nil
}

func (w *GoPacketConn) FrontHeadroom() int {
	return w.platformIO.transmitPrefix() + w.templateLength
}

func (w *GoPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.IsIP() {
		buffer.Release()
		return E.Cause(os.ErrInvalid, "invalid destination")
	}
	defer buffer.Release()
	return w.transmit(buffer, destination)
}

func (w *GoPacketConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil, false
	}
	return w, true
}

func (w *GoPacketConn) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	defer buf.ReleaseMulti(buffers)
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		return os.ErrInvalid
	}
	var frames [goPacketBatchSize]goUDPFrame
	count := 0
	for index, buffer := range buffers {
		if !destinations[index].IsIP() {
			return os.ErrInvalid
		}
		if buffer.Len()+w.templateLength > w.mtu {
			if count > 0 {
				err := goIgnoreDropped(w.platformIO.writePacketBatch(frames[:count]))
				if err != nil {
					return err
				}
				clear(frames[:count])
				count = 0
			}
			err := w.transmit(buffer, destinations[index])
			if err != nil {
				return err
			}
			continue
		}
		frame := &frames[count]
		meta, err := w.preparePacketHeader(frame.header[:], buffer.Bytes(), destinations[index], w.checksumOffload)
		if err == errGoFrameDropped {
			continue
		} else if err != nil {
			return err
		}
		frame.length = w.templateLength
		frame.payload = buffer.Bytes()
		frame.meta = meta
		count++
		if count == len(frames) {
			err = goIgnoreDropped(w.platformIO.writePacketBatch(frames[:count]))
			if err != nil {
				return err
			}
			clear(frames[:count])
			count = 0
		}
	}
	if count == 0 {
		return nil
	}
	return goIgnoreDropped(w.platformIO.writePacketBatch(frames[:count]))
}

func (w *GoPacketConn) transmit(buffer *buf.Buffer, destination M.Socksaddr) error {
	payload := buffer.Bytes()
	fragmented := w.templateLength+len(payload) > w.mtu
	meta, err := w.preparePacketHeader(buffer.ExtendHeader(w.templateLength), payload, destination, w.checksumOffload && !fragmented)
	if err != nil {
		if w.ipVersion == 4 && destination.IsIPv6() {
			return E.New("send IPv6 packet to IPv4 connection")
		}
		return goIgnoreDropped(err)
	}
	packet := buffer.Bytes()
	if !fragmented {
		return goIgnoreDropped(w.platformIO.writeFrame([][]byte{packet}, meta))
	}
	var (
		fragments      [][]byte
		fragmentsBuilt bool
	)
	if w.ipVersion == 4 {
		ipHdr := header.IPv4(packet)
		ipHdr.SetID(uint16(w.engine.stack.udpIdentification.Add(1)))
		ipHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		fragments, fragmentsBuilt = fragmentIPv4Packet(ipHdr, uint32(w.mtu))
	} else {
		fragments, fragmentsBuilt = fragmentIPv6Packet(header.IPv6(packet), uint32(w.mtu), w.engine.stack.udpIdentification.Add(1))
	}
	if !fragmentsBuilt {
		return nil
	}
	var writeErr error
	for _, fragment := range fragments {
		writeErr = E.Errors(writeErr, goIgnoreDropped(w.platformIO.writeFrame([][]byte{fragment}, ForwardFrameMeta{})))
	}
	return writeErr
}

func (w *GoPacketConn) HandshakeSuccess() error {
	w.snapshotAccess.Lock()
	w.snapshot = nil
	w.snapshotAccess.Unlock()
	return nil
}

func (w *GoPacketConn) HandshakeFailure(err error) error {
	w.snapshotAccess.Lock()
	snapshot := w.snapshot
	snapshotMeta := w.snapshotMeta
	w.snapshot = nil
	w.snapshotAccess.Unlock()
	if snapshot == nil {
		return os.ErrInvalid
	}
	snapshotMeta.completeChecksum(snapshot)
	reply, ok := BuildUnreachable(snapshot, netip.Addr{}, 0)
	if !ok {
		return nil
	}
	return goIgnoreDropped(w.platformIO.writeFrame([][]byte{reply}, ForwardFrameMeta{}))
}

func (w *GoPacketConn) closeSplice(err error) {
	w.spliceCloseError.CompareAndSwap(nil, &goConnError{err: err})
	w.engine.postMessage(&w.closeMessage)
}

func (w *GoPacketConn) Close() error {
	directory := &w.engine.stack.directory
	if directory.udpFlows != nil {
		directory.access.Lock()
		if directory.udpFlows[w.key] == w {
			delete(directory.udpFlows, w.key)
		}
		directory.access.Unlock()
	}
	if w.splicePending.Load() != nil || w.spliceActive.Load() {
		w.closeSplice(io.ErrClosedPipe)
	}
	return nil
}

func (w *GoPacketConn) CloseFlow() {
	conn := w.conn.Load()
	if conn != nil {
		conn.Close()
	}
}

func (w *GoPacketConn) handleSessionClose(err error) {
	trackerPointer := w.tracker.Load()
	if trackerPointer == nil {
		return
	}
	if !w.trackerClosed.CompareAndSwap(false, true) {
		return
	}
	if err != nil && !E.IsClosedOrCanceled(err) {
		(*trackerPointer).CloseFlow(FlowCloseReset)
	} else {
		(*trackerPointer).CloseFlow(FlowCloseTimeout)
	}
}

var (
	_ N.PacketWriter            = (*GoPacketConn)(nil)
	_ N.FrontHeadroom           = (*GoPacketConn)(nil)
	_ N.HandshakeSuccess        = (*GoPacketConn)(nil)
	_ N.HandshakeFailure        = (*GoPacketConn)(nil)
	_ io.Closer                 = (*GoPacketConn)(nil)
	_ FlowHandle                = (*GoPacketConn)(nil)
	_ N.PacketBatchWriteCreator = (*GoPacketConn)(nil)
	_ N.PacketBatchWriter       = (*GoPacketConn)(nil)
)
