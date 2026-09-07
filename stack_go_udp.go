package tun

import (
	"context"
	"io"
	"net/netip"
	"os"
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

type goUDPUserData struct {
	packet    []byte
	meta      ForwardFrameMeta
	ipVersion uint8
	created   *GoPacketConn
}

func (e *goEngine) demuxUDP(packet []byte, meta ForwardFrameMeta, parsed *forwardPacket) {
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
	userData := &e.udpUserData
	*userData = goUDPUserData{
		packet:    packet,
		meta:      meta,
		ipVersion: parsed.ipVersion,
	}
	conn, ok := e.stack.udpNat.getOrCreateConn(source, destination, userData)
	if !ok {
		return
	}
	if userData.created != nil {
		e.attachUDPSession(conn, userData.created, &parsed.verdict)
		userData.created = nil
	}
	if writer, isNative := conn.writer.(*GoPacketConn); isNative {
		trackerPointer := writer.tracker.Load()
		if trackerPointer != nil {
			(*trackerPointer).CountForward(len(packet))
		}
		if writer.splice != nil {
			e.packetSpliceUpload(writer, payload, destination)
			return
		}
	}
	readWaitOptions := conn.loadReadWaitOptions()
	buffer := readWaitOptions.NewBufferSize(len(payload))
	buffer.Write(payload)
	readWaitOptions.PostReturn(buffer)
	conn.enqueue(buffer, destination)
	e.wokeHandlerThisBurst = true
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
	writer := &GoPacketConn{
		engine:          s.engine,
		platformIO:      s.engine.platformIO,
		mtu:             s.mtu,
		checksumOffload: s.engine.platformIO.transmitChecksumOffload(),
		snapshot:        slices.Clone(data.packet),
		snapshotMeta:    data.meta,
	}
	writer.spliceMessage = goMessage{kind: goMessagePacketSplice, packet: writer}
	writer.closeMessage = goMessage{kind: goMessagePacketClose, packet: writer}
	writer.buildTemplate(data.ipVersion, source)
	data.created = writer
	return true, s.ctx, writer, writer.handleSessionClose
}

var (
	_ N.PacketWriter     = (*GoPacketConn)(nil)
	_ N.FrontHeadroom    = (*GoPacketConn)(nil)
	_ N.HandshakeSuccess = (*GoPacketConn)(nil)
	_ N.HandshakeFailure = (*GoPacketConn)(nil)
	_ io.Closer          = (*GoPacketConn)(nil)
	_ FlowHandle         = (*GoPacketConn)(nil)
)

type GoPacketConn struct {
	engine           *goEngine
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

func (w *GoPacketConn) writeFrame(packet []byte, meta ForwardFrameMeta) error {
	return goIgnoreDropped(w.platformIO.writeFrame([][]byte{packet}, meta))
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

func (w *GoPacketConn) FrontHeadroom() int {
	return w.platformIO.transmitPrefix() + w.templateLength
}

func (w *GoPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.IsIP() {
		buffer.Release()
		return E.Cause(os.ErrInvalid, "invalid destination")
	}
	buffer = (N.ReadWaitOptions{FrontHeadroom: w.templateLength}).Copy(buffer)
	defer buffer.Release()
	return w.transmit(buffer, destination)
}

func (w *GoPacketConn) transmit(buffer *buf.Buffer, destination M.Socksaddr) error {
	if w.ipVersion == 4 {
		if destination.IsIPv6() {
			return E.New("send IPv6 packet to IPv4 connection")
		}
	} else if destination.IsIPv4() {
		destination = M.SocksaddrFrom(netip.AddrFrom16(destination.Addr.As16()), destination.Port)
	}
	payloadLength := buffer.Len()
	maximumPayload := 65535 - header.UDPMinimumSize
	if w.ipVersion == 4 {
		maximumPayload -= header.IPv4MinimumSize
	}
	if payloadLength > maximumPayload {
		return nil
	}
	copy(buffer.ExtendHeader(w.templateLength), w.template[:w.templateLength])
	packet := buffer.Bytes()
	udpLength := uint16(header.UDPMinimumSize + payloadLength)
	var (
		network header.Network
		udpHdr  header.UDP
	)
	if w.ipVersion == 4 {
		ipHdr := header.IPv4(packet)
		ipHdr.SetTotalLength(uint16(len(packet)))
		ipHdr.SetSourceAddr(destination.Addr)
		network = ipHdr
		udpHdr = header.UDP(ipHdr.Payload())
	} else {
		ipHdr := header.IPv6(packet)
		ipHdr.SetPayloadLength(udpLength)
		ipHdr.SetSourceAddr(destination.Addr)
		network = ipHdr
		udpHdr = header.UDP(ipHdr.Payload())
	}
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(udpLength)
	fragmented := len(packet) > w.mtu
	var meta ForwardFrameMeta
	if w.checksumOffload && !fragmented {
		udpHdr.SetChecksum(header.PseudoHeaderChecksum(header.UDPProtocolNumber, network.SourceAddressSlice(), network.DestinationAddressSlice(), udpLength))
		meta.needsChecksum = true
		meta.checksumStart = uint16(w.templateLength - header.UDPMinimumSize)
		meta.checksumOffset = goUDPChecksumOffset
	} else {
		setGoUDPChecksum(network, udpHdr)
	}
	trackerPointer := w.tracker.Load()
	if trackerPointer != nil {
		(*trackerPointer).CountReverse(len(packet))
	}
	if !fragmented {
		if ipHdr, isIPv4 := network.(header.IPv4); isIPv4 {
			ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		}
		return w.writeFrame(packet, meta)
	}
	var (
		fragments [][]byte
		ok        bool
	)
	if w.ipVersion == 4 {
		ipHdr := network.(header.IPv4)
		ipHdr.SetID(uint16(goFragmentIdent.Add(1)))
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		fragments, ok = fragmentIPv4Packet(ipHdr, uint32(w.mtu))
	} else {
		fragments, ok = fragmentIPv6Packet(network.(header.IPv6), uint32(w.mtu), goFragmentIdent.Add(1))
	}
	if !ok {
		return nil
	}
	var writeErr error
	for _, fragment := range fragments {
		writeErr = E.Errors(writeErr, w.writeFrame(fragment, ForwardFrameMeta{}))
	}
	return writeErr
}

var goFragmentIdent atomic.Uint32

const goUDPChecksumOffset = 6

func setGoUDPChecksum(network header.Network, udpHdr header.UDP) {
	udpHdr.SetChecksum(0)
	sum := ^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, network.SourceAddressSlice(), network.DestinationAddressSlice(), udpHdr.Length()),
	))
	if sum == 0 {
		sum = 0xffff
	}
	udpHdr.SetChecksum(sum)
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
