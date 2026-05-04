//go:build with_gvisor

package tun

import (
	"net/netip"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	buf "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// WrapTCPHandlerWithDirectRoute wraps an existing gVisor TCP transport handler
// with DirectRoute support for traceroute. Low-TTL SYN packets are handled via
// DirectRoute (sending ICMP Time Exceeded), while all other packets are passed
// to the original handler.
//
// localAddr4/localAddr6 are the node's own addresses used as the source IP
// in ICMP Time Exceeded messages. If zero, TTL=1 packets fall through to
// the original handler.
func WrapTCPHandlerWithDirectRoute(
	ipStack *stack.Stack,
	handler Handler,
	icmpForwarder *ICMPForwarder,
	timeout time.Duration,
	maxTracerouteHopLimit uint8,
	localAddr4 netip.Addr,
	localAddr6 netip.Addr,
	original func(stack.TransportEndpointID, *stack.PacketBuffer) bool,
) func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	if maxTracerouteHopLimit == 0 {
		maxTracerouteHopLimit = defaultMaxTracerouteHopLimit
	}
	w := &directRouteTCPWrapper{
		stack:                 ipStack,
		handler:               handler,
		icmpForwarder:         icmpForwarder,
		directRouteMapping:    NewDirectRouteMapping(timeout),
		maxTracerouteHopLimit: maxTracerouteHopLimit,
		localAddr4:            localAddr4,
		localAddr6:            localAddr6,
		original:              original,
	}
	return w.HandlePacket
}

type directRouteTCPWrapper struct {
	stack                 *stack.Stack
	handler               Handler
	icmpForwarder         *ICMPForwarder
	directRouteMapping    *DirectRouteMapping
	maxTracerouteHopLimit uint8
	localAddr4            netip.Addr
	localAddr6            netip.Addr
	original              func(stack.TransportEndpointID, *stack.PacketBuffer) bool
}

func (w *directRouteTCPWrapper) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	// Only intercept SYN packets (no ACK) with low TTL/HopLimit.
	tcpHdr := header.TCP(pkt.TransportHeader().Slice())
	if tcpHdr.Flags()&header.TCPFlagSyn == 0 || tcpHdr.Flags()&header.TCPFlagAck != 0 {
		return w.original(id, pkt)
	}

	ttlAct := checkTracerouteTTL(pkt, w.maxTracerouteHopLimit, w.localAddr4, w.localAddr6)
	if ttlAct == ttlActionPass {
		return w.original(id, pkt)
	}
	if ttlAct == ttlActionTLE {
		_ = gWriteTimeExceeded(w.stack, pkt, w.localAddr4, w.localAddr6)
		return true
	}

	// ttlActionDecrement or ttlActionForward: forward via DirectRoute
	source := M.SocksaddrFrom(AddrFromAddress(id.RemoteAddress), id.RemotePort)
	destination := M.SocksaddrFrom(AddrFromAddress(id.LocalAddress), id.LocalPort)

	var sourceNetwork tcpip.NetworkProtocolNumber
	if source.Addr.Is4() {
		sourceNetwork = header.IPv4ProtocolNumber
	} else {
		sourceNetwork = header.IPv6ProtocolNumber
	}
	backWriter := &ICMPBackWriter{
		stack:         w.stack,
		packet:        pkt,
		source:        AddressFromAddr(source.Addr),
		sourceNetwork: sourceNetwork,
	}
	if action, err := w.directRouteMapping.Lookup(
		DirectRouteSession{Source: source.Addr, Destination: destination.Addr},
		func(timeout time.Duration) (DirectRouteDestination, error) {
			return w.handler.PrepareConnection(N.NetworkTCP, source, destination, backWriter, timeout)
		},
	); err == nil && action != nil {
		if w.icmpForwarder != nil {
			w.icmpForwarder.registerSession(uint8(header.TCPProtocolNumber), destination.Addr, source.Port, source.Addr, backWriter)
		}
		if ttlAct == ttlActionDecrement {
			_ = directRouteWritePacketWithDecrementedTTL(action, pkt)
		} else {
			_ = directRouteWritePacket(action, pkt)
		}
		return true
	}

	return w.original(id, pkt)
}

// WrapUDPHandlerWithDirectRoute wraps an existing gVisor UDP transport handler
// with DirectRoute support for traceroute. Low-TTL packets are handled via
// DirectRoute (sending ICMP Time Exceeded), while all other packets are passed
// to the original handler.
func WrapUDPHandlerWithDirectRoute(
	ipStack *stack.Stack,
	handler Handler,
	icmpForwarder *ICMPForwarder,
	timeout time.Duration,
	maxTracerouteHopLimit uint8,
	localAddr4 netip.Addr,
	localAddr6 netip.Addr,
	original func(stack.TransportEndpointID, *stack.PacketBuffer) bool,
) func(stack.TransportEndpointID, *stack.PacketBuffer) bool {
	if maxTracerouteHopLimit == 0 {
		maxTracerouteHopLimit = defaultMaxTracerouteHopLimit
	}
	w := &directRouteUDPWrapper{
		stack:                 ipStack,
		handler:               handler,
		icmpForwarder:         icmpForwarder,
		directRouteMapping:    NewDirectRouteMapping(timeout),
		maxTracerouteHopLimit: maxTracerouteHopLimit,
		localAddr4:            localAddr4,
		localAddr6:            localAddr6,
		original:              original,
	}
	return w.HandlePacket
}

type directRouteUDPWrapper struct {
	stack                 *stack.Stack
	handler               Handler
	icmpForwarder         *ICMPForwarder
	directRouteMapping    *DirectRouteMapping
	maxTracerouteHopLimit uint8
	localAddr4            netip.Addr
	localAddr6            netip.Addr
	original              func(stack.TransportEndpointID, *stack.PacketBuffer) bool
}

func (w *directRouteUDPWrapper) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	ttlAct := checkTracerouteTTL(pkt, w.maxTracerouteHopLimit, w.localAddr4, w.localAddr6)
	if ttlAct == ttlActionPass {
		return w.original(id, pkt)
	}
	if ttlAct == ttlActionTLE {
		_ = gWriteTimeExceeded(w.stack, pkt, w.localAddr4, w.localAddr6)
		return true
	}

	// ttlActionDecrement or ttlActionForward: forward via DirectRoute
	source := M.SocksaddrFrom(AddrFromAddress(id.RemoteAddress), id.RemotePort)
	destination := M.SocksaddrFrom(AddrFromAddress(id.LocalAddress), id.LocalPort)

	var sourceNetwork tcpip.NetworkProtocolNumber
	if source.Addr.Is4() {
		sourceNetwork = header.IPv4ProtocolNumber
	} else {
		sourceNetwork = header.IPv6ProtocolNumber
	}
	backWriter := &ICMPBackWriter{
		stack:         w.stack,
		packet:        pkt,
		source:        AddressFromAddr(source.Addr),
		sourceNetwork: sourceNetwork,
	}
	if action, err := w.directRouteMapping.Lookup(
		DirectRouteSession{Source: source.Addr, Destination: destination.Addr},
		func(timeout time.Duration) (DirectRouteDestination, error) {
			return w.handler.PrepareConnection(N.NetworkUDP, source, destination, backWriter, timeout)
		},
	); err == nil && action != nil {
		if w.icmpForwarder != nil {
			w.icmpForwarder.registerSession(uint8(header.UDPProtocolNumber), destination.Addr, source.Port, source.Addr, backWriter)
		}
		if ttlAct == ttlActionDecrement {
			_ = directRouteWritePacketWithDecrementedTTL(action, pkt)
		} else {
			_ = directRouteWritePacket(action, pkt)
		}
		return true
	}

	return w.original(id, pkt)
}

// ttlAction describes what to do with a packet based on its TTL/HopLimit.
type ttlAction int

const (
	ttlActionPass      ttlAction = iota // Not traceroute (TTL=0 or >= maxHopLimit)
	ttlActionForward                    // Forward via DirectRoute with original TTL (no local address)
	ttlActionTLE                        // Generate ICMP Time Exceeded (TTL=1, has local address)
	ttlActionDecrement                  // Forward via DirectRoute with TTL-1 (TTL>1, has local address)
)

// checkTracerouteTTL inspects a packet's TTL/HopLimit and determines
// the appropriate action for traceroute support.
func checkTracerouteTTL(pkt *stack.PacketBuffer, maxHopLimit uint8, tleAddr4, tleAddr6 netip.Addr) ttlAction {
	var hopLimit uint8
	var isIPv4 bool
	switch ipHdr := pkt.Network().(type) {
	case header.IPv4:
		hopLimit = ipHdr.TTL()
		isIPv4 = true
	case header.IPv6:
		hopLimit = ipHdr.HopLimit()
	}
	if hopLimit == 0 || hopLimit >= maxHopLimit {
		return ttlActionPass
	}
	hasTLEAddr := isIPv4 && tleAddr4.IsValid() || !isIPv4 && tleAddr6.IsValid()
	if !hasTLEAddr {
		return ttlActionForward
	}
	if hopLimit == 1 {
		return ttlActionTLE
	}
	return ttlActionDecrement
}

// directRouteWritePacketWithDecrementedTTL copies the packet, decrements
// TTL/HopLimit by 1, updates the IPv4 header checksum, and forwards via
// DirectRoute.
func directRouteWritePacketWithDecrementedTTL(action DirectRouteDestination, packetBuffer *stack.PacketBuffer) error {
	networkHdr := make([]byte, len(packetBuffer.NetworkHeader().Slice()))
	copy(networkHdr, packetBuffer.NetworkHeader().Slice())

	switch packetBuffer.Network().(type) {
	case header.IPv4:
		ipHdr := header.IPv4(networkHdr)
		ipHdr.SetTTL(ipHdr.TTL() - 1)
		ipHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	case header.IPv6:
		ipHdr := header.IPv6(networkHdr)
		ipHdr.SetHopLimit(ipHdr.HopLimit() - 1)
	}

	packetSlice := networkHdr
	packetSlice = append(packetSlice, packetBuffer.TransportHeader().Slice()...)
	packetSlice = append(packetSlice, packetBuffer.Data().AsRange().ToSlice()...)
	return action.WritePacket(buf.As(packetSlice).ToOwned())
}

// gWriteTimeExceeded constructs and injects an ICMP Time Exceeded message
// back into the gVisor stack, making this node appear as a hop in traceroute.
func gWriteTimeExceeded(ipStack *stack.Stack, pkt *stack.PacketBuffer, localAddr4, localAddr6 netip.Addr) error {
	origNetwork := pkt.NetworkHeader().Slice()
	origTransport := pkt.TransportHeader().Slice()
	origData := pkt.Data().AsRange().ToSlice()

	switch pkt.Network().(type) {
	case header.IPv4:
		return gWriteTimeExceeded4(ipStack, origNetwork, origTransport, origData, AddressFromAddr(localAddr4))
	case header.IPv6:
		return gWriteTimeExceeded6(ipStack, origNetwork, origTransport, origData, AddressFromAddr(localAddr6))
	}
	return nil
}

func gWriteTimeExceeded4(ipStack *stack.Stack, origNetwork, origTransport, origData []byte, localAddr tcpip.Address) error {
	clientAddr := header.IPv4(origNetwork).SourceAddress()

	// RFC 1812: include as much of original packet as possible, up to 576 bytes total
	maxPayload := 576 - header.IPv4MinimumSize - header.ICMPv4MinimumSize
	payload := buildICMPErrorPayload(origNetwork, origTransport, origData, maxPayload)

	route, gErr := ipStack.FindRoute(DefaultNIC, localAddr, clientAddr, header.IPv4ProtocolNumber, false)
	if gErr != nil {
		return gonet.TranslateNetstackError(gErr)
	}
	defer route.Release()

	// Build ICMP packet using gVisor's PacketBuffer API (same as gVisor's internal ICMP sending)
	icmpPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv4MinimumSize,
		Payload:            buffer.MakeWithData(payload),
	})
	defer icmpPkt.DecRef()

	icmpPkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber
	icmpHdr := header.ICMPv4(icmpPkt.TransportHeader().Push(header.ICMPv4MinimumSize))
	icmpHdr.SetType(header.ICMPv4TimeExceeded)
	icmpHdr.SetCode(header.ICMPv4TTLExceeded)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, icmpPkt.Data().Checksum()))

	return gonet.TranslateNetstackError(route.WritePacket(
		stack.NetworkHeaderParams{
			Protocol: header.ICMPv4ProtocolNumber,
			TTL:      route.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		},
		icmpPkt,
	))
}

func gWriteTimeExceeded6(ipStack *stack.Stack, origNetwork, origTransport, origData []byte, localAddr tcpip.Address) error {
	clientAddr := header.IPv6(origNetwork).SourceAddress()

	// RFC 4443: include as much of invoking packet as possible, up to minimum IPv6 MTU
	maxPayload := 1280 - header.IPv6MinimumSize - header.ICMPv6MinimumSize
	payload := buildICMPErrorPayload(origNetwork, origTransport, origData, maxPayload)

	route, gErr := ipStack.FindRoute(DefaultNIC, localAddr, clientAddr, header.IPv6ProtocolNumber, false)
	if gErr != nil {
		return gonet.TranslateNetstackError(gErr)
	}
	defer route.Release()

	// Build ICMPv6 packet using gVisor's PacketBuffer API
	icmpPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.ICMPv6MinimumSize,
		Payload:            buffer.MakeWithData(payload),
	})
	defer icmpPkt.DecRef()

	icmpPkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
	icmpHdr := header.ICMPv6(icmpPkt.TransportHeader().Push(header.ICMPv6MinimumSize))
	icmpHdr.SetType(header.ICMPv6TimeExceeded)
	icmpHdr.SetCode(header.ICMPv6HopLimitExceeded)

	pktData := icmpPkt.Data()
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHdr,
		Src:         route.LocalAddress(),
		Dst:         route.RemoteAddress(),
		PayloadCsum: pktData.Checksum(),
		PayloadLen:  pktData.Size(),
	}))

	return gonet.TranslateNetstackError(route.WritePacket(
		stack.NetworkHeaderParams{
			Protocol: header.ICMPv6ProtocolNumber,
			TTL:      route.DefaultTTL(),
			TOS:      stack.DefaultTOS,
		},
		icmpPkt,
	))
}

func buildICMPErrorPayload(origNetwork, origTransport, origData []byte, maxLen int) []byte {
	var payload []byte
	payload = append(payload, origNetwork...)
	payload = append(payload, origTransport...)
	payload = append(payload, origData...)
	if len(payload) > maxLen {
		payload = payload[:maxLen]
	}
	return payload
}
