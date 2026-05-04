//go:build with_gvisor

package tun

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/header/parse"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

type ICMPForwarder struct {
	ctx                   context.Context
	stack                 *stack.Stack
	inet4Address          netip.Addr
	inet6Address          netip.Addr
	tleAddr4              netip.Addr
	tleAddr6              netip.Addr
	maxTracerouteHopLimit uint8
	handler               Handler
	mapping               *DirectRouteMapping
	// reverseMapping maps {protocol, port/ident, destination} → original client
	// address for delivering ICMP error responses (TimeExceeded/DstUnreachable)
	// back to the correct TUN client. Covers ICMP echo, UDP, and TCP inner packets.
	reverseMapping freelru.Cache[reverseKey, icmpReverseEntry]
}

// reverseKey identifies an outgoing session by protocol, port (or ICMP ident),
// and destination, for reverse lookup when delivering ICMP errors.
type reverseKey struct {
	Protocol    uint8
	Port        uint16 // ICMP ident, or TCP/UDP source port
	Destination netip.Addr
}

type icmpReverseEntry struct {
	ClientAddr netip.Addr
	BackWriter *ICMPBackWriter
}

func NewICMPForwarder(
	ctx context.Context,
	stack *stack.Stack,
	handler Handler,
	timeout time.Duration,
) *ICMPForwarder {
	reverseMapping := common.Must1(freelru.NewSynced[reverseKey, icmpReverseEntry](
		4096, maphash.NewHasher[reverseKey]().Hash32,
	))
	reverseMapping.SetLifetime(30 * time.Second)
	return &ICMPForwarder{
		ctx:            ctx,
		stack:          stack,
		handler:        handler,
		mapping:        NewDirectRouteMapping(timeout),
		reverseMapping: reverseMapping,
	}
}

func (f *ICMPForwarder) SetLocalAddresses(inet4Address, inet6Address netip.Addr) {
	f.inet4Address = inet4Address
	f.inet6Address = inet6Address
}

func (f *ICMPForwarder) SetTTLDecrement(addr4, addr6 netip.Addr, maxHopLimit uint8) {
	f.tleAddr4 = addr4
	f.tleAddr6 = addr6
	if maxHopLimit == 0 {
		maxHopLimit = defaultMaxTracerouteHopLimit
	}
	f.maxTracerouteHopLimit = maxHopLimit
}

func (f *ICMPForwarder) registerSession(protocol uint8, destination netip.Addr, srcPort uint16, clientAddr netip.Addr, backWriter *ICMPBackWriter) {
	f.reverseMapping.Add(reverseKey{
		Protocol:    protocol,
		Port:        srcPort,
		Destination: destination,
	}, icmpReverseEntry{
		ClientAddr: clientAddr,
		BackWriter: backWriter,
	})
}

func (f *ICMPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
		icmpHdr := header.ICMPv4(pkt.TransportHeader().Slice())
		switch icmpHdr.Type() {
		case header.ICMPv4TimeExceeded, header.ICMPv4DstUnreachable:
			return f.handleICMPError4(pkt)
		case header.ICMPv4Echo:
		default:
			return false
		}
		if icmpHdr.Code() != 0 {
			return false
		}
		sourceAddr := M.AddrFromIP(ipHdr.SourceAddressSlice())
		destinationAddr := M.AddrFromIP(ipHdr.DestinationAddressSlice())
		if destinationAddr != f.inet4Address {
			ttlAct := checkTracerouteTTL(pkt, f.maxTracerouteHopLimit, f.tleAddr4, f.tleAddr6)
			if ttlAct == ttlActionTLE {
				_ = gWriteTimeExceeded(f.stack, pkt, f.tleAddr4, f.tleAddr6)
				return true
			}
			backWriter := &ICMPBackWriter{
				stack:         f.stack,
				packet:        pkt,
				source:        ipHdr.SourceAddress(),
				sourceNetwork: header.IPv4ProtocolNumber,
			}
			action, err := f.mapping.Lookup(DirectRouteSession{Source: sourceAddr, Destination: destinationAddr}, func(timeout time.Duration) (DirectRouteDestination, error) {
				dest, prepErr := f.handler.PrepareConnection(
					N.NetworkICMP,
					M.SocksaddrFrom(sourceAddr, 0),
					M.SocksaddrFrom(destinationAddr, 0),
					backWriter,
					timeout,
				)
				if prepErr == nil && dest != nil {
					f.reverseMapping.Add(reverseKey{
						Protocol:    uint8(header.ICMPv4ProtocolNumber),
						Port:        icmpHdr.Ident(),
						Destination: destinationAddr,
					}, icmpReverseEntry{
						ClientAddr: sourceAddr,
						BackWriter: backWriter,
					})
				}
				return dest, prepErr
			})
			if errors.Is(err, ErrReset) {
				gWriteUnreachable(f.stack, pkt)
				return true
			} else if errors.Is(err, ErrDrop) {
				return true
			}
			if action != nil {
				if ttlAct == ttlActionDecrement {
					_ = directRouteWritePacketWithDecrementedTTL(action, pkt)
				} else {
					_ = directRouteWritePacket(action, pkt)
				}
				return true
			}
		}
		icmpHdr.SetType(header.ICMPv4EchoReply)
		sourceAddress := ipHdr.SourceAddress()
		ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
		ipHdr.SetDestinationAddress(sourceAddress)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], pkt.Data().Checksum()))
		ipHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		outgoingEP, gErr := f.stack.GetNetworkEndpoint(DefaultNIC, header.IPv4ProtocolNumber)
		if gErr != nil {
			// TODO: log error
			return true
		}
		route, gErr := f.stack.FindRoute(
			DefaultNIC,
			id.LocalAddress,
			id.RemoteAddress,
			header.IPv4ProtocolNumber,
			false,
		)
		if gErr != nil {
			// TODO: log error
			return true
		}
		defer route.Release()
		outgoingEP.(ipv4.ExportedEndpoint).WritePacketDirect(route, pkt)
		return true
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Slice())
		icmpHdr := header.ICMPv6(pkt.TransportHeader().Slice())
		switch icmpHdr.Type() {
		case header.ICMPv6TimeExceeded, header.ICMPv6DstUnreachable:
			return f.handleICMPError6(pkt)
		case header.ICMPv6EchoRequest:
		default:
			return false
		}
		if icmpHdr.Code() != 0 {
			return false
		}
		sourceAddr := M.AddrFromIP(ipHdr.SourceAddressSlice())
		destinationAddr := M.AddrFromIP(ipHdr.DestinationAddressSlice())
		if destinationAddr != f.inet6Address {
			ttlAct := checkTracerouteTTL(pkt, f.maxTracerouteHopLimit, f.tleAddr4, f.tleAddr6)
			if ttlAct == ttlActionTLE {
				_ = gWriteTimeExceeded(f.stack, pkt, f.tleAddr4, f.tleAddr6)
				return true
			}
			backWriter := &ICMPBackWriter{
				stack:         f.stack,
				packet:        pkt,
				source:        ipHdr.SourceAddress(),
				sourceNetwork: header.IPv6ProtocolNumber,
			}
			action, err := f.mapping.Lookup(DirectRouteSession{Source: sourceAddr, Destination: destinationAddr}, func(timeout time.Duration) (DirectRouteDestination, error) {
				dest, prepErr := f.handler.PrepareConnection(
					N.NetworkICMP,
					M.SocksaddrFrom(sourceAddr, 0),
					M.SocksaddrFrom(destinationAddr, 0),
					backWriter,
					timeout,
				)
				if prepErr == nil && dest != nil {
					f.reverseMapping.Add(reverseKey{
						Protocol:    uint8(header.ICMPv6ProtocolNumber),
						Port:        icmpHdr.Ident(),
						Destination: destinationAddr,
					}, icmpReverseEntry{
						ClientAddr: sourceAddr,
						BackWriter: backWriter,
					})
				}
				return dest, prepErr
			})
			if errors.Is(err, ErrReset) {
				gWriteUnreachable(f.stack, pkt)
				return true
			} else if errors.Is(err, ErrDrop) {
				return true
			}
			if action != nil {
				if ttlAct == ttlActionDecrement {
					_ = directRouteWritePacketWithDecrementedTTL(action, pkt)
				} else {
					pkt.IncRef()
					_ = directRouteWritePacket(action, pkt)
				}
				return true
			}
		}
		icmpHdr.SetType(header.ICMPv6EchoReply)
		sourceAddress := ipHdr.SourceAddress()
		ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
		ipHdr.SetDestinationAddress(sourceAddress)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHdr,
			Src:         ipHdr.SourceAddress(),
			Dst:         ipHdr.DestinationAddress(),
			PayloadCsum: pkt.Data().Checksum(),
			PayloadLen:  pkt.Data().Size(),
		}))
		outgoingEP, gErr := f.stack.GetNetworkEndpoint(DefaultNIC, header.IPv6ProtocolNumber)
		if gErr != nil {
			// TODO: log error
			return true
		}
		route, gErr := f.stack.FindRoute(
			DefaultNIC,
			id.LocalAddress,
			id.RemoteAddress,
			header.IPv6ProtocolNumber,
			false,
		)
		if gErr != nil {
			// TODO: log error
			return true
		}
		defer route.Release()
		outgoingEP.(ipv6.ExportedEndpoint).WritePacketDirect(route, pkt)
		return true
	}
}

type ICMPBackWriter struct {
	access        sync.Mutex
	stack         *stack.Stack
	packet        *stack.PacketBuffer
	source        tcpip.Address
	sourceNetwork tcpip.NetworkProtocolNumber
}

func (w *ICMPBackWriter) WritePacket(p []byte) error {
	var srcAddr tcpip.Address
	if w.sourceNetwork == header.IPv4ProtocolNumber {
		srcAddr = header.IPv4(p).SourceAddress()
	} else {
		srcAddr = header.IPv6(p).SourceAddress()
	}
	route, err := w.stack.FindRoute(
		DefaultNIC,
		srcAddr,
		w.source,
		w.sourceNetwork,
		false,
	)
	if err != nil {
		return gonet.TranslateNetstackError(err)
	}
	defer route.Release()
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(p),
	})
	defer packet.DecRef()
	if w.sourceNetwork == header.IPv4ProtocolNumber {
		parse.IPv4(packet)
	} else {
		parse.IPv6(packet)
	}
	return gonet.TranslateNetstackError(route.WritePacketDirect(packet))
}

// resolveInnerProtocol looks up the reverse mapping for the inner packet's
// protocol, port/ident, and destination. icmpProto is the ICMP protocol
// number for the address family (ICMPv4 or ICMPv6).
func (f *ICMPForwarder) resolveInnerProtocol(
	icmpProto uint8,
	innerProto uint8,
	innerPayloadLen uint16,
	innerPayload []byte,
	innerDst netip.Addr,
) (icmpReverseEntry, bool) {
	var minSize int
	switch innerProto {
	case icmpProto:
		minSize = header.ICMPv4MinimumSize
	case uint8(header.UDPProtocolNumber):
		minSize = header.UDPMinimumSize
	case uint8(header.TCPProtocolNumber):
		minSize = header.TCPMinimumSize
	default:
		return icmpReverseEntry{}, false
	}
	if innerPayloadLen < uint16(minSize) {
		return icmpReverseEntry{}, false
	}
	var port uint16
	if innerProto == icmpProto {
		port = header.ICMPv4(innerPayload).Ident() // offset 4
	} else {
		port = header.UDP(innerPayload).SourcePort() // offset 0 (same for TCP)
	}
	return f.reverseMapping.Get(reverseKey{
		Protocol:    innerProto,
		Port:        port,
		Destination: innerDst,
	})
}

func (f *ICMPForwarder) handleICMPError4(pkt *stack.PacketBuffer) bool {
	transportHdr := pkt.TransportHeader().Slice()
	dataSlice := pkt.Data().AsRange().ToSlice()
	payload := make([]byte, len(transportHdr)+len(dataSlice))
	copy(payload, transportHdr)
	copy(payload[len(transportHdr):], dataSlice)
	if len(payload) < header.ICMPv4MinimumSize+header.IPv4MinimumSize {
		return false
	}
	innerIPHdr := header.IPv4(payload[header.ICMPv4MinimumSize:])
	if !innerIPHdr.IsValid(len(payload) - header.ICMPv4MinimumSize) {
		return false
	}
	innerDst := M.AddrFromIP(innerIPHdr.DestinationAddressSlice())
	entry, found := f.resolveInnerProtocol(
		uint8(header.ICMPv4ProtocolNumber),
		innerIPHdr.Protocol(),
		innerIPHdr.PayloadLength(),
		innerIPHdr.Payload(),
		innerDst,
	)
	if !found {
		return false
	}
	networkHdr := pkt.NetworkHeader().Slice()
	errPacket := make([]byte, len(networkHdr)+len(payload))
	copy(errPacket, networkHdr)
	copy(errPacket[len(networkHdr):], payload)
	outerIPHdr := header.IPv4(errPacket)
	outerIPHdr.SetDestinationAddress(tcpip.AddrFrom4(entry.ClientAddr.As4()))
	innerOffset := len(networkHdr) + header.ICMPv4MinimumSize
	innerIP := header.IPv4(errPacket[innerOffset:])
	innerIP.SetSourceAddress(tcpip.AddrFrom4(entry.ClientAddr.As4()))
	innerIP.SetChecksum(0)
	innerIP.SetChecksum(^innerIP.CalculateChecksum())
	outerIPHdr.SetChecksum(0)
	outerIPHdr.SetChecksum(^outerIPHdr.CalculateChecksum())
	outerICMP := header.ICMPv4(errPacket[outerIPHdr.HeaderLength():])
	outerICMP.SetChecksum(0)
	outerICMP.SetChecksum(header.ICMPv4Checksum(outerICMP, 0))
	return entry.BackWriter.WritePacket(errPacket) == nil
}

func (f *ICMPForwarder) handleICMPError6(pkt *stack.PacketBuffer) bool {
	transportHdr := pkt.TransportHeader().Slice()
	dataSlice := pkt.Data().AsRange().ToSlice()
	payload := make([]byte, len(transportHdr)+len(dataSlice))
	copy(payload, transportHdr)
	copy(payload[len(transportHdr):], dataSlice)
	if len(payload) < header.ICMPv6MinimumSize+header.IPv6MinimumSize {
		return false
	}
	innerIPHdr := header.IPv6(payload[header.ICMPv6MinimumSize:])
	if !innerIPHdr.IsValid(len(payload) - header.ICMPv6MinimumSize) {
		return false
	}
	innerDst := M.AddrFromIP(innerIPHdr.DestinationAddressSlice())
	entry, found := f.resolveInnerProtocol(
		uint8(header.ICMPv6ProtocolNumber),
		uint8(innerIPHdr.TransportProtocol()),
		innerIPHdr.PayloadLength(),
		innerIPHdr.Payload(),
		innerDst,
	)
	if !found {
		return false
	}
	networkHdr := pkt.NetworkHeader().Slice()
	errPacket := make([]byte, len(networkHdr)+len(payload))
	copy(errPacket, networkHdr)
	copy(errPacket[len(networkHdr):], payload)
	outerIPHdr := header.IPv6(errPacket)
	clientAddr16 := entry.ClientAddr.As16()
	outerIPHdr.SetDestinationAddress(tcpip.AddrFrom16(clientAddr16))
	innerOffset := len(networkHdr) + header.ICMPv6MinimumSize
	innerIP := header.IPv6(errPacket[innerOffset:])
	innerIP.SetSourceAddress(tcpip.AddrFrom16(clientAddr16))
	// Recalculate inner transport checksum if it's ICMPv6
	if innerIP.TransportProtocol() == header.ICMPv6ProtocolNumber && innerIP.PayloadLength() >= header.ICMPv6MinimumSize {
		innerICMP := header.ICMPv6(innerIP.Payload())
		innerICMP.SetChecksum(0)
		innerICMP.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: innerICMP,
			Src:    innerIP.SourceAddress(),
			Dst:    innerIP.DestinationAddress(),
		}))
	}
	outerICMP := header.ICMPv6(errPacket[header.IPv6MinimumSize:])
	outerICMP.SetChecksum(0)
	outerICMP.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: outerICMP,
		Src:    outerIPHdr.SourceAddress(),
		Dst:    outerIPHdr.DestinationAddress(),
	}))
	return entry.BackWriter.WritePacket(errPacket) == nil
}
