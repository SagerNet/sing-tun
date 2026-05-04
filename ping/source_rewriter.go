package ping

import (
	"context"
	"net/netip"
	"sync"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
)

// sourceKey identifies an outgoing session by protocol, port (or ICMP ident),
// and destination, for reverse lookup when rewriting ICMP errors or echo replies.
type sourceKey struct {
	Protocol    uint8
	Port        uint16 // ICMP ident, or TCP/UDP source port
	Destination netip.Addr
}

type SourceRewriter struct {
	ctx    context.Context
	logger logger.ContextLogger
	access sync.RWMutex
	// sessions tracks active DirectRoute sessions for routing writeback packets.
	sessions map[tun.DirectRouteSession]tun.DirectRouteContext
	// sourceAddress maps {protocol, port/ident, destination} → original client
	// address, used to rewrite ICMP echo replies and error destinations back
	// to the TUN client. Covers ICMP, UDP, and TCP inner packets.
	sourceAddress map[sourceKey]netip.Addr
	inet4Address  netip.Addr
	inet6Address  netip.Addr
}

func NewSourceRewriter(ctx context.Context, logger logger.ContextLogger, inet4Address netip.Addr, inet6Address netip.Addr) *SourceRewriter {
	return &SourceRewriter{
		ctx:           ctx,
		logger:        logger,
		sessions:      make(map[tun.DirectRouteSession]tun.DirectRouteContext),
		sourceAddress: make(map[sourceKey]netip.Addr),
		inet4Address:  inet4Address,
		inet6Address:  inet6Address,
	}
}

func (m *SourceRewriter) CreateSession(session tun.DirectRouteSession, context tun.DirectRouteContext) {
	m.access.Lock()
	m.sessions[session] = context
	m.access.Unlock()
}

func (m *SourceRewriter) DeleteSession(session tun.DirectRouteSession) {
	m.access.Lock()
	delete(m.sessions, session)
	m.access.Unlock()
}

func (m *SourceRewriter) RewritePacket(packet []byte) {
	var ipHdr header.Network
	var bindAddr netip.Addr
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr = header.IPv4(packet)
		bindAddr = m.inet4Address
	case header.IPv6Version:
		ipHdr = header.IPv6(packet)
		bindAddr = m.inet6Address
	default:
		return
	}
	sourceAddr := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(bindAddr)
	if ipHdr4, isIPv4 := ipHdr.(header.IPv4); isIPv4 {
		ipHdr4.SetChecksum(^ipHdr4.CalculateChecksum())
	}
	switch ipHdr.TransportProtocol() {
	case header.ICMPv4ProtocolNumber:
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		m.access.Lock()
		m.sourceAddress[sourceKey{Protocol: uint8(header.ICMPv4ProtocolNumber), Port: icmpHdr.Ident(), Destination: ipHdr.DestinationAddr()}] = sourceAddr
		m.access.Unlock()
		m.logger.TraceContext(m.ctx, "write ICMPv4 echo request from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
	case header.ICMPv6ProtocolNumber:
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmpHdr,
			Src:    ipHdr.SourceAddressSlice(),
			Dst:    ipHdr.DestinationAddressSlice(),
		}))
		m.access.Lock()
		m.sourceAddress[sourceKey{Protocol: uint8(header.ICMPv6ProtocolNumber), Port: icmpHdr.Ident(), Destination: ipHdr.DestinationAddr()}] = sourceAddr
		m.access.Unlock()
		m.logger.TraceContext(m.ctx, "write ICMPv6 echo request from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
	case header.UDPProtocolNumber:
		if len(ipHdr.Payload()) >= header.UDPMinimumSize {
			udpHdr := header.UDP(ipHdr.Payload())
			m.access.Lock()
			m.sourceAddress[sourceKey{Protocol: uint8(header.UDPProtocolNumber), Port: udpHdr.SourcePort(), Destination: ipHdr.DestinationAddr()}] = sourceAddr
			m.access.Unlock()
		}
	case header.TCPProtocolNumber:
		if len(ipHdr.Payload()) >= header.TCPMinimumSize {
			tcpHdr := header.TCP(ipHdr.Payload())
			m.access.Lock()
			m.sourceAddress[sourceKey{Protocol: uint8(header.TCPProtocolNumber), Port: tcpHdr.SourcePort(), Destination: ipHdr.DestinationAddr()}] = sourceAddr
			m.access.Unlock()
		}
	}
}

// resolveInnerSource looks up the original client address from the inner
// transport header of an ICMP error. Returns the source address and true
// if found.
func (m *SourceRewriter) resolveInnerSource(
	innerProto uint8,
	innerPayloadLen uint16,
	innerPayload []byte,
	innerDst netip.Addr,
) (netip.Addr, bool) {
	var minSize int
	switch innerProto {
	case uint8(header.ICMPv4ProtocolNumber), uint8(header.ICMPv6ProtocolNumber):
		minSize = header.ICMPv4MinimumSize
	case uint8(header.UDPProtocolNumber):
		minSize = header.UDPMinimumSize
	case uint8(header.TCPProtocolNumber):
		minSize = header.TCPMinimumSize
	default:
		return netip.Addr{}, false
	}
	if innerPayloadLen < uint16(minSize) {
		return netip.Addr{}, false
	}
	var port uint16
	switch innerProto {
	case uint8(header.ICMPv4ProtocolNumber), uint8(header.ICMPv6ProtocolNumber):
		port = header.ICMPv4(innerPayload).Ident() // offset 4
	default:
		port = header.UDP(innerPayload).SourcePort() // offset 0 (same for TCP)
	}
	key := sourceKey{Protocol: innerProto, Port: port, Destination: innerDst}
	m.access.RLock()
	source, loaded := m.sourceAddress[key]
	m.access.RUnlock()
	return source, loaded
}

func (m *SourceRewriter) WriteBack(packet []byte) (bool, error) {
	var ipHdr header.Network
	var routeSession tun.DirectRouteSession
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr = header.IPv4(packet)
		routeSession.Destination = ipHdr.SourceAddr()
	case header.IPv6Version:
		ipHdr = header.IPv6(packet)
		routeSession.Destination = ipHdr.SourceAddr()
	default:
		return false, nil
	}
	var echoKey sourceKey
	var isEchoReply bool
	var resolvedSource netip.Addr
	switch ipHdr.TransportProtocol() {
	case header.ICMPv4ProtocolNumber:
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		switch icmpHdr.Type() {
		case header.ICMPv4EchoReply:
			echoKey = sourceKey{Protocol: uint8(header.ICMPv4ProtocolNumber), Port: icmpHdr.Ident(), Destination: ipHdr.SourceAddr()}
			isEchoReply = true
		case header.ICMPv4TimeExceeded, header.ICMPv4DstUnreachable:
			if len(ipHdr.Payload()) < header.ICMPv4MinimumSize+header.IPv4MinimumSize {
				return false, nil
			}
			innerIPHdr := header.IPv4(ipHdr.Payload()[header.ICMPv4MinimumSize:])
			if !innerIPHdr.IsValid(len(ipHdr.Payload()) - header.ICMPv4MinimumSize) {
				return false, nil
			}
			routeSession.Destination = innerIPHdr.DestinationAddr()
			source, loaded := m.resolveInnerSource(
				uint8(innerIPHdr.TransportProtocol()),
				innerIPHdr.PayloadLength(),
				innerIPHdr.Payload(),
				innerIPHdr.DestinationAddr(),
			)
			if !loaded {
				if innerIPHdr.TransportProtocol() == header.ICMPv4ProtocolNumber {
					// ICMP echo errors are optional — don't abort
					break
				}
				return false, nil
			}
			innerIPHdr.SetSourceAddr(source)
			innerIPHdr.SetChecksum(^innerIPHdr.CalculateChecksum())
			icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
			resolvedSource = source
		default:
			return false, nil
		}
	case header.ICMPv6ProtocolNumber:
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		switch icmpHdr.Type() {
		case header.ICMPv6EchoReply:
			echoKey = sourceKey{Protocol: uint8(header.ICMPv6ProtocolNumber), Port: icmpHdr.Ident(), Destination: ipHdr.SourceAddr()}
			isEchoReply = true
		case header.ICMPv6TimeExceeded, header.ICMPv6DstUnreachable:
			if len(ipHdr.Payload()) < header.ICMPv6MinimumSize+header.IPv6MinimumSize {
				return false, nil
			}
			innerIPHdr := header.IPv6(ipHdr.Payload()[header.ICMPv6MinimumSize:])
			if !innerIPHdr.IsValid(len(ipHdr.Payload()) - header.ICMPv6MinimumSize) {
				return false, nil
			}
			routeSession.Destination = innerIPHdr.DestinationAddr()
			source, loaded := m.resolveInnerSource(
				uint8(innerIPHdr.TransportProtocol()),
				innerIPHdr.PayloadLength(),
				innerIPHdr.Payload(),
				innerIPHdr.DestinationAddr(),
			)
			if !loaded {
				if innerIPHdr.TransportProtocol() == header.ICMPv6ProtocolNumber {
					break
				}
				return false, nil
			}
			innerIPHdr.SetSourceAddr(source)
			if innerIPHdr.TransportProtocol() == header.ICMPv6ProtocolNumber {
				innerICMPHdr := header.ICMPv6(innerIPHdr.Payload())
				innerICMPHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
					Header: innerICMPHdr,
					Src:    innerIPHdr.SourceAddressSlice(),
					Dst:    innerIPHdr.DestinationAddressSlice(),
				}))
			}
			resolvedSource = source
		default:
			return false, nil
		}
	default:
		return false, nil
	}
	var source netip.Addr
	if resolvedSource.IsValid() {
		source = resolvedSource
	} else {
		var loaded bool
		m.access.RLock()
		source, loaded = m.sourceAddress[echoKey]
		m.access.RUnlock()
		if !loaded {
			return false, nil
		}
		// Only delete the mapping for EchoReply, not for error messages
		// (multiple errors may arrive for the same ident, e.g. traceroute)
		if isEchoReply {
			m.access.Lock()
			delete(m.sourceAddress, echoKey)
			m.access.Unlock()
		}
	}
	routeSession.Source = source
	m.access.RLock()
	context, loaded := m.sessions[routeSession]
	m.access.RUnlock()
	if !loaded {
		return false, nil
	}
	ipHdr.SetDestinationAddr(routeSession.Source)
	if ipHdr4, isIPv4 := ipHdr.(header.IPv4); isIPv4 {
		ipHdr4.SetChecksum(^ipHdr4.CalculateChecksum())
	}
	switch ipHdr.TransportProtocol() {
	case header.ICMPv4ProtocolNumber:
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		switch icmpHdr.Type() {
		case header.ICMPv4EchoReply:
			m.logger.TraceContext(m.ctx, "read ICMPv4 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
		case header.ICMPv4TimeExceeded, header.ICMPv4DstUnreachable:
			m.logger.TraceContext(m.ctx, "read ICMPv4 error type ", uint8(icmpHdr.Type()), " from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr())
		}
	case header.ICMPv6ProtocolNumber:
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmpHdr,
			Src:    ipHdr.SourceAddressSlice(),
			Dst:    ipHdr.DestinationAddressSlice(),
		}))
		switch icmpHdr.Type() {
		case header.ICMPv6EchoReply:
			m.logger.TraceContext(m.ctx, "read ICMPv6 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
		case header.ICMPv6TimeExceeded, header.ICMPv6DstUnreachable:
			m.logger.TraceContext(m.ctx, "read ICMPv6 error type ", uint8(icmpHdr.Type()), " from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr())
		}
	}
	return true, context.WritePacket(packet)
}
