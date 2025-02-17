package tun

import (
	"net/netip"
	"sync"

	"github.com/sagernet/sing-tun/internal/gtcpip/checksum"
	"github.com/sagernet/sing-tun/internal/gtcpip/header"
)

type NatMapping struct {
	access    sync.RWMutex
	sessions  map[DirectRouteSession]DirectRouteContext
	ipRewrite bool
}

func NewNatMapping(ipRewrite bool) *NatMapping {
	return &NatMapping{
		sessions:  make(map[DirectRouteSession]DirectRouteContext),
		ipRewrite: ipRewrite,
	}
}

func (m *NatMapping) CreateSession(session DirectRouteSession, context DirectRouteContext) {
	if m.ipRewrite {
		session.Source = netip.Addr{}
	}
	m.access.Lock()
	m.sessions[session] = context
	m.access.Unlock()
}

func (m *NatMapping) DeleteSession(session DirectRouteSession) {
	if m.ipRewrite {
		session.Source = netip.Addr{}
	}
	m.access.Lock()
	delete(m.sessions, session)
	m.access.Unlock()
}

func (m *NatMapping) WritePacket(packet []byte) (bool, error) {
	var routeSession DirectRouteSession
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		routeSession.Source = ipHdr.DestinationAddr()
		routeSession.Destination = ipHdr.SourceAddr()
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		routeSession.Source = ipHdr.DestinationAddr()
		routeSession.Destination = ipHdr.SourceAddr()
	default:
		return false, nil
	}
	m.access.RLock()
	context, loaded := m.sessions[routeSession]
	m.access.RUnlock()
	if !loaded {
		return false, nil
	}
	return true, context.WritePacket(packet)
}

type NatWriter struct {
	inet4Address netip.Addr
	inet6Address netip.Addr
}

func NewNatWriter(inet4Address netip.Addr, inet6Address netip.Addr) *NatWriter {
	return &NatWriter{
		inet4Address: inet4Address,
		inet6Address: inet6Address,
	}
}

func (w *NatWriter) RewritePacket(packet []byte) {
	var ipHdr header.Network
	var bindAddr netip.Addr
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr = header.IPv4(packet)
		bindAddr = w.inet4Address
	case header.IPv6Version:
		ipHdr = header.IPv6(packet)
		bindAddr = w.inet6Address
	default:
		return
	}
	ipHdr.SetSourceAddr(bindAddr)
	switch ipHdr.TransportProtocol() {
	case header.ICMPv4ProtocolNumber:
		icmpHdr := header.ICMPv4(packet)
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(icmpHdr.Payload(), 0)))
	case header.ICMPv6ProtocolNumber:
		icmpHdr := header.ICMPv6(packet)
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmpHdr,
			Src:    ipHdr.SourceAddress(),
			Dst:    ipHdr.DestinationAddress(),
		}))
	}
	if ipHdr4, isIPv4 := ipHdr.(header.IPv4); isIPv4 {
		ipHdr4.SetChecksum(0)
		ipHdr4.SetChecksum(^ipHdr4.CalculateChecksum())
	}
}
