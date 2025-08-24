package ping

import (
	"net/netip"
	"sync"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/internal/gtcpip/header"
)

type Rewriter struct {
	access         sync.RWMutex
	sessions       map[tun.DirectRouteSession]tun.DirectRouteContext
	source4Address map[uint16]netip.Addr
	source6Address map[uint16]netip.Addr
	inet4Address   netip.Addr
	inet6Address   netip.Addr
}

func NewRewriter(inet4Address netip.Addr, inet6Address netip.Addr) *Rewriter {
	return &Rewriter{
		sessions:     make(map[tun.DirectRouteSession]tun.DirectRouteContext),
		inet4Address: inet4Address,
		inet6Address: inet6Address,
	}
}

func (m *Rewriter) CreateSession(session tun.DirectRouteSession, context tun.DirectRouteContext) {
	m.access.Lock()
	m.sessions[session] = context
	m.access.Unlock()
}

func (m *Rewriter) DeleteSession(session tun.DirectRouteSession) {
	m.access.Lock()
	delete(m.sessions, session)
	m.access.Unlock()
}

func (m *Rewriter) RewritePacket(packet []byte) {
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
		ipHdr4.SetChecksum(0)
		ipHdr4.SetChecksum(^ipHdr4.CalculateChecksum())
	}
	switch ipHdr.TransportProtocol() {
	case header.ICMPv4ProtocolNumber:
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		m.access.Lock()
		m.source4Address[icmpHdr.Ident()] = sourceAddr
		m.access.Lock()
	case header.ICMPv6ProtocolNumber:
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmpHdr,
			Src:    ipHdr.SourceAddressSlice(),
			Dst:    ipHdr.DestinationAddressSlice(),
		}))
		m.access.Lock()
		m.source6Address[icmpHdr.Ident()] = sourceAddr
		m.access.Lock()
	}
}

func (m *Rewriter) WriteBack(packet []byte) (bool, error) {
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
	switch ipHdr.TransportProtocol() {
	case header.ICMPv4ProtocolNumber:
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		m.access.Lock()
		ident := icmpHdr.Ident()
		source, loaded := m.source4Address[ident]
		if !loaded {
			m.access.Unlock()
			return false, nil
		}
		delete(m.source4Address, icmpHdr.Ident())
		m.access.Lock()
		routeSession.Source = source
	case header.ICMPv6ProtocolNumber:
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		m.access.Lock()
		ident := icmpHdr.Ident()
		source, loaded := m.source6Address[ident]
		if !loaded {
			m.access.Unlock()
			return false, nil
		}
		delete(m.source6Address, icmpHdr.Ident())
		m.access.Lock()
		routeSession.Source = source
	default:
		return false, nil
	}
	m.access.RLock()
	context, loaded := m.sessions[routeSession]
	m.access.RUnlock()
	if !loaded {
		return false, nil
	}
	ipHdr.SetDestinationAddr(routeSession.Source)
	if ipHdr4, isIPv4 := ipHdr.(header.IPv4); isIPv4 {
		ipHdr4.SetChecksum(0)
		ipHdr4.SetChecksum(^ipHdr4.CalculateChecksum())
	}
	switch ipHdr.TransportProtocol() {
	case header.ICMPv6ProtocolNumber:
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmpHdr,
			Src:    ipHdr.SourceAddressSlice(),
			Dst:    ipHdr.DestinationAddressSlice(),
		}))
	}
	return true, context.WritePacket(packet)
}
