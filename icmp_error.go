package tun

import (
	"encoding/binary"
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

type ICMPError uint8

const (
	ICMPErrorNoRoute ICMPError = iota
	ICMPErrorAddressUnreachable
	ICMPErrorPortUnreachable
	ICMPErrorSourcePolicy
	ICMPErrorHopLimitExceeded
	ICMPErrorPacketTooBig
)

func BuildICMPError(packet []byte, errorType ICMPError, source netip.Addr, mtu uint32, headroom int) ([]byte, bool) {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.FragmentOffset() != 0 {
			return nil, false
		}
		sourceAddr := ipHdr.SourceAddr()
		if sourceAddr.IsUnspecified() || sourceAddr.IsMulticast() {
			return nil, false
		}
		destinationAddr := ipHdr.DestinationAddr()
		if destinationAddr.IsMulticast() || destinationAddr == netip.AddrFrom4([4]byte{0xff, 0xff, 0xff, 0xff}) {
			return nil, false
		}
		if ipHdr.TransportProtocol() == header.ICMPv4ProtocolNumber {
			if len(ipHdr.Payload()) < header.ICMPv4MinimumSize {
				return nil, false
			}
			switch header.ICMPv4(ipHdr.Payload()).Type() {
			case header.ICMPv4DstUnreachable, header.ICMPv4SrcQuench, header.ICMPv4Redirect, header.ICMPv4TimeExceeded, header.ICMPv4ParamProblem:
				return nil, false
			}
		}
		if !source.Is4() {
			source = destinationAddr
		}
		return buildICMPv4Error(ipHdr, errorType, source, mtu, headroom), true
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		if !ipHdr.IsValid(len(packet)) {
			return nil, false
		}
		sourceAddr := ipHdr.SourceAddr()
		if sourceAddr.IsUnspecified() || sourceAddr.IsMulticast() {
			return nil, false
		}
		destinationAddr := ipHdr.DestinationAddr()
		if destinationAddr.IsMulticast() && errorType != ICMPErrorPacketTooBig {
			return nil, false
		}
		if ipHdr.TransportProtocol() == header.ICMPv6ProtocolNumber {
			if len(ipHdr.Payload()) < header.ICMPv6MinimumSize {
				return nil, false
			}
			icmpType := header.ICMPv6(ipHdr.Payload()).Type()
			if icmpType < header.ICMPv6EchoRequest || icmpType == header.ICMPv6RedirectMsg {
				return nil, false
			}
		}
		if !source.Is6() || source.Is4In6() {
			source = destinationAddr
		}
		return buildICMPv6Error(ipHdr, errorType, source, mtu, headroom), true
	default:
		return nil, false
	}
}

func buildICMPv4Error(packet header.IPv4, errorType ICMPError, source netip.Addr, mtu uint32, headroom int) []byte {
	icmpType := header.ICMPv4DstUnreachable
	var icmpCode header.ICMPv4Code
	switch errorType {
	case ICMPErrorNoRoute, ICMPErrorAddressUnreachable:
		icmpCode = header.ICMPv4HostUnreachable
	case ICMPErrorPortUnreachable:
		icmpCode = header.ICMPv4PortUnreachable
	case ICMPErrorSourcePolicy:
		icmpCode = header.ICMPv4AdminProhibited
	case ICMPErrorHopLimitExceeded:
		icmpType = header.ICMPv4TimeExceeded
		icmpCode = header.ICMPv4TTLExceeded
	case ICMPErrorPacketTooBig:
		icmpCode = header.ICMPv4FragmentationNeeded
	}
	const maxPayloadLength = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize - header.ICMPv4MinimumSize
	payloadLength := min(int(packet.TotalLength()), len(packet), maxPayloadLength)
	size := header.IPv4MinimumSize + header.ICMPv4MinimumSize + payloadLength
	buffer := make([]byte, headroom+size)
	response := header.IPv4(buffer[headroom:])
	response.Encode(&header.IPv4Fields{
		TotalLength: uint16(size),
		TTL:         synthesizedTTL,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     source,
		DstAddr:     packet.SourceAddr(),
	})
	response.SetChecksum(^response.CalculateChecksum())
	icmpHdr := header.ICMPv4(response.Payload())
	icmpHdr.SetType(icmpType)
	icmpHdr.SetCode(icmpCode)
	if errorType == ICMPErrorPacketTooBig {
		icmpHdr.SetMTU(uint16(min(max(mtu, header.IPv4MinimumMTU), 0xffff)))
	}
	copy(icmpHdr.Payload(), packet[:payloadLength])
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	return buffer
}

func buildICMPv6Error(packet header.IPv6, errorType ICMPError, source netip.Addr, mtu uint32, headroom int) []byte {
	icmpType := header.ICMPv6DstUnreachable
	var icmpCode header.ICMPv6Code
	switch errorType {
	case ICMPErrorNoRoute:
		icmpCode = header.ICMPv6NetworkUnreachable
	case ICMPErrorAddressUnreachable:
		icmpCode = header.ICMPv6AddressUnreachable
	case ICMPErrorPortUnreachable:
		icmpCode = header.ICMPv6PortUnreachable
	case ICMPErrorSourcePolicy:
		icmpCode = header.ICMPv6Policy
	case ICMPErrorHopLimitExceeded:
		icmpType = header.ICMPv6TimeExceeded
		icmpCode = header.ICMPv6HopLimitExceeded
	case ICMPErrorPacketTooBig:
		icmpType = header.ICMPv6PacketTooBig
		icmpCode = header.ICMPv6UnusedCode
	}
	const maxPayloadLength = header.IPv6MinimumMTU - header.IPv6MinimumSize - header.ICMPv6ErrorHeaderSize
	payloadLength := min(header.IPv6MinimumSize+int(packet.PayloadLength()), len(packet), maxPayloadLength)
	size := header.IPv6MinimumSize + header.ICMPv6ErrorHeaderSize + payloadLength
	buffer := make([]byte, headroom+size)
	response := header.IPv6(buffer[headroom:])
	response.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6ErrorHeaderSize + payloadLength),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          synthesizedTTL,
		SrcAddr:           source,
		DstAddr:           packet.SourceAddr(),
	})
	icmpHdr := header.ICMPv6(response.Payload())
	icmpHdr.SetType(icmpType)
	icmpHdr.SetCode(icmpCode)
	if errorType == ICMPErrorPacketTooBig {
		icmpHdr.SetMTU(max(mtu, header.IPv6MinimumMTU))
	}
	copy(icmpHdr[header.ICMPv6ErrorHeaderSize:], packet[:payloadLength])
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    response.SourceAddressSlice(),
		Dst:    response.DestinationAddressSlice(),
	}))
	return buffer
}

func IPTransportProtocol(packet []byte) (uint8, bool) {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		if !ipHdr.IsValid(len(packet)) {
			return 0, false
		}
		return ipHdr.Protocol(), true
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		if !ipHdr.IsValid(len(packet)) {
			return 0, false
		}
		protocol := ipHdr.NextHeader()
		payload := ipHdr.Payload()
		for {
			var fragment, transportPresent bool
			protocol, payload, fragment, transportPresent = skipIPv6ExtensionHeaders(protocol, payload)
			if transportPresent {
				return protocol, true
			}
			if !fragment || len(payload) < header.IPv6FragmentHeaderSize {
				return 0, false
			}
			protocol = payload[0]
			if binary.BigEndian.Uint16(payload[2:])>>3 != 0 {
				switch header.IPv6ExtensionHeaderIdentifier(protocol) {
				case header.IPv6HopByHopOptionsExtHdrIdentifier, header.IPv6RoutingExtHdrIdentifier, header.IPv6DestinationOptionsExtHdrIdentifier, header.IPv6FragmentExtHdrIdentifier:
					return 0, false
				}
				return protocol, true
			}
			payload = payload[header.IPv6FragmentHeaderSize:]
		}
	default:
		return 0, false
	}
}
