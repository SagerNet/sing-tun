package tun

import (
	"github.com/sagernet/sing-tun/gtcpip/header"
)

func buildReject(packet *forwardPacket, headroom int) ([]byte, bool) {
	switch packet.protocol {
	case uint8(header.TCPProtocolNumber):
		if len(packet.transport) < header.TCPMinimumSize {
			return nil, false
		}
		tcpHdr := header.TCP(packet.transport)
		if packet.ipVersion == 4 {
			return buildResetIPv4(header.IPv4(packet.network), tcpHdr, headroom), true
		}
		return buildResetIPv6(header.IPv6(packet.network), tcpHdr, headroom), true
	case uint8(header.UDPProtocolNumber):
		return buildICMPError(packet, ICMPErrorPortUnreachable, 0, headroom), true
	default:
		return buildICMPError(packet, ICMPErrorAddressUnreachable, 0, headroom), true
	}
}

func buildICMPError(packet *forwardPacket, errorType ICMPError, mtu uint32, headroom int) []byte {
	if packet.ipVersion == 4 {
		ipHdr := header.IPv4(packet.network)
		return buildICMPv4Error(ipHdr, errorType, ipHdr.DestinationAddr(), mtu, headroom)
	}
	ipHdr := header.IPv6(packet.network)
	return buildICMPv6Error(ipHdr, errorType, ipHdr.DestinationAddr(), mtu, headroom)
}

func buildResetIPv4(origIPHdr header.IPv4, origTCPHdr header.TCP, headroom int) []byte {
	size := header.IPv4MinimumSize + header.TCPMinimumSize
	buffer := make([]byte, headroom+size)
	ipHdr := header.IPv4(buffer[headroom:])
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(size),
		TTL:         synthesizedTTL,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     origIPHdr.DestinationAddr(),
		DstAddr:     origIPHdr.SourceAddr(),
	})
	tcpHdr := header.TCP(ipHdr.Payload())
	encodeResetTCP(tcpHdr, origTCPHdr)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return buffer
}

func buildResetIPv6(origIPHdr header.IPv6, origTCPHdr header.TCP, headroom int) []byte {
	size := header.IPv6MinimumSize + header.TCPMinimumSize
	buffer := make([]byte, headroom+size)
	ipHdr := header.IPv6(buffer[headroom:])
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.TCPMinimumSize),
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          synthesizedTTL,
		SrcAddr:           origIPHdr.DestinationAddr(),
		DstAddr:           origIPHdr.SourceAddr(),
	})
	tcpHdr := header.TCP(ipHdr.Payload())
	encodeResetTCP(tcpHdr, origTCPHdr)
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), header.TCPMinimumSize)))
	return buffer
}

func encodeResetTCP(tcpHdr header.TCP, origTCPHdr header.TCP) {
	fields := header.TCPFields{
		SrcPort:    origTCPHdr.DestinationPort(),
		DstPort:    origTCPHdr.SourcePort(),
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst,
	}
	if origTCPHdr.Flags()&header.TCPFlagAck != 0 {
		fields.SeqNum = origTCPHdr.AckNumber()
	} else {
		fields.Flags |= header.TCPFlagAck
		ackNumber := origTCPHdr.SequenceNumber() + uint32(len(origTCPHdr.Payload()))
		if origTCPHdr.Flags()&header.TCPFlagSyn != 0 {
			ackNumber++
		}
		if origTCPHdr.Flags()&header.TCPFlagFin != 0 {
			ackNumber++
		}
		fields.AckNum = ackNumber
	}
	tcpHdr.Encode(&fields)
}
