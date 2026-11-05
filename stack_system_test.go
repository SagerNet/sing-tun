package tun

import (
	"fmt"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestSystemUDPPacketWriterClearsECN(t *testing.T) {
	t.Parallel()
	const dscp = 46 << 2 // EF
	const flowLabel = 0x12345
	payload := []byte("reply")
	for _, ecn := range []uint8{0b00, 0b01, 0b10, 0b11} {
		t.Run(fmt.Sprintf("ipv4/ecn=%02b", ecn), func(t *testing.T) {
			source := M.ParseSocksaddrHostPort("172.19.0.2", 40000)
			destination := M.ParseSocksaddrHostPort("1.1.1.1", 53)
			const totalLen = header.IPv4MinimumSize + header.UDPMinimumSize
			packet := header.IPv4(make([]byte, totalLen))
			packet.Encode(&header.IPv4Fields{
				TOS:         dscp | ecn,
				TotalLength: totalLen,
				TTL:         64,
				Protocol:    uint8(header.UDPProtocolNumber),
				SrcAddr:     source.Addr,
				DstAddr:     destination.Addr,
			})
			udpHdr := header.UDP(packet.Payload())
			udpHdr.SetSourcePort(source.Port)
			udpHdr.SetDestinationPort(destination.Port)
			reply := prepareSystemUDPReply(t, source, destination, packet, payload)
			ipHdr := header.IPv4(reply)
			tos, _ := ipHdr.TOS()
			require.Equal(t, uint8(dscp), tos)
			require.True(t, ipHdr.IsChecksumValid())
			require.Equal(t, destination.Addr, ipHdr.SourceAddr())
			require.Equal(t, source.Addr, ipHdr.DestinationAddr())
			require.Equal(t, payload, header.UDP(ipHdr.Payload()).Payload())
		})
		t.Run(fmt.Sprintf("ipv6/ecn=%02b", ecn), func(t *testing.T) {
			source := M.ParseSocksaddrHostPort("fdfe:dcba:9876::2", 40000)
			destination := M.ParseSocksaddrHostPort("2606:4700:4700::1111", 53)
			packet := header.IPv6(make([]byte, header.IPv6MinimumSize+header.UDPMinimumSize))
			packet.Encode(&header.IPv6Fields{
				TrafficClass:      dscp | ecn,
				FlowLabel:         flowLabel,
				PayloadLength:     header.UDPMinimumSize,
				TransportProtocol: header.UDPProtocolNumber,
				HopLimit:          64,
				SrcAddr:           source.Addr,
				DstAddr:           destination.Addr,
			})
			udpHdr := header.UDP(packet.Payload())
			udpHdr.SetSourcePort(source.Port)
			udpHdr.SetDestinationPort(destination.Port)
			reply := prepareSystemUDPReply(t, source, destination, packet, payload)
			ipHdr := header.IPv6(reply)
			trafficClass, replyFlowLabel := ipHdr.TOS()
			require.Equal(t, uint8(dscp), trafficClass)
			require.Equal(t, uint32(flowLabel), replyFlowLabel)
			require.Equal(t, destination.Addr, ipHdr.SourceAddr())
			require.Equal(t, source.Addr, ipHdr.DestinationAddr())
			require.Equal(t, payload, header.UDP(ipHdr.Payload()).Payload())
		})
	}
}

func prepareSystemUDPReply(t *testing.T, source M.Socksaddr, destination M.Socksaddr, packet any, payload []byte) []byte {
	t.Helper()
	_, _, writer, _ := (&System{}).preparePacketConnection(source, destination, packet)
	headroom := writer.(interface{ FrontHeadroom() int }).FrontHeadroom()
	buffer := buf.NewSize(headroom + len(payload))
	t.Cleanup(buffer.Release)
	buffer.Resize(headroom, 0)
	copy(buffer.Extend(len(payload)), payload)
	switch w := writer.(type) {
	case *systemUDPPacketWriter4:
		w.preparePacket(buffer, destination)
	case *systemUDPPacketWriter6:
		w.preparePacket(buffer, destination)
	default:
		t.Fatalf("unexpected writer %T", writer)
	}
	return buffer.Bytes()
}
