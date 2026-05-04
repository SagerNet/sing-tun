package ping_test

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing-tun/ping"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestUDPDestinationIsClosed(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.SkipNow()
	}
	if runtime.GOOS != "windows" && os.Getuid() != 0 {
		t.SkipNow()
	}
	destination, err := ping.ConnectUDPDestination(
		context.Background(),
		logger.NOP(),
		nil,
		netip.MustParseAddr("127.0.0.1"),
		nil,
		30*time.Second,
	)
	require.NoError(t, err)
	defer destination.Close()

	require.False(t, destination.IsClosed())
	destination.Close()
	require.True(t, destination.IsClosed())
}

func TestUDPDestinationWritePacketIPv4(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.SkipNow()
	}
	if runtime.GOOS != "windows" && os.Getuid() != 0 {
		t.SkipNow()
	}

	// Start a local UDP listener to receive the probe
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	listenerAddr := listener.LocalAddr().(*net.UDPAddr)

	destination, err := ping.ConnectUDPDestination(
		context.Background(),
		logger.NOP(),
		nil,
		netip.MustParseAddr("127.0.0.1"),
		nil,
		30*time.Second,
	)
	require.NoError(t, err)
	defer destination.Close()

	// Build an IPv4+UDP packet
	payload := []byte("traceroute-probe")
	pkt := buildIPv4UDPPacket(t,
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("127.0.0.1"),
		12345,
		uint16(listenerAddr.Port),
		64,
		payload,
	)

	err = destination.WritePacket(pkt)
	require.NoError(t, err)

	// Read from the listener
	recvBuf := make([]byte, 1500)
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(3*time.Second)))
	n, _, readErr := listener.ReadFrom(recvBuf)
	require.NoError(t, readErr)
	require.Equal(t, payload, recvBuf[:n])
}

func TestUDPDestinationWritePacketInvalidHeader(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.SkipNow()
	}
	if runtime.GOOS != "windows" && os.Getuid() != 0 {
		t.SkipNow()
	}

	destination, err := ping.ConnectUDPDestination(
		context.Background(),
		logger.NOP(),
		nil,
		netip.MustParseAddr("127.0.0.1"),
		nil,
		30*time.Second,
	)
	require.NoError(t, err)
	defer destination.Close()

	t.Run("too-short", func(t *testing.T) {
		pkt := buf.As([]byte{0x45, 0x00}).ToOwned()
		err := destination.WritePacket(pkt)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid IPv4 header")
	})

	t.Run("not-udp", func(t *testing.T) {
		// Build an IPv4 packet with ICMP protocol instead of UDP
		pkt := buildIPv4ICMPPacket(t,
			netip.MustParseAddr("10.0.0.2"),
			netip.MustParseAddr("127.0.0.1"),
			64,
		)
		err := destination.WritePacket(pkt)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not a UDP packet")
	})
}

func TestUDPDestinationMultiplePortProbes(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.SkipNow()
	}
	if runtime.GOOS != "windows" && os.Getuid() != 0 {
		t.SkipNow()
	}

	// Start multiple listeners on different ports (simulating traceroute behavior)
	const numProbes = 3
	listeners := make([]net.PacketConn, numProbes)
	for i := range numProbes {
		l, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		defer l.Close()
		listeners[i] = l
	}

	destination, err := ping.ConnectUDPDestination(
		context.Background(),
		logger.NOP(),
		nil,
		netip.MustParseAddr("127.0.0.1"),
		nil,
		30*time.Second,
	)
	require.NoError(t, err)
	defer destination.Close()

	// Send probes with different TTLs and destination ports (like mtr --udp)
	for i, l := range listeners {
		lAddr := l.LocalAddr().(*net.UDPAddr)
		payload := []byte{byte(i + 1)} // simple payload with hop number
		pkt := buildIPv4UDPPacket(t,
			netip.MustParseAddr("10.0.0.2"),
			netip.MustParseAddr("127.0.0.1"),
			60183,
			uint16(lAddr.Port),
			uint8(i+1), // TTL 1, 2, 3
			payload,
		)
		err := destination.WritePacket(pkt)
		require.NoError(t, err)
	}

	// All probes should arrive at their respective listeners
	for i, l := range listeners {
		recvBuf := make([]byte, 64)
		require.NoError(t, l.SetReadDeadline(time.Now().Add(3*time.Second)))
		n, _, readErr := l.ReadFrom(recvBuf)
		require.NoError(t, readErr, "probe %d should arrive", i+1)
		require.Equal(t, []byte{byte(i + 1)}, recvBuf[:n])
	}
}

// buildIPv4UDPPacket constructs a valid IPv4+UDP packet as a buf.Buffer.
func buildIPv4UDPPacket(
	t *testing.T,
	src, dst netip.Addr,
	srcPort, dstPort uint16,
	ttl uint8,
	payload []byte,
) *buf.Buffer {
	t.Helper()

	udpLen := uint16(header.UDPMinimumSize + len(payload))
	totalLen := uint16(header.IPv4MinimumSize) + udpLen

	packet := make([]byte, totalLen)

	// Encode IPv4 header
	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: totalLen,
		TTL:         ttl,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	// Encode UDP header
	udpHdr := header.UDP(packet[header.IPv4MinimumSize:])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  udpLen,
	})
	copy(packet[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)

	return buf.As(packet).ToOwned()
}

// buildIPv4ICMPPacket constructs a minimal IPv4+ICMP packet (for testing non-UDP rejection).
func buildIPv4ICMPPacket(
	t *testing.T,
	src, dst netip.Addr,
	ttl uint8,
) *buf.Buffer {
	t.Helper()

	icmpLen := header.ICMPv4MinimumSize
	totalLen := uint16(header.IPv4MinimumSize + icmpLen)

	packet := make([]byte, totalLen)

	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: totalLen,
		TTL:         ttl,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	icmpHdr := header.ICMPv4(packet[header.IPv4MinimumSize:])
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))

	return buf.As(packet).ToOwned()
}

// buildICMPv4ErrorWithUDP constructs an ICMP Time Exceeded error containing an inner IPv4+UDP packet.
// This simulates what a router sends when TTL expires on a UDP probe.
func buildICMPv4ErrorWithUDP(
	t *testing.T,
	outerSrc, outerDst netip.Addr,
	innerSrc, innerDst netip.Addr,
	innerSrcPort, innerDstPort uint16,
	icmpType header.ICMPv4Type,
) []byte {
	t.Helper()

	// Inner: IPv4 + UDP header (minimum, no payload as per RFC)
	innerIPLen := header.IPv4MinimumSize + header.UDPMinimumSize
	// ICMP header (8 bytes) + inner IP+UDP
	icmpPayloadLen := header.ICMPv4MinimumSize + innerIPLen
	totalLen := header.IPv4MinimumSize + icmpPayloadLen

	packet := make([]byte, totalLen)

	// Outer IPv4
	outerIP := header.IPv4(packet)
	outerIP.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     outerSrc,
		DstAddr:     outerDst,
	})
	outerIP.SetChecksum(^outerIP.CalculateChecksum())

	// ICMP header
	icmpOffset := header.IPv4MinimumSize
	icmpHdr := header.ICMPv4(packet[icmpOffset:])
	icmpHdr.SetType(icmpType)
	icmpHdr.SetCode(0)

	// Inner IPv4 (inside ICMP error)
	innerIPOffset := icmpOffset + header.ICMPv4MinimumSize
	innerIP := header.IPv4(packet[innerIPOffset:])
	innerIP.Encode(&header.IPv4Fields{
		TotalLength: uint16(innerIPLen),
		TTL:         1,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     innerSrc,
		DstAddr:     innerDst,
	})
	innerIP.SetChecksum(^innerIP.CalculateChecksum())

	// Inner UDP header
	innerUDPOffset := innerIPOffset + header.IPv4MinimumSize
	innerUDP := header.UDP(packet[innerUDPOffset:])
	binary.BigEndian.PutUint16(packet[innerUDPOffset:], innerSrcPort)
	binary.BigEndian.PutUint16(packet[innerUDPOffset+2:], innerDstPort)
	_ = innerUDP
	binary.BigEndian.PutUint16(packet[innerUDPOffset+4:], header.UDPMinimumSize) // length

	// Calculate ICMP checksum
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))

	return packet
}

func TestBuildIPv4UDPPacket(t *testing.T) {
	t.Parallel()
	payload := []byte("hello")
	pkt := buildIPv4UDPPacket(t,
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("1.1.1.1"),
		12345, 33434, 5, payload,
	)
	defer pkt.Release()

	ipHdr := header.IPv4(pkt.Bytes())
	require.True(t, ipHdr.IsValid(pkt.Len()))
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), ipHdr.SourceAddr())
	require.Equal(t, netip.MustParseAddr("1.1.1.1"), ipHdr.DestinationAddr())
	require.Equal(t, uint8(5), ipHdr.TTL())
	require.Equal(t, header.UDPProtocolNumber, ipHdr.TransportProtocol())

	udpHdr := header.UDP(ipHdr.Payload())
	require.Equal(t, uint16(12345), udpHdr.SourcePort())
	require.Equal(t, uint16(33434), udpHdr.DestinationPort())
	require.Equal(t, payload, udpHdr.Payload())
}

func TestBuildICMPv4ErrorWithUDP(t *testing.T) {
	t.Parallel()
	packet := buildICMPv4ErrorWithUDP(t,
		netip.MustParseAddr("192.168.1.1"),    // router
		netip.MustParseAddr("192.168.10.254"), // server
		netip.MustParseAddr("192.168.10.254"), // inner src (server's real IP)
		netip.MustParseAddr("1.1.1.1"),        // inner dst
		23674,                                 // inner src port (kernel port)
		33434,                                 // inner dst port
		header.ICMPv4TimeExceeded,
	)

	outerIP := header.IPv4(packet)
	require.True(t, outerIP.IsValid(len(packet)))
	require.Equal(t, header.ICMPv4ProtocolNumber, outerIP.TransportProtocol())

	icmpHdr := header.ICMPv4(outerIP.Payload())
	require.Equal(t, header.ICMPv4TimeExceeded, icmpHdr.Type())

	innerIP := header.IPv4(outerIP.Payload()[header.ICMPv4MinimumSize:])
	require.True(t, innerIP.IsValid(len(outerIP.Payload())-header.ICMPv4MinimumSize))
	require.Equal(t, header.UDPProtocolNumber, innerIP.TransportProtocol())

	innerUDP := header.UDP(innerIP.Payload())
	require.Equal(t, uint16(23674), innerUDP.SourcePort())
	require.Equal(t, uint16(33434), innerUDP.DestinationPort())
}

func TestICMPv4ErrorRewriteAddresses(t *testing.T) {
	t.Parallel()

	// Simulate the rewrite logic from loopReadErrors (IPv4 path)
	// Scenario: ICMP TTL Exceeded from router 192.168.1.1 → server 192.168.10.254
	// Inner packet: server 192.168.10.254:23674 → 1.1.1.1:33434
	// After rewrite: outer dst → 10.0.0.2, inner src → 10.0.0.2, inner UDP src port → 60183
	packet := buildICMPv4ErrorWithUDP(t,
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.10.254"),
		netip.MustParseAddr("192.168.10.254"),
		netip.MustParseAddr("1.1.1.1"),
		23674, 33434,
		header.ICMPv4TimeExceeded,
	)

	originalSource := netip.MustParseAddr("10.0.0.2")
	var originalSourcePort uint16 = 60183
	var localPort uint16 = 23674

	// Apply the same rewrite logic as loopReadErrors
	outerIP := header.IPv4(packet)
	icmpHdr := header.ICMPv4(outerIP.Payload())
	innerIP := header.IPv4(outerIP.Payload()[header.ICMPv4MinimumSize:])
	innerUDP := header.UDP(innerIP.Payload())

	outerIP.SetDestinationAddr(originalSource)
	innerIP.SetSourceAddr(originalSource)
	if originalSourcePort != 0 && localPort != 0 && innerUDP.SourcePort() == localPort {
		innerUDP.SetSourcePort(originalSourcePort)
	}
	innerIP.SetChecksum(^innerIP.CalculateChecksum())
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	outerIP.SetChecksum(^outerIP.CalculateChecksum())

	// Verify rewrites
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), outerIP.DestinationAddr(),
		"outer dst should be rewritten to client tunnel IP")
	require.Equal(t, netip.MustParseAddr("192.168.1.1"), outerIP.SourceAddr(),
		"outer src should remain as router IP")
	require.Equal(t, netip.MustParseAddr("10.0.0.2"), innerIP.SourceAddr(),
		"inner src should be rewritten to client tunnel IP")
	require.Equal(t, netip.MustParseAddr("1.1.1.1"), innerIP.DestinationAddr(),
		"inner dst should remain as original destination")
	require.Equal(t, uint16(60183), innerUDP.SourcePort(),
		"inner UDP src port should be rewritten from kernel port to client port")
	require.Equal(t, uint16(33434), innerUDP.DestinationPort(),
		"inner UDP dst port should remain unchanged")
}

func TestICMPv4ErrorNoPortRewriteWhenMismatch(t *testing.T) {
	t.Parallel()

	// When inner src port doesn't match localPort, no rewrite should happen
	packet := buildICMPv4ErrorWithUDP(t,
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.10.254"),
		netip.MustParseAddr("192.168.10.254"),
		netip.MustParseAddr("1.1.1.1"),
		99999%65536, 33434, // different port from localPort
		header.ICMPv4TimeExceeded,
	)

	var localPort uint16 = 23674
	var originalSourcePort uint16 = 60183

	outerIP := header.IPv4(packet)
	innerIP := header.IPv4(outerIP.Payload()[header.ICMPv4MinimumSize:])
	innerUDP := header.UDP(innerIP.Payload())

	originalInnerSrcPort := innerUDP.SourcePort()

	// Apply conditional rewrite
	if originalSourcePort != 0 && localPort != 0 && innerUDP.SourcePort() == localPort {
		innerUDP.SetSourcePort(originalSourcePort)
	}

	require.Equal(t, originalInnerSrcPort, innerUDP.SourcePort(),
		"inner UDP src port should NOT be rewritten when it doesn't match localPort")
}
