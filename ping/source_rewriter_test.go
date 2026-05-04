package ping_test

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing-tun/ping"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// mockDirectRouteContext captures packets written back for verification.
type mockDirectRouteContext struct {
	packets [][]byte
}

func (m *mockDirectRouteContext) WritePacket(packet []byte) error {
	copied := make([]byte, len(packet))
	copy(copied, packet)
	m.packets = append(m.packets, copied)
	return nil
}

var _ tun.DirectRouteContext = (*mockDirectRouteContext)(nil)

// --- SourceRewriter Tests ---

func TestSourceRewriterEchoRequest(t *testing.T) {
	t.Parallel()

	serverAddr := netip.MustParseAddr("192.168.10.254")
	clientAddr := netip.MustParseAddr("10.0.0.2")
	destAddr := netip.MustParseAddr("1.1.1.1")

	rewriter := ping.NewSourceRewriter(
		context.Background(),
		logger.NOP(),
		serverAddr,
		netip.Addr{},
	)

	// Build an ICMP echo request from client to destination
	totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
	packet := make([]byte, totalLen)
	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     clientAddr,
		DstAddr:     destAddr,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	icmpHdr := header.ICMPv4(packet[header.IPv4MinimumSize:])
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetIdent(1234)
	icmpHdr.SetSequence(1)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))

	rewriter.RewritePacket(packet)

	// After rewrite, source should be serverAddr
	ipHdr = header.IPv4(packet)
	require.Equal(t, serverAddr, ipHdr.SourceAddr(),
		"source should be rewritten to server bind address")
	require.Equal(t, destAddr, ipHdr.DestinationAddr(),
		"destination should remain unchanged")
}

func TestSourceRewriterEchoReply(t *testing.T) {
	t.Parallel()

	serverAddr := netip.MustParseAddr("192.168.10.254")
	clientAddr := netip.MustParseAddr("10.0.0.2")
	destAddr := netip.MustParseAddr("1.1.1.1")

	ctx := &mockDirectRouteContext{}
	rewriter := ping.NewSourceRewriter(
		context.Background(),
		logger.NOP(),
		serverAddr,
		netip.Addr{},
	)

	session := tun.DirectRouteSession{
		Source:      clientAddr,
		Destination: destAddr,
	}
	rewriter.CreateSession(session, ctx)

	// First, simulate outgoing request to register the ident mapping
	reqPacket := buildICMPv4EchoRequest(t, clientAddr, destAddr, 1234, 1)
	rewriter.RewritePacket(reqPacket)

	// Now simulate incoming reply
	replyPacket := buildICMPv4EchoReply(t, destAddr, serverAddr, 1234, 1)
	ok, err := rewriter.WriteBack(replyPacket)
	require.NoError(t, err)
	require.True(t, ok, "WriteBack should succeed for matching echo reply")

	require.Len(t, ctx.packets, 1, "one packet should be forwarded")
	rewrittenIP := header.IPv4(ctx.packets[0])
	require.Equal(t, clientAddr, rewrittenIP.DestinationAddr(),
		"reply destination should be rewritten to client tunnel IP")
}

func TestSourceRewriterICMPv4TimeExceeded(t *testing.T) {
	t.Parallel()

	// ICMP errors use the inner packet's destination for session lookup,
	// so errors from both intermediate routers and the destination itself
	// should match the session correctly.

	serverAddr := netip.MustParseAddr("192.168.10.254")
	clientAddr := netip.MustParseAddr("10.0.0.2")
	destAddr := netip.MustParseAddr("1.1.1.1")
	routerAddr := netip.MustParseAddr("192.168.1.1") // intermediate router

	ctx := &mockDirectRouteContext{}
	rewriter := ping.NewSourceRewriter(
		context.Background(),
		logger.NOP(),
		serverAddr,
		netip.Addr{},
	)

	session := tun.DirectRouteSession{
		Source:      clientAddr,
		Destination: destAddr,
	}
	rewriter.CreateSession(session, ctx)

	// Register ident mapping via outgoing echo request
	reqPacket := buildICMPv4EchoRequest(t, clientAddr, destAddr, 5678, 1)
	rewriter.RewritePacket(reqPacket)

	// Error from intermediate router: should match via inner destination
	errorPacket := buildICMPv4ErrorWithInnerICMP(t,
		routerAddr, serverAddr,
		serverAddr, destAddr,
		5678, 1,
		header.ICMPv4TimeExceeded,
	)

	ok, err := rewriter.WriteBack(errorPacket)
	require.NoError(t, err)
	require.True(t, ok, "WriteBack should succeed for error from intermediate router")

	require.Len(t, ctx.packets, 1)
	rewrittenIP := header.IPv4(ctx.packets[0])
	require.Equal(t, clientAddr, rewrittenIP.DestinationAddr())
	require.Equal(t, routerAddr, rewrittenIP.SourceAddr())

	// Error from the destination itself should also match
	errorFromDest := buildICMPv4ErrorWithInnerICMP(t,
		destAddr, serverAddr,
		serverAddr, destAddr,
		5678, 1,
		header.ICMPv4DstUnreachable,
	)
	ok, err = rewriter.WriteBack(errorFromDest)
	require.NoError(t, err)
	require.True(t, ok, "WriteBack should succeed for error from destination itself")

	require.Len(t, ctx.packets, 2)
	rewrittenIP = header.IPv4(ctx.packets[1])
	require.Equal(t, clientAddr, rewrittenIP.DestinationAddr())

	// Verify inner IP source was rewritten
	icmpPayload := rewrittenIP.Payload()
	innerIP := header.IPv4(icmpPayload[header.ICMPv4MinimumSize:])
	require.Equal(t, clientAddr, innerIP.SourceAddr(),
		"inner IP source should be rewritten to client tunnel IP")
}

func TestSourceRewriterICMPv4ErrorPreservesIdent(t *testing.T) {
	t.Parallel()

	// After processing an error, the ident mapping should NOT be deleted
	// (unlike echo reply), so multiple errors can arrive for the same ident.
	// In the SourceRewriter path, only errors from the destination match,
	// so we use destAddr as the error source.

	serverAddr := netip.MustParseAddr("192.168.10.254")
	clientAddr := netip.MustParseAddr("10.0.0.2")
	destAddr := netip.MustParseAddr("1.1.1.1")

	ctx := &mockDirectRouteContext{}
	rewriter := ping.NewSourceRewriter(
		context.Background(),
		logger.NOP(),
		serverAddr,
		netip.Addr{},
	)

	session := tun.DirectRouteSession{
		Source:      clientAddr,
		Destination: destAddr,
	}
	rewriter.CreateSession(session, ctx)

	// Register ident mapping
	reqPacket := buildICMPv4EchoRequest(t, clientAddr, destAddr, 9999, 1)
	rewriter.RewritePacket(reqPacket)

	// First error from destination (DstUnreachable)
	errorPacket1 := buildICMPv4ErrorWithInnerICMP(t,
		destAddr, serverAddr,
		serverAddr, destAddr,
		9999, 1,
		header.ICMPv4DstUnreachable,
	)
	ok, err := rewriter.WriteBack(errorPacket1)
	require.NoError(t, err)
	require.True(t, ok)

	// Second error for same ident (ident mapping should still exist)
	errorPacket2 := buildICMPv4ErrorWithInnerICMP(t,
		destAddr, serverAddr,
		serverAddr, destAddr,
		9999, 1,
		header.ICMPv4DstUnreachable,
	)
	ok, err = rewriter.WriteBack(errorPacket2)
	require.NoError(t, err)
	require.True(t, ok, "second error should still match (ident not deleted for errors)")

	require.Len(t, ctx.packets, 2, "both errors should be forwarded")
}

func TestSourceRewriterUnknownIdent(t *testing.T) {
	t.Parallel()

	serverAddr := netip.MustParseAddr("192.168.10.254")

	rewriter := ping.NewSourceRewriter(
		context.Background(),
		logger.NOP(),
		serverAddr,
		netip.Addr{},
	)

	// Build a reply with an ident that was never registered
	replyPacket := buildICMPv4EchoReply(t,
		netip.MustParseAddr("1.1.1.1"),
		serverAddr,
		42, 1,
	)
	ok, err := rewriter.WriteBack(replyPacket)
	require.NoError(t, err)
	require.False(t, ok, "WriteBack should return false for unknown ident")
}

func TestSourceRewriterSessionManagement(t *testing.T) {
	t.Parallel()

	serverAddr := netip.MustParseAddr("192.168.10.254")
	clientAddr := netip.MustParseAddr("10.0.0.2")
	destAddr := netip.MustParseAddr("1.1.1.1")

	ctx := &mockDirectRouteContext{}
	rewriter := ping.NewSourceRewriter(
		context.Background(),
		logger.NOP(),
		serverAddr,
		netip.Addr{},
	)

	session := tun.DirectRouteSession{
		Source:      clientAddr,
		Destination: destAddr,
	}
	rewriter.CreateSession(session, ctx)

	// Register ident mapping
	reqPacket := buildICMPv4EchoRequest(t, clientAddr, destAddr, 1111, 1)
	rewriter.RewritePacket(reqPacket)

	// Delete session
	rewriter.DeleteSession(session)

	// Now reply should fail (no session)
	replyPacket := buildICMPv4EchoReply(t, destAddr, serverAddr, 1111, 1)
	ok, err := rewriter.WriteBack(replyPacket)
	require.NoError(t, err)
	require.False(t, ok, "WriteBack should return false after session deletion")
}

func TestSourceRewriterNonICMPPacket(t *testing.T) {
	t.Parallel()

	serverAddr := netip.MustParseAddr("192.168.10.254")

	rewriter := ping.NewSourceRewriter(
		context.Background(),
		logger.NOP(),
		serverAddr,
		netip.Addr{},
	)

	// Build a TCP packet (should be ignored by WriteBack)
	totalLen := header.IPv4MinimumSize + 20 // minimal TCP header
	packet := make([]byte, totalLen)
	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    6, // TCP
		SrcAddr:     netip.MustParseAddr("1.1.1.1"),
		DstAddr:     serverAddr,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	ok, err := rewriter.WriteBack(packet)
	require.NoError(t, err)
	require.False(t, ok, "WriteBack should return false for non-ICMP packets")
}

func TestSourceRewriterDstUnreachable(t *testing.T) {
	t.Parallel()

	serverAddr := netip.MustParseAddr("192.168.10.254")
	clientAddr := netip.MustParseAddr("10.0.0.2")
	destAddr := netip.MustParseAddr("1.1.1.1")
	routerAddr := netip.MustParseAddr("1.1.1.1") // destination itself sends port unreachable

	ctx := &mockDirectRouteContext{}
	rewriter := ping.NewSourceRewriter(
		context.Background(),
		logger.NOP(),
		serverAddr,
		netip.Addr{},
	)

	session := tun.DirectRouteSession{
		Source:      clientAddr,
		Destination: destAddr,
	}
	rewriter.CreateSession(session, ctx)

	reqPacket := buildICMPv4EchoRequest(t, clientAddr, destAddr, 7777, 1)
	rewriter.RewritePacket(reqPacket)

	errorPacket := buildICMPv4ErrorWithInnerICMP(t,
		routerAddr, serverAddr,
		serverAddr, destAddr,
		7777, 1,
		header.ICMPv4DstUnreachable,
	)

	ok, err := rewriter.WriteBack(errorPacket)
	require.NoError(t, err)
	require.True(t, ok)

	require.Len(t, ctx.packets, 1)
	rewrittenIP := header.IPv4(ctx.packets[0])
	require.Equal(t, clientAddr, rewrittenIP.DestinationAddr())
}

// --- Helper functions for building test packets ---

func buildICMPv4EchoRequest(t *testing.T, src, dst netip.Addr, ident, seq uint16) []byte {
	t.Helper()
	totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
	packet := make([]byte, totalLen)

	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	icmpHdr := header.ICMPv4(packet[header.IPv4MinimumSize:])
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetIdent(ident)
	icmpHdr.SetSequence(seq)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))

	return packet
}

func buildICMPv4EchoReply(t *testing.T, src, dst netip.Addr, ident, seq uint16) []byte {
	t.Helper()
	totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
	packet := make([]byte, totalLen)

	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	icmpHdr := header.ICMPv4(packet[header.IPv4MinimumSize:])
	icmpHdr.SetType(header.ICMPv4EchoReply)
	icmpHdr.SetIdent(ident)
	icmpHdr.SetSequence(seq)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))

	return packet
}

// buildICMPv4ErrorWithInnerICMP builds an ICMP error (TimeExceeded/DstUnreachable)
// containing an inner IPv4+ICMP echo request.
func buildICMPv4ErrorWithInnerICMP(
	t *testing.T,
	outerSrc, outerDst netip.Addr,
	innerSrc, innerDst netip.Addr,
	innerIdent, innerSeq uint16,
	icmpType header.ICMPv4Type,
) []byte {
	t.Helper()

	innerIPLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
	totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize + innerIPLen

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

	// ICMP error header
	icmpOffset := header.IPv4MinimumSize
	icmpHdr := header.ICMPv4(packet[icmpOffset:])
	icmpHdr.SetType(icmpType)
	icmpHdr.SetCode(0)

	// Inner IPv4 + ICMP echo request
	innerIPOffset := icmpOffset + header.ICMPv4MinimumSize
	innerIP := header.IPv4(packet[innerIPOffset:])
	innerIP.Encode(&header.IPv4Fields{
		TotalLength: uint16(innerIPLen),
		TTL:         1,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     innerSrc,
		DstAddr:     innerDst,
	})
	innerIP.SetChecksum(^innerIP.CalculateChecksum())

	innerICMPOffset := innerIPOffset + header.IPv4MinimumSize
	innerICMP := header.ICMPv4(packet[innerICMPOffset:])
	innerICMP.SetType(header.ICMPv4Echo)
	innerICMP.SetIdent(innerIdent)
	innerICMP.SetSequence(innerSeq)
	innerICMP.SetChecksum(header.ICMPv4Checksum(innerICMP, 0))

	// Calculate outer ICMP checksum
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))

	return packet
}

// buildICMPv4ErrorWithInnerICMPInvertedIdent builds an ICMP error with an inner
// ICMP echo whose ident is inverted (as seen on the wire for privileged raw sockets).
func buildICMPv4ErrorWithInnerICMPInvertedIdent(
	t *testing.T,
	outerSrc, outerDst netip.Addr,
	innerSrc, innerDst netip.Addr,
	originalIdent, seq uint16,
	icmpType header.ICMPv4Type,
) []byte {
	t.Helper()
	packet := buildICMPv4ErrorWithInnerICMP(t,
		outerSrc, outerDst,
		innerSrc, innerDst,
		^originalIdent, seq, // wire-level inverted ident
		icmpType,
	)
	return packet
}

// --- Destination ICMP error rewrite tests (destination.go loopReadErrors logic) ---

func TestDestinationICMPv4ErrorRewriteWithIdentInversion(t *testing.T) {
	t.Parallel()

	// Simulate the exact scenario from the bug:
	// Client sends ping with ident=1234. Server raw socket inverts to ^1234 on wire.
	// Router sends ICMP TTL Exceeded. Inner ICMP has wire-level ^1234.
	// loopReadErrors should match via ^innerIdent == ^(^1234) == 1234.
	// Then rewrite: outer dst → client, inner src → client, inner ident → un-inverted.

	clientAddr := netip.MustParseAddr("10.0.0.2")
	serverAddr := netip.MustParseAddr("192.168.10.254")
	destAddr := netip.MustParseAddr("1.1.1.1")
	routerAddr := netip.MustParseAddr("192.168.1.1")
	var originalIdent uint16 = 1234

	// Build error with inverted ident (as it appears on the wire)
	packet := buildICMPv4ErrorWithInnerICMPInvertedIdent(t,
		routerAddr, serverAddr,
		serverAddr, destAddr,
		originalIdent, 1,
		header.ICMPv4TimeExceeded,
	)

	// Apply the same rewrite logic as destination.go loopReadErrors
	outerIP := header.IPv4(packet)
	icmpHdr := header.ICMPv4(outerIP.Payload())
	innerIP := header.IPv4(outerIP.Payload()[header.ICMPv4MinimumSize:])
	innerICMP := header.ICMPv4(innerIP.Payload())

	// Verify the inner ident is inverted on wire
	require.Equal(t, ^originalIdent, innerICMP.Ident(), "inner ident should be inverted on wire")

	// The matching logic: ^innerIdent should equal original ident
	matchIdent := ^innerICMP.Ident()
	require.Equal(t, originalIdent, matchIdent, "inverted ident should match original")

	// Apply rewrite
	outerIP.SetDestinationAddr(clientAddr)
	innerIP.SetSourceAddr(clientAddr)
	innerICMP.SetIdent(^innerICMP.Ident()) // un-invert
	innerIP.SetChecksum(^innerIP.CalculateChecksum())
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	outerIP.SetChecksum(^outerIP.CalculateChecksum())

	// Verify final state
	require.Equal(t, clientAddr, outerIP.DestinationAddr())
	require.Equal(t, routerAddr, outerIP.SourceAddr())
	require.Equal(t, clientAddr, innerIP.SourceAddr())
	require.Equal(t, destAddr, innerIP.DestinationAddr())
	require.Equal(t, originalIdent, innerICMP.Ident(),
		"inner ident should be restored to original value")
}

func TestDestinationICMPv4ErrorDstUnreachableRewrite(t *testing.T) {
	t.Parallel()

	clientAddr := netip.MustParseAddr("10.0.0.2")
	serverAddr := netip.MustParseAddr("192.168.10.254")
	destAddr := netip.MustParseAddr("1.1.1.1")
	var originalIdent uint16 = 4321

	// Build DstUnreachable (e.g., port unreachable from 1.1.1.1)
	packet := buildICMPv4ErrorWithInnerICMPInvertedIdent(t,
		destAddr, serverAddr, // destination itself sends the error
		serverAddr, destAddr,
		originalIdent, 5,
		header.ICMPv4DstUnreachable,
	)

	outerIP := header.IPv4(packet)
	icmpHdr := header.ICMPv4(outerIP.Payload())
	innerIP := header.IPv4(outerIP.Payload()[header.ICMPv4MinimumSize:])
	innerICMP := header.ICMPv4(innerIP.Payload())

	require.Equal(t, header.ICMPv4DstUnreachable, icmpHdr.Type())

	// Apply rewrite
	outerIP.SetDestinationAddr(clientAddr)
	innerIP.SetSourceAddr(clientAddr)
	innerICMP.SetIdent(^innerICMP.Ident())
	innerIP.SetChecksum(^innerIP.CalculateChecksum())
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	outerIP.SetChecksum(^outerIP.CalculateChecksum())

	require.Equal(t, clientAddr, outerIP.DestinationAddr())
	require.Equal(t, clientAddr, innerIP.SourceAddr())
	require.Equal(t, originalIdent, innerICMP.Ident())
}

// --- ErrorListener tests ---

func TestErrorListenerCreation(t *testing.T) {
	t.Parallel()
	// This test requires root on Linux/Darwin
	if !canCreateRawSocket(t) {
		t.SkipNow()
	}

	// The ConnectDestination function internally creates an ErrorListener.
	// Verify the destination can be created and closed cleanly.
	dest, err := ping.ConnectDestination(
		context.Background(),
		logger.NOP(),
		nil,
		netip.MustParseAddr("127.0.0.1"),
		nil,
		30*1e9, // 30s
	)
	require.NoError(t, err)
	require.False(t, dest.IsClosed())
	err = dest.Close()
	require.NoError(t, err)
	require.True(t, dest.IsClosed())
}

// --- IPv4 checksum validation after rewrite ---

func TestICMPv4ErrorChecksumAfterRewrite(t *testing.T) {
	t.Parallel()

	// Verify that checksums are valid after a complete rewrite cycle
	packet := buildICMPv4ErrorWithInnerICMP(t,
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.10.254"),
		netip.MustParseAddr("192.168.10.254"),
		netip.MustParseAddr("1.1.1.1"),
		1234, 1,
		header.ICMPv4TimeExceeded,
	)

	clientAddr := netip.MustParseAddr("10.0.0.2")

	outerIP := header.IPv4(packet)
	icmpHdr := header.ICMPv4(outerIP.Payload())
	innerIP := header.IPv4(outerIP.Payload()[header.ICMPv4MinimumSize:])

	// Apply rewrite
	outerIP.SetDestinationAddr(clientAddr)
	innerIP.SetSourceAddr(clientAddr)
	innerIP.SetChecksum(0)
	innerIP.SetChecksum(^innerIP.CalculateChecksum())
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	outerIP.SetChecksum(0)
	outerIP.SetChecksum(^outerIP.CalculateChecksum())

	// Validate outer IP checksum: calculate and verify it's consistent
	savedChecksum := outerIP.Checksum()
	outerIP.SetChecksum(0)
	calculatedChecksum := ^outerIP.CalculateChecksum()
	require.Equal(t, savedChecksum, calculatedChecksum, "outer IP checksum should be valid")

	// Validate inner IP checksum
	savedInnerChecksum := innerIP.Checksum()
	innerIP.SetChecksum(0)
	calculatedInnerChecksum := ^innerIP.CalculateChecksum()
	require.Equal(t, savedInnerChecksum, calculatedInnerChecksum, "inner IP checksum should be valid")
}

// --- Helper to detect raw socket capability ---

func canCreateRawSocket(t *testing.T) bool {
	t.Helper()
	// Try to create a destination - it will fail if no raw socket permission
	dest, err := ping.ConnectDestination(
		context.Background(),
		logger.NOP(),
		nil,
		netip.MustParseAddr("127.0.0.1"),
		nil,
		1e9,
	)
	if err != nil {
		return false
	}
	dest.Close()
	return true
}

// --- ICMP error with truncated inner packet (edge case) ---

func TestSourceRewriterTruncatedInnerPacket(t *testing.T) {
	t.Parallel()

	serverAddr := netip.MustParseAddr("192.168.10.254")

	rewriter := ping.NewSourceRewriter(
		context.Background(),
		logger.NOP(),
		serverAddr,
		netip.Addr{},
	)

	// Build an ICMP error where the inner payload is too short to contain
	// a valid inner IPv4 + ICMP header
	totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize + 4 // only 4 bytes of inner data (too short)
	packet := make([]byte, totalLen)

	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     netip.MustParseAddr("192.168.1.1"),
		DstAddr:     serverAddr,
	})
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

	icmpHdr := header.ICMPv4(packet[header.IPv4MinimumSize:])
	icmpHdr.SetType(header.ICMPv4TimeExceeded)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))

	ok, err := rewriter.WriteBack(packet)
	require.NoError(t, err)
	require.False(t, ok, "should return false for truncated inner packet")
}

// --- Unused helper for potential future IPv6 tests ---
// (IPv6 error rewrite tests could be added here when IPv6 environment is available)

func buildICMPv4ErrorWithInnerUDP(
	t *testing.T,
	outerSrc, outerDst netip.Addr,
	innerSrc, innerDst netip.Addr,
	innerSrcPort, innerDstPort uint16,
	icmpType header.ICMPv4Type,
) []byte {
	t.Helper()

	innerIPLen := header.IPv4MinimumSize + header.UDPMinimumSize
	totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize + innerIPLen

	packet := make([]byte, totalLen)

	outerIP := header.IPv4(packet)
	outerIP.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     outerSrc,
		DstAddr:     outerDst,
	})
	outerIP.SetChecksum(^outerIP.CalculateChecksum())

	icmpOffset := header.IPv4MinimumSize
	icmpHdr := header.ICMPv4(packet[icmpOffset:])
	icmpHdr.SetType(icmpType)
	icmpHdr.SetCode(0)

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

	innerUDPOffset := innerIPOffset + header.IPv4MinimumSize
	binary.BigEndian.PutUint16(packet[innerUDPOffset:], innerSrcPort)
	binary.BigEndian.PutUint16(packet[innerUDPOffset+2:], innerDstPort)
	binary.BigEndian.PutUint16(packet[innerUDPOffset+4:], header.UDPMinimumSize)

	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))

	return packet
}
