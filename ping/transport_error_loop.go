package ping

import (
	"context"
	"net/netip"

	tun "github.com/sagernet/sing-tun"
	tcpip "github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/contrab/freelru"

	"golang.org/x/net/ipv4"
)

// transportErrorLoop reads ICMP Time Exceeded and Destination Unreachable
// errors from an ErrorListener and delivers matched ones back through
// routeContext. It handles both IPv4 and IPv6, including address rewriting
// and checksum recalculation.
//
// This is shared by UDPDestination and TCPDestination. The caller provides:
//   - protocol/minSize: the expected inner transport protocol and minimum header size
//   - name: protocol name for logging ("UDP" or "TCP")
//   - matchPort: given (srcPort, dstPort), returns the port to check against requests
//   - rewritePort: optional func to rewrite ports before checksum recalculation;
//     receives the inner transport header as a byte slice
func transportErrorLoop(
	el *ErrorListener,
	isIPv6 bool,
	requests freelru.Cache[uint16, struct{}],
	originalSource *common.TypedValue[netip.Addr],
	routeCtx tun.DirectRouteContext,
	ctx context.Context,
	log logger.ContextLogger,
	protocol tcpip.TransportProtocolNumber,
	minSize int,
	name string,
	matchPort func(srcPort, dstPort uint16) uint16,
	rewritePort func(innerPayload []byte),
) {
	defer el.Close()
	for {
		buffer := buf.NewSize(1500)
		if isIPv6 {
			buffer.Advance(header.IPv6MinimumSize)
		}
		oob := make([]byte, 128)
		n, oobn, addr, err := el.ReadMsg(buffer.FreeBytes(), oob)
		if err != nil {
			buffer.Release()
			if !E.IsClosed(err) {
				log.ErrorContext(ctx, E.Cause(err, "receive ", name, " ICMP error"))
			}
			return
		}
		buffer.Truncate(n)

		forward := func() bool {
			if !isIPv6 {
				var ttl int
				if oobn > 0 {
					var cm ipv4.ControlMessage
					if cm.Parse(oob[:oobn]) == nil {
						ttl = cm.TTL
					}
				}
				ipHdr := header.IPv4(buffer.Bytes())
				if !ipHdr.IsValid(n) {
					return false
				}
				if ipHdr.PayloadLength() < header.ICMPv4MinimumSize {
					return false
				}
				icmpHdr := header.ICMPv4(ipHdr.Payload())
				switch icmpHdr.Type() {
				case header.ICMPv4TimeExceeded, header.ICMPv4DstUnreachable:
				default:
					return false
				}
				if len(ipHdr.Payload()) < header.ICMPv4MinimumSize+header.IPv4MinimumSize+minSize {
					return false
				}
				innerIPHdr := header.IPv4(ipHdr.Payload()[header.ICMPv4MinimumSize:])
				if !innerIPHdr.IsValid(len(ipHdr.Payload()) - header.ICMPv4MinimumSize) {
					return false
				}
				if innerIPHdr.TransportProtocol() != protocol {
					return false
				}
				if innerIPHdr.PayloadLength() < uint16(minSize) {
					return false
				}
				innerPayload := innerIPHdr.Payload()
				srcPort := header.UDP(innerPayload).SourcePort()
				dstPort := header.UDP(innerPayload).DestinationPort()

				log.DebugContext(ctx, name, " ICMPv4 error type ", uint8(icmpHdr.Type()),
					" from ", addr, " inner: ", innerIPHdr.SourceAddr(), ":", srcPort,
					" -> ", innerIPHdr.DestinationAddr(), ":", dstPort)

				if !requests.Contains(matchPort(srcPort, dstPort)) {
					return false
				}

				originalSrc := originalSource.Load()
				if originalSrc.IsValid() {
					ipHdr.SetDestinationAddr(originalSrc)
					innerIPHdr.SetSourceAddr(originalSrc)
					if rewritePort != nil {
						rewritePort(innerPayload)
					}
					innerIPHdr.SetChecksum(0)
					innerIPHdr.SetChecksum(^innerIPHdr.CalculateChecksum())
					icmpHdr.SetChecksum(0)
					icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
				} else {
					ipHdr.SetDestinationAddr(innerIPHdr.SourceAddr())
				}
				ipHdr.SetChecksum(0)
				ipHdr.SetChecksum(^ipHdr.CalculateChecksum())

				log.TraceContext(ctx, "read ", name, " ICMPv4 error type ", uint8(icmpHdr.Type()),
					" from ", addr, " ttl ", ttl, " -> ", ipHdr.DestinationAddr())
				return true
			}

			// IPv6
			var hopLimit int
			if oobn > 0 {
				cm, cmErr := parseIPv6ControlMessage(oob[:oobn])
				if cmErr == nil && cm != nil {
					hopLimit = cm.HopLimit
				}
			}
			if n < header.ICMPv6MinimumSize {
				return false
			}
			icmpHdr := header.ICMPv6(buffer.Bytes())
			switch icmpHdr.Type() {
			case header.ICMPv6TimeExceeded, header.ICMPv6DstUnreachable:
			default:
				return false
			}
			if n < header.ICMPv6MinimumSize+header.IPv6MinimumSize+minSize {
				return false
			}
			innerIPHdr := header.IPv6(buffer.Bytes()[header.ICMPv6MinimumSize:])
			if !innerIPHdr.IsValid(n - header.ICMPv6MinimumSize) {
				return false
			}
			if innerIPHdr.TransportProtocol() != protocol {
				return false
			}
			if innerIPHdr.PayloadLength() < uint16(minSize) {
				return false
			}
			innerPayload := innerIPHdr.Payload()
			srcPort := header.UDP(innerPayload).SourcePort()
			dstPort := header.UDP(innerPayload).DestinationPort()

			log.DebugContext(ctx, name, " ICMPv6 error type ", uint8(icmpHdr.Type()),
				" from ", addr, " inner: ", innerIPHdr.SourceAddr(), ":", srcPort,
				" -> ", innerIPHdr.DestinationAddr(), ":", dstPort)

			if !requests.Contains(matchPort(srcPort, dstPort)) {
				return false
			}

			dstAddr := addr
			originalSrc := originalSource.Load()
			if originalSrc.IsValid() {
				dstAddr = originalSrc
				innerIPHdr.SetSourceAddr(originalSrc)
				if rewritePort != nil {
					rewritePort(innerPayload)
				}
			} else {
				dstAddr = innerIPHdr.SourceAddr()
			}
			icmpHdr.SetChecksum(0)
			icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: icmpHdr,
				Src:    addr.AsSlice(),
				Dst:    dstAddr.AsSlice(),
			}))
			ipHdr := header.IPv6(buffer.ExtendHeader(header.IPv6MinimumSize))
			ipHdr.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(n),
				TransportProtocol: header.ICMPv6ProtocolNumber,
				HopLimit:          uint8(hopLimit),
				SrcAddr:           addr,
				DstAddr:           dstAddr,
			})

			log.TraceContext(ctx, "read ", name, " ICMPv6 error type ", uint8(icmpHdr.Type()),
				" from ", addr, " hoplimit ", hopLimit, " -> ", dstAddr)
			return true
		}()
		if forward {
			if err = routeCtx.WritePacket(buffer.Bytes()); err != nil {
				log.ErrorContext(ctx, E.Cause(err, "write ", name, " ICMP error"))
			}
		}
		buffer.Release()
	}
}
