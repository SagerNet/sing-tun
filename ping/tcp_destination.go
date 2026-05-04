package ping

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

var _ tun.DirectRouteDestination = (*TCPDestination)(nil)

const tcpRequestsCapacity = 4096

// TCPDestination sends raw TCP SYN packets (preserving TTL) and
// receives ICMP Time Exceeded / Destination Unreachable errors,
// enabling mtr --tcp / traceroute -T through a DirectRoute outbound.
type TCPDestination struct {
	conn          *tcpRawConn
	errorListener *ErrorListener
	ctx           context.Context
	logger        logger.ContextLogger
	destination   netip.Addr
	routeContext  tun.DirectRouteContext
	timeout       time.Duration
	closed        atomic.Bool

	// Track active TCP source ports for ICMP error matching
	requests       freelru.Cache[uint16, struct{}]
	originalSource common.TypedValue[netip.Addr]
}

func ConnectTCPDestination(
	ctx context.Context,
	logger logger.ContextLogger,
	controlFunc control.Func,
	destination netip.Addr,
	routeContext tun.DirectRouteContext,
	timeout time.Duration,
) (tun.DirectRouteDestination, error) {
	rawConn, err := connectTCPRaw(controlFunc, destination)
	if err != nil {
		return nil, err
	}
	d := &TCPDestination{
		conn:         rawConn,
		ctx:          ctx,
		logger:       logger,
		destination:  destination,
		routeContext: routeContext,
		timeout:      timeout,
		requests:     common.Must1(freelru.NewSynced[uint16, struct{}](tcpRequestsCapacity, maphash.NewHasher[uint16]().Hash32)),
	}
	d.requests.SetLifetime(timeout)

	if errorListener := tryListenErrors(ctx, logger, controlFunc, destination); errorListener != nil {
		d.errorListener = errorListener
		go d.loopReadErrors()
		logger.DebugContext(ctx, "TCP ICMP error listener started")
	} else {
		logger.WarnContext(ctx, "TCP ICMP error listener not available")
	}

	return d, nil
}

func (d *TCPDestination) WritePacket(packet *buf.Buffer) error {
	if !d.destination.Is6() {
		ipHdr := header.IPv4(packet.Bytes())
		if !ipHdr.IsValid(packet.Len()) {
			return E.New("invalid IPv4 header")
		}
		if ipHdr.TransportProtocol() != header.TCPProtocolNumber {
			return E.New("not a TCP packet")
		}
		if ipHdr.PayloadLength() < header.TCPMinimumSize {
			return E.New("invalid TCP header")
		}
		tcpHdr := header.TCP(ipHdr.Payload())
		srcPort := tcpHdr.SourcePort()

		d.originalSource.Store(ipHdr.SourceAddr())
		d.requests.Add(srcPort, struct{}{})

		d.logger.TraceContext(d.ctx, "write TCP SYN from ", ipHdr.SourceAddr(), ":", srcPort,
			" to ", ipHdr.DestinationAddr(), ":", tcpHdr.DestinationPort(), " ttl ", ipHdr.TTL())

		// For IPv4 IPPROTO_RAW (IP_HDRINCL), set source to 0.0.0.0
		// so the kernel fills in the correct outgoing IP address.
		// Without this, the source would be a private WG tunnel address
		// that is not routable on the internet, so ICMP errors from
		// intermediate routers would never reach us.
		ipHdr.SetSourceAddr(netip.IPv4Unspecified())
		ipHdr.SetChecksum(0) // kernel recomputes when source is 0
		destAddr := &net.IPAddr{
			IP: d.destination.AsSlice(),
		}
		_, err := d.conn.conn.WriteTo(packet.Bytes(), destAddr)
		packet.Release()
		return err
	} else {
		ipHdr := header.IPv6(packet.Bytes())
		if !ipHdr.IsValid(packet.Len()) {
			return E.New("invalid IPv6 header")
		}
		if ipHdr.TransportProtocol() != header.TCPProtocolNumber {
			return E.New("not a TCP packet")
		}
		if ipHdr.PayloadLength() < header.TCPMinimumSize {
			return E.New("invalid TCP header")
		}
		tcpHdr := header.TCP(ipHdr.Payload())
		srcPort := tcpHdr.SourcePort()

		d.originalSource.Store(ipHdr.SourceAddr())
		d.requests.Add(srcPort, struct{}{})

		hopLimit := ipHdr.HopLimit()
		if hopLimit > 0 {
			_ = d.conn.SetHopLimit(hopLimit)
		}

		d.logger.TraceContext(d.ctx, "write TCP SYN from ", ipHdr.SourceAddr(), ":", srcPort,
			" to ", ipHdr.DestinationAddr(), ":", tcpHdr.DestinationPort(), " hoplimit ", hopLimit)

		// For IPv6, send only the TCP segment (kernel adds IPv6 header).
		destAddr := &net.IPAddr{
			IP: d.destination.AsSlice(),
		}
		_, err := d.conn.conn.WriteTo(ipHdr.Payload(), destAddr)
		packet.Release()
		return err
	}
}

func (d *TCPDestination) loopReadErrors() {
	transportErrorLoop(
		d.errorListener, d.destination.Is6(),
		d.requests, &d.originalSource, d.routeContext,
		d.ctx, d.logger,
		header.TCPProtocolNumber, header.TCPMinimumSize, "TCP",
		func(srcPort, _ uint16) uint16 { return srcPort },
		nil,
	)
}

func (d *TCPDestination) Close() error {
	d.closed.Store(true)
	if d.errorListener != nil {
		_ = d.errorListener.Close()
	}
	return d.conn.Close()
}

func (d *TCPDestination) IsClosed() bool {
	return d.closed.Load()
}
