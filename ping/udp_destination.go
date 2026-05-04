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

var _ tun.DirectRouteDestination = (*UDPDestination)(nil)

const udpRequestsCapacity = 4096

type UDPDestination struct {
	conn          *net.UDPConn
	errorListener *ErrorListener
	ctx           context.Context
	logger        logger.ContextLogger
	destination   netip.Addr
	routeContext  tun.DirectRouteContext
	timeout       time.Duration
	closed        atomic.Bool

	// Track active UDP destination ports for ICMP error matching
	requests           freelru.Cache[uint16, struct{}]
	originalSource     common.TypedValue[netip.Addr]
	originalSourcePort uint16 // client's original UDP source port
	localPort          uint16 // kernel-assigned local UDP source port
}

func ConnectUDPDestination(
	ctx context.Context,
	logger logger.ContextLogger,
	controlFunc control.Func,
	destination netip.Addr,
	routeContext tun.DirectRouteContext,
	timeout time.Duration,
) (tun.DirectRouteDestination, error) {
	udpConn, err := connectUDP(controlFunc, destination)
	if err != nil {
		return nil, err
	}
	d := &UDPDestination{
		conn:         udpConn,
		ctx:          ctx,
		logger:       logger,
		destination:  destination,
		routeContext: routeContext,
		timeout:      timeout,
		requests:     common.Must1(freelru.NewSynced[uint16, struct{}](udpRequestsCapacity, maphash.NewHasher[uint16]().Hash32)),
	}
	d.requests.SetLifetime(timeout)
	if localAddr, ok := udpConn.LocalAddr().(*net.UDPAddr); ok {
		d.localPort = uint16(localAddr.Port)
	}

	if errorListener := tryListenErrors(ctx, logger, controlFunc, destination); errorListener != nil {
		d.errorListener = errorListener
		go d.loopReadErrors()
		logger.DebugContext(ctx, "UDP ICMP error listener started")
	} else {
		logger.WarnContext(ctx, "UDP ICMP error listener not available")
	}

	return d, nil
}

func (d *UDPDestination) WritePacket(packet *buf.Buffer) error {
	if !d.destination.Is6() {
		ipHdr := header.IPv4(packet.Bytes())
		if !ipHdr.IsValid(packet.Len()) {
			return E.New("invalid IPv4 header")
		}
		if ipHdr.TransportProtocol() != header.UDPProtocolNumber {
			return E.New("not a UDP packet")
		}
		if ipHdr.PayloadLength() < header.UDPMinimumSize {
			return E.New("invalid UDP header")
		}
		udpHdr := header.UDP(ipHdr.Payload())
		srcPort := udpHdr.SourcePort()
		dstPort := udpHdr.DestinationPort()

		d.originalSource.Store(ipHdr.SourceAddr())
		d.originalSourcePort = srcPort

		// Register destination port for ICMP error matching
		d.requests.Add(dstPort, struct{}{})

		ttl := ipHdr.TTL()
		if ttl > 0 {
			_ = setUDPTTL(d.conn, false, ttl)
		}

		d.logger.TraceContext(d.ctx, "write UDP from ", ipHdr.SourceAddr(), ":", srcPort, " to ", ipHdr.DestinationAddr(), ":", dstPort, " ttl ", ttl)

		// Send UDP payload to the correct destination port
		destAddr := &net.UDPAddr{
			IP:   d.destination.AsSlice(),
			Port: int(dstPort),
		}
		udpPayload := udpHdr.Payload()
		_, err := d.conn.WriteTo(udpPayload, destAddr)
		packet.Release()
		return err
	} else {
		ipHdr := header.IPv6(packet.Bytes())
		if !ipHdr.IsValid(packet.Len()) {
			return E.New("invalid IPv6 header")
		}
		if ipHdr.TransportProtocol() != header.UDPProtocolNumber {
			return E.New("not a UDP packet")
		}
		if ipHdr.PayloadLength() < header.UDPMinimumSize {
			return E.New("invalid UDP header")
		}
		udpHdr := header.UDP(ipHdr.Payload())
		srcPort := udpHdr.SourcePort()
		dstPort := udpHdr.DestinationPort()

		d.originalSource.Store(ipHdr.SourceAddr())
		d.originalSourcePort = srcPort

		// Register destination port for ICMP error matching
		d.requests.Add(dstPort, struct{}{})

		hopLimit := ipHdr.HopLimit()
		if hopLimit > 0 {
			_ = setUDPTTL(d.conn, true, hopLimit)
		}

		d.logger.TraceContext(d.ctx, "write UDP from ", ipHdr.SourceAddr(), ":", srcPort, " to ", ipHdr.DestinationAddr(), ":", dstPort, " hoplimit ", hopLimit)

		destAddr := &net.UDPAddr{
			IP:   d.destination.AsSlice(),
			Port: int(dstPort),
		}
		udpPayload := udpHdr.Payload()
		_, err := d.conn.WriteTo(udpPayload, destAddr)
		packet.Release()
		return err
	}
}

func (d *UDPDestination) loopReadErrors() {
	transportErrorLoop(
		d.errorListener, d.destination.Is6(),
		d.requests, &d.originalSource, d.routeContext,
		d.ctx, d.logger,
		header.UDPProtocolNumber, header.UDPMinimumSize, "UDP",
		func(_, dstPort uint16) uint16 { return dstPort },
		func(innerPayload []byte) {
			if d.originalSourcePort != 0 && d.localPort != 0 {
				innerUDP := header.UDP(innerPayload)
				if innerUDP.SourcePort() == d.localPort {
					innerUDP.SetSourcePort(d.originalSourcePort)
				}
			}
		},
	)
}

func (d *UDPDestination) Close() error {
	d.closed.Store(true)
	if d.errorListener != nil {
		_ = d.errorListener.Close()
	}
	return d.conn.Close()
}

func (d *UDPDestination) IsClosed() bool {
	return d.closed.Load()
}
