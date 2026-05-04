package ping

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var _ tun.DirectRouteDestination = (*Destination)(nil)

type Destination struct {
	conn           *Conn
	errorListener  *ErrorListener
	ctx            context.Context
	logger         logger.ContextLogger
	destination    netip.Addr
	routeContext   tun.DirectRouteContext
	timeout        time.Duration
	requestAccess  sync.Mutex
	requests       map[pingRequest]time.Time
	originalSource common.TypedValue[netip.Addr]
}

type pingRequest struct {
	Source      netip.Addr
	Destination netip.Addr
	Identifier  uint16
	Sequence    uint16
}

func ConnectDestination(
	ctx context.Context,
	logger logger.ContextLogger,
	controlFunc control.Func,
	destination netip.Addr,
	routeContext tun.DirectRouteContext,
	timeout time.Duration,
) (tun.DirectRouteDestination, error) {
	var (
		conn *Conn
		err  error
	)
	switch runtime.GOOS {
	case "darwin", "ios", "windows":
		conn, err = Connect(ctx, false, controlFunc, destination)
	default:
		conn, err = Connect(ctx, true, controlFunc, destination)
		if errors.Is(err, os.ErrPermission) {
			conn, err = Connect(ctx, false, controlFunc, destination)
		}
	}
	if err != nil {
		return nil, err
	}
	d := &Destination{
		conn:         conn,
		ctx:          ctx,
		logger:       logger,
		destination:  destination,
		routeContext: routeContext,
		timeout:      timeout,
		requests:     make(map[pingRequest]time.Time),
	}

	if errorListener := tryListenErrors(ctx, logger, controlFunc, destination); errorListener != nil {
		d.errorListener = errorListener
		go d.loopReadErrors()
		logger.DebugContext(ctx, "ICMP error listener started")
	} else {
		logger.WarnContext(ctx, "ICMP error listener not available")
	}

	go d.loopRead()
	return d, nil
}

func (d *Destination) loopRead() {
	defer d.Close()
	for {
		buffer := buf.NewPacket()
		err := d.conn.SetReadDeadline(time.Now().Add(d.timeout))
		if err != nil {
			d.logger.ErrorContext(d.ctx, E.Cause(err, "set read deadline for ICMP conn"))
		}
		err = d.conn.ReadIP(buffer)
		if err != nil {
			buffer.Release()
			if !E.IsClosed(err) {
				d.logger.ErrorContext(d.ctx, E.Cause(err, "receive ICMP echo reply"))
			}
			return
		}
		if !d.destination.Is6() {
			ipHdr := header.IPv4(buffer.Bytes())
			if !ipHdr.IsValid(buffer.Len()) {
				d.logger.ErrorContext(d.ctx, E.New("invalid IPv4 header received"))
				continue
			}
			if ipHdr.PayloadLength() < header.ICMPv4MinimumSize {
				d.logger.ErrorContext(d.ctx, E.New("invalid ICMPv4 header received"))
				continue
			}
			icmpHdr := header.ICMPv4(ipHdr.Payload())
			switch icmpHdr.Type() {
			case header.ICMPv4EchoReply:
				if d.needFilter() {
					request := pingRequest{Source: ipHdr.DestinationAddr(), Destination: ipHdr.SourceAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()}
					d.requestAccess.Lock()
					_, loaded := d.requests[request]
					if loaded {
						delete(d.requests, request)
					}
					d.requestAccess.Unlock()
					if !loaded {
						continue
					}
				}
				d.logger.TraceContext(d.ctx, "read ICMPv4 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
			default:
				continue
			}
		} else {
			ipHdr := header.IPv6(buffer.Bytes())
			if !ipHdr.IsValid(buffer.Len()) {
				d.logger.ErrorContext(d.ctx, E.New("invalid IPv6 header received"))
				continue
			}
			if ipHdr.PayloadLength() < header.ICMPv6MinimumSize {
				d.logger.ErrorContext(d.ctx, E.New("invalid ICMPv6 header received"))
				continue
			}
			icmpHdr := header.ICMPv6(ipHdr.Payload())
			switch icmpHdr.Type() {
			case header.ICMPv6EchoReply:
				if d.needFilter() {
					request := pingRequest{Source: ipHdr.DestinationAddr(), Destination: ipHdr.SourceAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()}
					d.requestAccess.Lock()
					_, loaded := d.requests[request]
					if loaded {
						delete(d.requests, request)
					}
					d.requestAccess.Unlock()
					if !loaded {
						continue
					}
				}
				d.logger.TraceContext(d.ctx, "read ICMPv6 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
			default:
				continue
			}
		}
		err = d.routeContext.WritePacket(buffer.Bytes())
		if err != nil {
			d.logger.ErrorContext(d.ctx, E.Cause(err, "write ICMP echo reply"))
		}
		buffer.Release()
	}
}

func (d *Destination) loopReadErrors() {
	defer d.errorListener.Close()
	for {
		buffer := buf.NewSize(1500)
		if d.destination.Is6() {
			// IPv6 raw sockets don't include the IPv6 header in received data;
			// reserve space so we can prepend one later.
			buffer.Advance(header.IPv6MinimumSize)
		}
		oob := make([]byte, 128)
		n, oobn, addr, err := d.errorListener.ReadMsg(buffer.FreeBytes(), oob)
		if err != nil {
			buffer.Release()
			if !E.IsClosed(err) {
				d.logger.ErrorContext(d.ctx, E.Cause(err, "receive ICMP error"))
			}
			return
		}
		buffer.Truncate(n)
		d.logger.DebugContext(d.ctx, "received raw ICMP packet from ", addr, " size ", n)

		if !d.destination.Is6() {
			var ttl int
			if oobn > 0 {
				var cm ipv4.ControlMessage
				err = cm.Parse(oob[:oobn])
				if err == nil {
					ttl = cm.TTL
				}
			}
			ipHdr := header.IPv4(buffer.Bytes())
			if !ipHdr.IsValid(n) {
				continue
			}
			if ipHdr.PayloadLength() < header.ICMPv4MinimumSize {
				continue
			}
			icmpHdr := header.ICMPv4(ipHdr.Payload())
			d.logger.DebugContext(d.ctx, "ICMPv4 error type ", uint8(icmpHdr.Type()), " from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr())
			switch icmpHdr.Type() {
			case header.ICMPv4TimeExceeded, header.ICMPv4DstUnreachable:
				if len(ipHdr.Payload()) < header.ICMPv4MinimumSize+header.IPv4MinimumSize+header.ICMPv4MinimumSize {
					continue
				}
				innerIPHdr := header.IPv4(ipHdr.Payload()[header.ICMPv4MinimumSize:])
				if !innerIPHdr.IsValid(len(ipHdr.Payload()) - header.ICMPv4MinimumSize) {
					continue
				}
				if innerIPHdr.PayloadLength() < header.ICMPv4MinimumSize {
					continue
				}
				innerICMPHdr := header.ICMPv4(innerIPHdr.Payload())
				d.logger.DebugContext(d.ctx, "ICMPv4 error inner: src=", innerIPHdr.SourceAddr(), " dst=", innerIPHdr.DestinationAddr(), " ident=", innerICMPHdr.Ident(), " seq=", innerICMPHdr.Sequence())
				if d.needFilter() {
					// The inner packet reflects the wire-level packet: source is the kernel's
					// real IP (not the tunnel client IP) and ident is inverted (for privileged
					// raw sockets). Invert ident back and match.
					matchIdent := ^innerICMPHdr.Ident()
					originalSource := d.originalSource.Load()
					request := pingRequest{Source: originalSource, Destination: innerIPHdr.DestinationAddr(), Identifier: matchIdent, Sequence: innerICMPHdr.Sequence()}
					d.requestAccess.Lock()
					_, loaded := d.requests[request]
					d.requestAccess.Unlock()
					if !loaded {
						d.logger.DebugContext(d.ctx, "ICMPv4 error: no matching request found")
						continue
					}
				}
				// Rewrite the error packet so it can be routed back through the tunnel:
				// - outer destination → original client tunnel IP
				// - inner source → original client tunnel IP
				// - inner ident → original (pre-inversion) ident
				originalSource := d.originalSource.Load()
				if originalSource.IsValid() {
					ipHdr.SetDestinationAddr(originalSource)
					innerIPHdr.SetSourceAddr(originalSource)
					innerIPHdr.SetChecksum(^innerIPHdr.CalculateChecksum())
					innerICMPHdr.SetIdent(^innerICMPHdr.Ident())
					icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
				} else {
					ipHdr.SetDestinationAddr(innerIPHdr.SourceAddr())
				}
				ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
				d.logger.TraceContext(d.ctx, "read ICMPv4 error type ", uint8(icmpHdr.Type()), " from ", addr, " ttl ", ttl, " -> ", ipHdr.DestinationAddr())
			default:
				continue
			}
		} else {
			var hopLimit int
			if oobn > 0 {
				var cm *ipv6.ControlMessage
				cm, err = parseIPv6ControlMessage(oob[:oobn])
				if err == nil && cm != nil {
					hopLimit = cm.HopLimit
				}
			}
			// IPv6 raw sockets return ICMPv6 payload only (no IPv6 header)
			if n < header.ICMPv6MinimumSize {
				continue
			}
			icmpHdr := header.ICMPv6(buffer.Bytes())
			d.logger.DebugContext(d.ctx, "ICMPv6 error type ", uint8(icmpHdr.Type()), " from ", addr)
			switch icmpHdr.Type() {
			case header.ICMPv6TimeExceeded, header.ICMPv6DstUnreachable:
				if n < header.ICMPv6MinimumSize+header.IPv6MinimumSize+header.ICMPv6MinimumSize {
					continue
				}
				innerIPHdr := header.IPv6(buffer.Bytes()[header.ICMPv6MinimumSize:])
				if !innerIPHdr.IsValid(n - header.ICMPv6MinimumSize) {
					continue
				}
				if innerIPHdr.PayloadLength() < header.ICMPv6MinimumSize {
					continue
				}
				innerICMPHdr := header.ICMPv6(innerIPHdr.Payload())
				if d.needFilter() {
					matchIdent := ^innerICMPHdr.Ident()
					originalSource := d.originalSource.Load()
					request := pingRequest{Source: originalSource, Destination: innerIPHdr.DestinationAddr(), Identifier: matchIdent, Sequence: innerICMPHdr.Sequence()}
					d.requestAccess.Lock()
					_, loaded := d.requests[request]
					d.requestAccess.Unlock()
					if !loaded {
						continue
					}
				}
				dstAddr := addr
				originalSource := d.originalSource.Load()
				if originalSource.IsValid() {
					dstAddr = originalSource
					innerIPHdr.SetSourceAddr(originalSource)
					innerICMPHdr.SetIdent(^innerICMPHdr.Ident())
					innerICMPHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
						Header: innerICMPHdr,
						Src:    innerIPHdr.SourceAddressSlice(),
						Dst:    innerIPHdr.DestinationAddressSlice(),
					}))
				} else {
					dstAddr = innerIPHdr.SourceAddr()
				}
				icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
					Header: icmpHdr,
					Src:    addr.AsSlice(),
					Dst:    dstAddr.AsSlice(),
				}))
				// Prepend synthesized IPv6 header
				ipHdr := header.IPv6(buffer.ExtendHeader(header.IPv6MinimumSize))
				ipHdr.Encode(&header.IPv6Fields{
					PayloadLength:     uint16(n),
					TransportProtocol: header.ICMPv6ProtocolNumber,
					HopLimit:          uint8(hopLimit),
					SrcAddr:           addr,
					DstAddr:           dstAddr,
				})
				d.logger.TraceContext(d.ctx, "read ICMPv6 error type ", uint8(icmpHdr.Type()), " from ", addr, " hoplimit ", hopLimit, " -> ", dstAddr)
			default:
				continue
			}
		}
		err = d.routeContext.WritePacket(buffer.Bytes())
		if err != nil {
			d.logger.ErrorContext(d.ctx, E.Cause(err, "write ICMP error"))
		}
	}
}

func (d *Destination) WritePacket(packet *buf.Buffer) error {
	if !d.destination.Is6() {
		ipHdr := header.IPv4(packet.Bytes())
		if !ipHdr.IsValid(packet.Len()) {
			return E.New("invalid IPv4 header")
		}
		if ipHdr.PayloadLength() < header.ICMPv4MinimumSize {
			return E.New("invalid ICMPv4 header")
		}
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		d.originalSource.Store(ipHdr.SourceAddr())
		if d.needFilter() {
			d.registerRequest(pingRequest{Source: ipHdr.SourceAddr(), Destination: ipHdr.DestinationAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()})
		}
		ttl := ipHdr.TTL()
		if ttl > 0 {
			_ = d.conn.SetTTL(ttl)
		}
		d.logger.TraceContext(d.ctx, "write ICMPv4 echo request from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
	} else {
		ipHdr := header.IPv6(packet.Bytes())
		if !ipHdr.IsValid(packet.Len()) {
			return E.New("invalid IPv6 header")
		}
		if ipHdr.PayloadLength() < header.ICMPv6MinimumSize {
			return E.New("invalid ICMPv6 header")
		}
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		d.originalSource.Store(ipHdr.SourceAddr())
		if d.needFilter() {
			d.registerRequest(pingRequest{Source: ipHdr.SourceAddr(), Destination: ipHdr.DestinationAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()})
		}
		hopLimit := ipHdr.HopLimit()
		if hopLimit > 0 {
			_ = d.conn.SetTTL(hopLimit)
		}
		d.logger.TraceContext(d.ctx, "write ICMPv6 echo request from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
	}
	return d.conn.WriteIP(packet)
}

func (d *Destination) needFilter() bool {
	return !d.conn.isLinuxUnprivileged()
}

func (d *Destination) registerRequest(request pingRequest) {
	const requestsLimit = 1024
	d.requestAccess.Lock()
	defer d.requestAccess.Unlock()
	now := time.Now()
	var (
		oldestRequest  pingRequest
		oldestCreateAt = now
	)
	for oldRequest, createdAt := range d.requests {
		if now.Sub(createdAt) > d.timeout {
			delete(d.requests, oldRequest)
		} else if createdAt.Before(oldestCreateAt) {
			oldestRequest = oldRequest
			oldestCreateAt = createdAt
		}
	}
	if len(d.requests) > requestsLimit {
		delete(d.requests, oldestRequest)
	}
	d.requests[request] = now
}

func (d *Destination) Close() error {
	if d.errorListener != nil {
		_ = d.errorListener.Close()
	}
	return d.conn.Close()
}

func (d *Destination) IsClosed() bool {
	return d.conn.IsClosed()
}
