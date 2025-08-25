package ping

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

var _ tun.DirectRouteDestination = (*Destination)(nil)

type Destination struct {
	conn          *Conn
	ctx           context.Context
	logger        logger.ContextLogger
	destination   netip.Addr
	routeContext  tun.DirectRouteContext
	timeout       time.Duration
	requestAccess sync.Mutex
	requests      map[pingRequest]bool
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
		requests:     make(map[pingRequest]bool),
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
			if icmpHdr.Type() != header.ICMPv4EchoReply {
				continue
			}
			var requestExists bool
			request := pingRequest{Source: ipHdr.DestinationAddr(), Destination: ipHdr.SourceAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()}
			d.requestAccess.Lock()
			if d.requests[request] {
				requestExists = true
				delete(d.requests, request)
			}
			d.requestAccess.Unlock()
			if !requestExists {
				continue
			}
			d.logger.TraceContext(d.ctx, "read ICMPv4 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
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
			if icmpHdr.Type() != header.ICMPv6EchoReply {
				continue
			}
			var requestExists bool
			request := pingRequest{Source: ipHdr.DestinationAddr(), Destination: ipHdr.SourceAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()}
			d.requestAccess.Lock()
			if d.requests[request] {
				requestExists = true
				delete(d.requests, request)
			}
			d.requestAccess.Unlock()
			if !requestExists {
				continue
			}
			d.logger.TraceContext(d.ctx, "read ICMPv6 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
		}
		err = d.routeContext.WritePacket(buffer.Bytes())
		if err != nil {
			d.logger.ErrorContext(d.ctx, E.Cause(err, "write ICMP echo reply"))
		}
		buffer.Release()
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
		d.requestAccess.Lock()
		d.requests[pingRequest{Source: ipHdr.SourceAddr(), Destination: ipHdr.DestinationAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()}] = true
		d.requestAccess.Unlock()
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
		d.requestAccess.Lock()
		d.requests[pingRequest{Source: ipHdr.SourceAddr(), Destination: ipHdr.DestinationAddr(), Identifier: icmpHdr.Ident(), Sequence: icmpHdr.Sequence()}] = true
		d.requestAccess.Unlock()
		d.logger.TraceContext(d.ctx, "write ICMPv6 echo request from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr(), " id ", icmpHdr.Ident(), " seq ", icmpHdr.Sequence())
	}
	return d.conn.WriteIP(packet)
}

func (d *Destination) Close() error {
	return d.conn.Close()
}

func (d *Destination) IsClosed() bool {
	return d.conn.IsClosed()
}
