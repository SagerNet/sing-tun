package ping

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

var _ tun.DirectRouteDestination = (*Destination)(nil)

type Destination struct {
	conn         *Conn
	ctx          context.Context
	logger       logger.ContextLogger
	routeContext tun.DirectRouteContext
	timeout      time.Duration
}

func ConnectDestination(
	ctx context.Context,
	logger logger.ContextLogger,
	controlFunc control.Func,
	address netip.Addr,
	routeContext tun.DirectRouteContext,
	timeout time.Duration,
) (tun.DirectRouteDestination, error) {
	var (
		conn *Conn
		err  error
	)
	switch runtime.GOOS {
	case "darwin", "ios", "windows":
		conn, err = Connect(ctx, logger, false, controlFunc, address)
	default:
		conn, err = Connect(ctx, logger, true, controlFunc, address)
		if errors.Is(err, os.ErrPermission) {
			conn, err = Connect(ctx, logger, false, controlFunc, address)
		}
	}
	if err != nil {
		return nil, err
	}
	d := &Destination{
		conn:         conn,
		ctx:          ctx,
		logger:       logger,
		routeContext: routeContext,
		timeout:      timeout,
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
		err = d.routeContext.WritePacket(buffer.Bytes())
		if err != nil {
			d.logger.ErrorContext(d.ctx, E.Cause(err, "write ICMP echo reply"))
		}
		buffer.Release()
	}
}

func (d *Destination) WritePacket(packet *buf.Buffer) error {
	return d.conn.WriteIP(packet)
}

func (d *Destination) Close() error {
	return d.conn.Close()
}

func (d *Destination) IsClosed() bool {
	return d.conn.IsClosed()
}
