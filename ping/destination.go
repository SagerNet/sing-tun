package ping

import (
	"errors"
	"net/netip"
	"os"
	"runtime"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

var _ tun.DirectRouteDestination = (*Destination)(nil)

type Destination struct {
	logger       logger.Logger
	routeContext tun.DirectRouteContext
	conn         *Conn
}

func ConnectDestination(logger logger.Logger, controlFunc control.Func, address netip.Addr, routeContext tun.DirectRouteContext) (tun.DirectRouteDestination, error) {
	var (
		conn *Conn
		err  error
	)
	switch runtime.GOOS {
	case "darwin", "ios", "windows":
		conn, err = Connect(false, controlFunc, address)
	default:
		conn, err = Connect(true, controlFunc, address)
		if errors.Is(err, os.ErrPermission) {
			conn, err = Connect(false, controlFunc, address)
		}
	}
	if err != nil {
		return nil, err
	}
	d := &Destination{
		logger:       logger,
		routeContext: routeContext,
		conn:         conn,
	}
	go d.loopRead()
	return d, nil
}

func (d *Destination) loopRead() {
	for {
		buffer := buf.NewPacket()
		err := d.conn.ReadIP(buffer)
		if err != nil {
			buffer.Release()
			if !E.IsClosed(err) {
				d.logger.Error(E.Cause(err, "receive ICMP echo reply"))
			}
			return
		}
		err = d.routeContext.WritePacket(buffer.Bytes())
		if err != nil {
			d.logger.Error(E.Cause(err, "write ICMP echo reply"))
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
