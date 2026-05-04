//go:build !unix

package ping

import (
	"net/netip"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

type tcpRawConn struct{}

func connectTCPRaw(controlFunc control.Func, destination netip.Addr) (*tcpRawConn, error) {
	return nil, E.New("TCP traceroute not supported on this platform")
}

func (c *tcpRawConn) SetHopLimit(hopLimit uint8) error {
	return nil
}

func (c *tcpRawConn) Close() error {
	return nil
}
