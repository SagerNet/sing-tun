//go:build !unix

package ping

import (
	"net/netip"
	"time"

	"github.com/sagernet/sing/common/control"
)

type ErrorListener struct{}

func listenErrors(privileged bool, controlFunc control.Func, destination netip.Addr) (*ErrorListener, error) {
	// ICMP error listening not supported on non-Unix platforms
	return nil, nil
}

func (l *ErrorListener) ReadMsg(b, oob []byte) (n, oobn int, addr netip.Addr, err error) {
	return 0, 0, netip.Addr{}, nil
}

func (l *ErrorListener) Close() error {
	return nil
}

func (l *ErrorListener) SetReadDeadline(t time.Time) error {
	return nil
}
