//go:build !unix

package ping

import (
	"net"
	"net/netip"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

func connectUDP(controlFunc control.Func, destination netip.Addr) (*net.UDPConn, error) {
	return nil, E.New("UDP traceroute not supported on this platform")
}

func setUDPTTL(conn *net.UDPConn, isIPv6 bool, ttl uint8) error {
	return nil
}
