//go:build linux && !android

package tun

import (
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

const kernelMaxDatagram = 60000

func kernelAddUnreachableRoute(t *testing.T, prefix netip.Prefix) bool {
	t.Helper()
	route := &netlink.Route{
		Dst:  &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())},
		Type: unix.RTN_UNREACHABLE,
	}
	err := netlink.RouteAdd(route)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netlink.RouteDel(route) })
	return true
}
