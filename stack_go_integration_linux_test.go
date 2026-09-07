//go:build linux && !android

package tun

import (
	"testing"
	"time"

	"github.com/sagernet/netlink"

	"golang.org/x/sys/unix"
)

const (
	kernelConnectionRefused = unix.ECONNREFUSED
	kernelConnectionReset   = unix.ECONNRESET
)

func configureKernelInterface(t *testing.T, device Tun, options Options) {
	t.Helper()
	link, err := netlink.LinkByName(options.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range append(options.Inet4Address, options.Inet6Address...) {
		address, parseErr := netlink.ParseAddr(prefix.String())
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		address.Flags = unix.IFA_F_NODAD
		err = netlink.AddrAdd(link, address)
		if err != nil {
			t.Fatal(err)
		}
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range options.Inet6Address {
		deadline := time.Now().Add(time.Second)
		for {
			routes, routeErr := netlink.RouteGet(prefix.Addr().AsSlice())
			if routeErr != nil {
				t.Fatal(routeErr)
			}
			if len(routes) > 0 && routes[0].Type == unix.RTN_LOCAL {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("IPv6 local route was not installed: %s", prefix.Addr())
			}
			t.Log("waiting for IPv6 local route:", prefix.Addr())
			time.Sleep(time.Millisecond)
		}
	}
}
