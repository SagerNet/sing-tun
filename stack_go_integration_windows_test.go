package tun

import (
	"testing"

	"github.com/sagernet/sing-tun/internal/winipcfg"

	"golang.org/x/sys/windows"
)

const (
	kernelConnectionRefused = windows.WSAECONNREFUSED
	kernelConnectionReset   = windows.WSAECONNRESET
)

func configureKernelInterface(t *testing.T, device Tun, options Options) {
	t.Helper()
	luid := winipcfg.LUID(device.(*NativeTun).adapter.LUID())
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		addresses := options.Inet4Address
		if family == windows.AF_INET6 {
			addresses = options.Inet6Address
		}
		err := luid.SetIPAddressesForFamily(family, addresses)
		if err != nil {
			t.Fatal(err)
		}
		row, err := luid.IPInterface(family)
		if err != nil {
			t.Fatal(err)
		}
		row.NLMTU = options.MTU
		row.DadTransmits = 0
		row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		err = row.Set()
		if err != nil {
			t.Fatal(err)
		}
	}
}
