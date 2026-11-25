package tun

import (
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

const (
	kernelConnectionRefused = windows.WSAECONNREFUSED
	kernelConnectionReset   = windows.WSAECONNRESET
)

func kernelSetSocketBuffers(descriptor uintptr, size int) error {
	return E.Errors(
		windows.SetsockoptInt(windows.Handle(descriptor), windows.SOL_SOCKET, windows.SO_RCVBUF, size),
		windows.SetsockoptInt(windows.Handle(descriptor), windows.SOL_SOCKET, windows.SO_SNDBUF, size),
	)
}

var allowKernelInboundUDP = sync.OnceValue(func() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	shortPath, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return err
	}
	longPath := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetLongPathName(shortPath, &longPath[0], uint32(len(longPath)))
	if err != nil {
		return err
	}
	executable = windows.UTF16ToString(longPath[:length])
	const name = "name=sing-tun-test"
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", name).Run()
	output, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", name, "dir=in", "action=allow", "protocol=UDP", "program="+executable, "profile=any").CombinedOutput()
	if err != nil {
		return E.Cause(err, "add firewall rule: ", string(output))
	}
	return nil
})

func configureKernelInterface(t *testing.T, device Tun, options Options) {
	t.Helper()
	err := allowKernelInboundUDP()
	if err != nil {
		t.Fatal(err)
	}
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
