package tun

import (
	"math"
	"net"
	"net/netip"
	"runtime"
	"syscall"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type NativeTun struct {
	name         string
	inet4Address netip.Prefix
	inet6Address netip.Prefix
	mtu          uint32
	autoRoute    bool
	fdList       []int
}

func Open(name string, inet4Address netip.Prefix, inet6Address netip.Prefix, mtu uint32, autoRoute bool) (Tun, error) {
	tunFd, err := tun.Open(name)
	if err != nil {
		return nil, err
	}
	nativeTun := &NativeTun{
		name:         name,
		fdList:       []int{tunFd},
		mtu:          mtu,
		inet4Address: inet4Address,
		inet6Address: inet6Address,
		autoRoute:    autoRoute,
	}
	err = nativeTun.configure()
	if err != nil {
		return nil, E.Errors(err, syscall.Close(tunFd))
	}
	return nativeTun, nil
}

func (t *NativeTun) configure() error {
	tunLink, err := netlink.LinkByName(t.name)
	if err != nil {
		return err
	}
	if t.inet4Address.IsValid() {
		addr4, _ := netlink.ParseAddr(t.inet4Address.String())
		err = netlink.AddrAdd(tunLink, addr4)
		if err != nil {
			return err
		}
	}

	if t.inet6Address.IsValid() {
		addr6, _ := netlink.ParseAddr(t.inet6Address.String())
		err = netlink.AddrAdd(tunLink, addr6)
		if err != nil {
			return err
		}
	}

	err = netlink.LinkSetMTU(tunLink, int(t.mtu))
	if err != nil {
		return err
	}

	err = netlink.LinkSetUp(tunLink)
	if err != nil {
		return err
	}

	if t.autoRoute {
		if t.inet4Address.IsValid() {
			err = netlink.RouteAdd(&netlink.Route{
				Dst: &net.IPNet{
					IP:   net.IPv4zero,
					Mask: net.CIDRMask(0, 32),
				},
				LinkIndex: tunLink.Attrs().Index,
			})
			if err != nil {
				return err
			}
		}
		if t.inet6Address.IsValid() {
			err = netlink.RouteAdd(&netlink.Route{
				Dst: &net.IPNet{
					IP:   net.IPv6zero,
					Mask: net.CIDRMask(0, 128),
				},
				LinkIndex: tunLink.Attrs().Index,
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, error) {
	var packetDispatchMode fdbased.PacketDispatchMode
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		packetDispatchMode = fdbased.PacketMMap
	} else {
		packetDispatchMode = fdbased.RecvMMsg
	}
	dupFdSize := int(math.Max(float64(runtime.NumCPU()/2), 1)) - 1
	for i := 0; i < dupFdSize; i++ {
		dupFd, err := syscall.Dup(t.fdList[0])
		if err != nil {
			return nil, err
		}
		t.fdList = append(t.fdList, dupFd)
	}
	return fdbased.New(&fdbased.Options{
		FDs:                t.fdList,
		MTU:                t.mtu,
		PacketDispatchMode: packetDispatchMode,
	})
}

func (t *NativeTun) Close() error {
	tunLink, err := netlink.LinkByName(t.name)
	if err != nil {
		return err
	}
	if t.autoRoute {
		if t.inet4Address.IsValid() {
			err = netlink.RouteDel(&netlink.Route{
				Dst: &net.IPNet{
					IP:   net.IPv4zero,
					Mask: net.CIDRMask(0, 32),
				},
				LinkIndex: tunLink.Attrs().Index,
			})
			if err != nil {
				return err
			}
		}
		if t.inet6Address.IsValid() {
			err = netlink.RouteDel(&netlink.Route{
				Dst: &net.IPNet{
					IP:   net.IPv6zero,
					Mask: net.CIDRMask(0, 128),
				},
				LinkIndex: tunLink.Attrs().Index,
			})
			if err != nil {
				return err
			}
		}
	}
	return E.Errors(common.Map(t.fdList, syscall.Close)...)
}
