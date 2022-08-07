package tun

import (
	"net"
	"net/netip"
	"unsafe"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"

	"golang.org/x/sys/unix"
)

type NativeTun struct {
	name         string
	fd           int
	inet4Address netip.Prefix
	inet6Address netip.Prefix
	mtu          uint32
	autoRoute    bool
}

func Open(name string, inet4Address netip.Prefix, inet6Address netip.Prefix, mtu uint32, autoRoute bool) (Tun, error) {
	tunFd, err := open(name)
	if err != nil {
		return nil, err
	}
	tunLink, err := netlink.LinkByName(name)
	if err != nil {
		return nil, E.Errors(err, unix.Close(tunFd))
	}
	nativeTun := &NativeTun{
		name:         name,
		fd:           tunFd,
		mtu:          mtu,
		inet4Address: inet4Address,
		inet6Address: inet6Address,
		autoRoute:    autoRoute,
	}
	err = nativeTun.configure(tunLink)
	if err != nil {
		return nil, E.Errors(err, unix.Close(tunFd))
	}
	return nativeTun, nil
}

var controlPath string

func init() {
	const defaultTunPath = "/dev/net/tun"
	const androidTunPath = "/dev/tun"
	if rw.FileExists(androidTunPath) {
		controlPath = androidTunPath
	} else {
		controlPath = defaultTunPath
	}
}

func open(name string) (int, error) {
	fd, err := unix.Open(controlPath, unix.O_RDWR, 0)
	if err != nil {
		return -1, err
	}

	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}

	copy(ifr.name[:], name)
	ifr.flags = unix.IFF_TUN | unix.IFF_NO_PI
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		unix.Close(fd)
		return -1, errno
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return -1, err
	}

	return fd, nil
}

func (t *NativeTun) configure(tunLink netlink.Link) error {
	err := netlink.LinkSetMTU(tunLink, int(t.mtu))
	if err == unix.EPERM {
		// unprivileged
		return nil
	} else if err != nil {
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

	err = netlink.LinkSetUp(tunLink)
	if err != nil {
		return err
	}

	if t.autoRoute {
		_ = t.unsetRoute0(tunLink)
		err = t.setRoute(tunLink)
		if err != nil {
			_ = t.unsetRoute0(tunLink)
			return err
		}
	}
	return nil
}

func (t *NativeTun) Close() error {
	var errors []error
	if t.autoRoute {
		errors = append(errors, t.unsetRoute())
	}
	errors = append(errors, unix.Close(t.fd))
	return E.Errors(errors...)
}

const tunTableIndex = 2022

func (t *NativeTun) routes(tunLink netlink.Link) []netlink.Route {
	var routes []netlink.Route
	if t.inet4Address.IsValid() {
		routes = append(routes, netlink.Route{
			Dst: &net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, 32),
			},
			LinkIndex: tunLink.Attrs().Index,
			Table:     tunTableIndex,
		})
	}
	if t.inet6Address.IsValid() {
		routes = append(routes, netlink.Route{
			Dst: &net.IPNet{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, 128),
			},
			LinkIndex: tunLink.Attrs().Index,
			Table:     tunTableIndex,
		})
	}
	return routes
}

func (t *NativeTun) rules() []*netlink.Rule {
	var rules []*netlink.Rule

	priority := 9000

	it := netlink.NewRule()
	it.Priority = priority
	it.Invert = true
	it.UIDRange = netlink.NewRuleUIDRange(0, 0xFFFFFFFF-1)
	it.Goto = 9100
	rules = append(rules, it)
	priority++

	if t.inet4Address.IsValid() {
		it = netlink.NewRule()
		it.Priority = priority
		it.Dst = t.inet4Address.Masked()
		it.Table = tunTableIndex
		rules = append(rules, it)
		priority++

		it = netlink.NewRule()
		it.Priority = priority
		it.IPProto = unix.IPPROTO_ICMP
		it.Goto = 9100
		rules = append(rules, it)
		priority++
	}

	if t.inet6Address.IsValid() {
		it = netlink.NewRule()
		it.Priority = priority
		it.Dst = t.inet6Address.Masked()
		it.Table = tunTableIndex
		rules = append(rules, it)
		priority++

		it = netlink.NewRule()
		it.Priority = priority
		it.IPProto = unix.IPPROTO_ICMPV6
		it.Goto = 9100
		rules = append(rules, it)
		priority++
	}

	it = netlink.NewRule()
	it.Priority = priority
	it.Invert = true
	it.Dport = netlink.NewRulePortRange(53, 53)
	it.Table = unix.RT_TABLE_MAIN
	it.SuppressPrefixlen = 0
	rules = append(rules, it)
	priority++

	it = netlink.NewRule()
	it.Priority = priority
	it.Invert = true
	it.IifName = "lo"
	it.Table = tunTableIndex
	rules = append(rules, it)
	priority++

	it = netlink.NewRule()
	it.Priority = priority
	it.IifName = "lo"
	it.Src = netip.PrefixFrom(netip.IPv4Unspecified(), 32)
	it.Table = tunTableIndex
	rules = append(rules, it)
	priority++

	if t.inet4Address.IsValid() {
		it = netlink.NewRule()
		it.Priority = priority
		it.IifName = "lo"
		it.Src = t.inet4Address.Masked()
		it.Table = tunTableIndex
		rules = append(rules, it)
		priority++
	}

	if t.inet6Address.IsValid() {
		it = netlink.NewRule()
		it.Priority = priority
		it.IifName = "lo"
		it.Src = t.inet6Address.Masked()
		it.Table = tunTableIndex
		rules = append(rules, it)
		priority++
	}

	it = netlink.NewRule()
	it.Priority = 9100
	rules = append(rules, it)

	return rules
}

func (t *NativeTun) setRoute(tunLink netlink.Link) error {
	for i, route := range t.routes(tunLink) {
		err := netlink.RouteAdd(&route)
		if err != nil {
			return E.Cause(err, "add route ", i)
		}
	}
	for i, rule := range t.rules() {
		err := netlink.RuleAdd(rule)
		if err != nil {
			return E.Cause(err, "add rule ", i, "/", len(t.rules()))
		}
	}
	return nil
}

func (t *NativeTun) unsetRoute() error {
	tunLink, err := netlink.LinkByName(t.name)
	if err != nil {
		return err
	}
	return t.unsetRoute0(tunLink)
}

func (t *NativeTun) unsetRoute0(tunLink netlink.Link) error {
	var errors []error
	for _, route := range t.routes(tunLink) {
		err := netlink.RouteDel(&route)
		if err != nil {
			errors = append(errors, err)
		}
	}
	for _, rule := range t.rules() {
		err := netlink.RuleDel(rule)
		if err != nil {
			errors = append(errors, err)
		}
	}
	return E.Errors(errors...)
}
