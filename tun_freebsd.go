/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */
// The code about tun configuration was obtained partially from wireguard-go.

package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const PacketOffset = 4

type NativeTun struct {
	tunFile      *os.File
	tunResolv    string
	tunWriter    N.VectorisedWriter
	options      Options
	inet4Address [4]byte
	inet6Address [16]byte
	routeSet     bool
}

func (t *NativeTun) Name() (string, error) {
	return getTunName(t.tunFile)
}

func New(options Options) (Tun, error) {
	var nativeTun *NativeTun
	var tunFd int
	if options.FileDescriptor == 0 {
		if len(options.Name) > unix.IFNAMSIZ-1 {
			return nil, E.New("interface name too long: ", options.Name)
		}

		tunFile, err := os.OpenFile("/dev/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}

		assignedName, err := getTunName(tunFile)
		if err != nil {
			return nil, E.Errors(err, tunFile.Close(), destoryTun("tun"))
		}

		err = E.Errors(
			setIfHeadMode(tunFile), setIfMode(tunFile),
			setND6(assignedName), setPID(tunFile),
			setMTU(assignedName, int32(options.MTU)),
			setTunName(options.Name, assignedName),
		)
		if err != nil {
			return nil, E.Errors(err, tunFile.Close(), destoryTun(assignedName))
		}

		err = E.Errors(
			setGateway(tunFile, options),
			setTunAddress(options.Name, options),
		)
		if err != nil {
			return nil, E.Errors(err, tunFile.Close(), destoryTun(options.Name))
		}

		var resolvString string = ""
		if options.AutoRoute {
			resolvString, err = setDNSServers(options)
			if err != nil {
				return nil, E.Errors(err, tunFile.Close(), destoryTun(options.Name))
			}
		}

		nativeTun = &NativeTun{
			tunFile:   tunFile,
			options:   options,
			tunResolv: resolvString,
		}
	} else {
		tunFd = options.FileDescriptor
		nativeTun = &NativeTun{
			tunFile: os.NewFile(uintptr(tunFd), "utun"),
			options: options,
		}
	}

	if len(options.Inet4Address) > 0 {
		nativeTun.inet4Address = options.Inet4Address[0].Addr().As4()
	}
	if len(options.Inet6Address) > 0 {
		nativeTun.inet6Address = options.Inet6Address[0].Addr().As16()
	}
	var ok bool
	nativeTun.tunWriter, ok = bufio.CreateVectorisedWriter(nativeTun.tunFile)
	if !ok {
		panic("create vectorised writer")
	}
	return nativeTun, nil
}

func (t *NativeTun) Start() error {
	t.options.InterfaceMonitor.RegisterMyInterface(t.options.Name)
	return t.setRoutes()
}

func (t *NativeTun) Close() error {
	if t.options.AutoRoute {
		return E.Errors(
			restoreDNSServers(t.tunResolv), t.unsetRoutes(),
			t.tunFile.Close(), destoryTun(t.options.Name),
		)
	}
	return E.Errors(t.unsetRoutes(), t.tunFile.Close(), destoryTun(t.options.Name))
}

func (t *NativeTun) Read(p []byte) (n int, err error) {
	return t.tunFile.Read(p)
}

func (t *NativeTun) Write(p []byte) (n int, err error) {
	//To prevent "address family not supported by protocol family"
	switch uint(p[3]) {
	case unix.AF_INET:
		copy(p[:4], packetHeader4[:])
	case unix.AF_INET6:
		copy(p[:4], packetHeader6[:])
	}
	return t.tunFile.Write(p)
}

var (
	packetHeader4 = [4]byte{0x00, 0x00, 0x00, unix.AF_INET}
	packetHeader6 = [4]byte{0x00, 0x00, 0x00, unix.AF_INET6}
)

func (t *NativeTun) WriteVectorised(buffers []*buf.Buffer) error {
	var packetHeader []byte
	switch header.IPVersion(buffers[0].Bytes()) {
	case header.IPv4Version:
		packetHeader = packetHeader4[:]
	case header.IPv6Version:
		packetHeader = packetHeader6[:]
	}
	return t.tunWriter.WriteVectorised(append([]*buf.Buffer{buf.As(packetHeader)}, buffers...))
}

const (
	TUNSIFHEAD             = 0x80047460
	TUNSIFMODE             = 0x8004745e
	TUNGIFNAME             = 0x4020745d
	TUNSIFPID              = 0x2000745f
	SIOCGIFINFO_IN6        = 0xc048696c
	SIOCSIFINFO_IN6        = 0xc048696d
	ND6_IFF_AUTO_LINKLOCAL = 0x20
	ND6_IFF_NO_DAD         = 0x100
	SIOCAIFADDR_IN6        = 2166384923 //(0x80000000) | ((288 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 27
	IN6_IFF_NODAD          = 0x0020
	ND6_INFINITE_LIFETIME  = 0xFFFFFFFF
)

type Ifreq struct {
	Name [unix.IFNAMSIZ]byte
	Data uintptr
}

type IfreqMTU struct {
	Name [unix.IFNAMSIZ]byte
	MTU  int32
}

type ND6Req struct {
	Name          [unix.IFNAMSIZ]byte
	Linkmtu       uint32
	Maxmtu        uint32
	Basereachable uint32
	Reachable     uint32
	Retrans       uint32
	Flags         uint32
	Recalctm      int
	Chlim         uint8
	Initialized   uint8
	Randomseed0   [8]byte
	Randomseed1   [8]byte
	Randomid      [8]byte
}

type ifAliasReq struct {
	Name    [unix.IFNAMSIZ]byte
	Addr    unix.RawSockaddrInet4
	Dstaddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
	Vhid    uint32
}

type ifAliasReq6 struct {
	Name     [16]byte
	Addr     unix.RawSockaddrInet6
	Dstaddr  unix.RawSockaddrInet6
	Mask     unix.RawSockaddrInet6
	Flags    uint32
	Lifetime addrLifetime6
	Vhid     uint32
}

type addrLifetime6 struct {
	Expire    float64
	Preferred float64
	Vltime    uint32
	Pltime    uint32
}

func getTunName(tunFile *os.File) (string, error) {
	var errno syscall.Errno
	var ifr Ifreq
	err := useFd(tunFile, func(fd uintptr) {
		_, _, errno = unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(fd),
			uintptr(TUNGIFNAME),
			uintptr(unsafe.Pointer(&ifr)),
		)
	})
	if errno != 0 {
		return "", os.NewSyscallError("TUNGIFNAME", err)
	}
	if err != nil {
		return "", err
	}
	return unix.ByteSliceToString(ifr.Name[:]), nil
}

func destoryTun(name string) error {
	err := useSocket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0, func(socketFd int) error {
		var ifr Ifreq
		copy(ifr.Name[:], name)
		_, _, errno := unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(socketFd),
			uintptr(unix.SIOCIFDESTROY),
			uintptr(unsafe.Pointer(&ifr)),
		)
		if errno != 0 {
			return E.New(errno.Error())
		}
		return nil
	})
	if err != nil {
		return os.NewSyscallError("SIOCIFDESTROY", err)
	}
	return nil
}

func setFIB(tunFile *os.File, fib int) error {
	var errno syscall.Errno
	err := useFd(tunFile, func(fd uintptr) {
		_, _, errno = unix.Syscall(
			syscall.SYS_SETFIB,
			uintptr(fib),
			uintptr(0),
			uintptr(0),
		)
	})
	if errno != 0 {
		return os.NewSyscallError("SYS_SETFIB", errno)
	}
	return err
}

func setGateway(tunFile *os.File, options Options) error {
	if !options.AutoRoute {
		return nil
	}
	add_addr, err := unix.SysctlUint32("net.add_addr_allfibs")
	if err != nil {
		return err
	}
	if add_addr == 0 {
		output, err := exec.Command("sysctl", "net.add_addr_allfibs=1").CombinedOutput()
		if err != nil {
			return E.New("execute \"sysctl net.add_addr_allfibs=1\"\n", string(output))
		}
	}
	fibs, err := unix.SysctlUint32("net.fibs")
	if err != nil {
		return err
	}
	var fibSize int = options.FIBIndex + 1
	if fibs < uint32(fibSize) {
		output, err := exec.Command("sysctl", fmt.Sprintf("net.fibs=%d", fibSize)).CombinedOutput()
		if err != nil {
			return E.New(fmt.Sprintf("execute \"sysctl net.fibs=%d\"\n", fibSize), string(output))
		}
	}

	var defaultGateway4 string = ""
	var defaultGateway6 string = ""
	ribMessage, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return err
	}
	routeMessages, err := route.ParseRIB(route.RIBTypeRoute, ribMessage)
	if err != nil {
		return err
	}
	for _, rawRouteMessage := range routeMessages {
		routeMessage := rawRouteMessage.(*route.RouteMessage)
		if len(routeMessage.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		gateway4, isIPv4Gateway := routeMessage.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
		if !isIPv4Gateway {
			continue
		}
		netmask4, isIPv4Mask := routeMessage.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr)
		if !isIPv4Mask {
			continue
		}
		ones, _ := net.IPMask(netmask4.IP[:]).Size()
		if ones != 0 {
			continue
		}
		defaultGateway4 = netip.AddrFrom4(gateway4.IP).String()
	}
	for _, rawRouteMessage := range routeMessages {
		routeMessage := rawRouteMessage.(*route.RouteMessage)
		if len(routeMessage.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		gateway6, isIPv6Gateway := routeMessage.Addrs[unix.RTAX_GATEWAY].(*route.Inet6Addr)
		if !isIPv6Gateway {
			continue
		}
		netmask6, isIPv6Mask := routeMessage.Addrs[unix.RTAX_NETMASK].(*route.Inet6Addr)
		if !isIPv6Mask {
			continue
		}
		ones, _ := net.IPMask(netmask6.IP[:]).Size()
		if ones != 0 {
			continue
		}
		defaultGateway6 = netip.AddrFrom16(gateway6.IP).String()
	}

	err = setFIB(tunFile, fibSize-1)
	if err != nil {
		return err
	}
	exec.Command("setfib", strconv.Itoa(fibSize-1), "route", "delete", "default").CombinedOutput()
	exec.Command("setfib", strconv.Itoa(fibSize-1), "route", "delete", "-inet6", "default").CombinedOutput()
	ribMessage, err = route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return err
	}
	routeMessages, err = route.ParseRIB(route.RIBTypeRoute, ribMessage)
	if err != nil {
		return err
	}
	if len(routeMessages) == 0 {
		return E.New("empty fib, please change the `fib_index`")
	}
	if defaultGateway4 != "" {
		output, err := exec.Command(
			"setfib", strconv.Itoa(fibSize-1), "route", "add", "default", defaultGateway4,
		).CombinedOutput()
		if err != nil {
			return E.New("add ipv4 gateway\n", string(output))
		}
	}
	if defaultGateway6 != "" {
		interfaceName := options.InterfaceMonitor.DefaultInterface().Name
		output, err := exec.Command(
			"setfib", strconv.Itoa(fibSize-1), "route", "add", "-inet6", "default",
			fmt.Sprintf("%s%%%s", defaultGateway6, interfaceName),
		).CombinedOutput()
		if err != nil {
			return E.New("add ipv6 gateway\n", string(output))
		}
	}

	return nil
}

func setIfHeadMode(tunFile *os.File) error {
	var errno syscall.Errno
	ifheadmode := 1
	err := useFd(tunFile, func(fd uintptr) {
		_, _, errno = unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(fd),
			uintptr(TUNSIFHEAD),
			uintptr(unsafe.Pointer(&ifheadmode)),
		)
	})
	if errno != 0 {
		return os.NewSyscallError("TUNSIFHEAD", errno)
	}
	return err
}

func setIfMode(tunFile *os.File) error {
	var errno syscall.Errno
	ifflags := syscall.IFF_BROADCAST | syscall.IFF_MULTICAST
	err := useFd(tunFile, func(fd uintptr) {
		_, _, errno = unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(fd),
			uintptr(TUNSIFMODE),
			uintptr(unsafe.Pointer(&ifflags)),
		)
	})
	if errno != 0 {
		return os.NewSyscallError("TUNSIFMODE", errno)
	}
	return err
}

func setND6(name string) error {
	var nd6req ND6Req
	copy(nd6req.Name[:], name)
	err := useSocket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0, func(socketFd int) error {
		_, _, errno := unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(socketFd),
			uintptr(SIOCGIFINFO_IN6),
			uintptr(unsafe.Pointer(&nd6req)),
		)
		if errno != 0 {
			return E.New(errno.Error())
		}
		return nil
	})
	if err != nil {
		return os.NewSyscallError("SIOCGIFINFO_IN6", err)
	}
	nd6req.Flags = nd6req.Flags &^ ND6_IFF_AUTO_LINKLOCAL
	nd6req.Flags = nd6req.Flags | ND6_IFF_NO_DAD
	err = useSocket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0, func(socketFd int) error {
		_, _, errno := unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(socketFd),
			uintptr(SIOCSIFINFO_IN6),
			uintptr(unsafe.Pointer(&nd6req)),
		)
		if errno != 0 {
			return E.New(errno.Error())
		}
		return nil
	})
	if err != nil {
		return os.NewSyscallError("SIOCSIFINFO_IN6", err)
	}
	return nil
}

func setPID(tunFile *os.File) error {
	var errno syscall.Errno
	err := useFd(tunFile, func(fd uintptr) {
		_, _, errno = unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(fd),
			uintptr(TUNSIFPID),
			uintptr(0),
		)
	})
	if errno != 0 {
		return os.NewSyscallError("TUNSIFPID", err)
	}
	return err
}

func setMTU(name string, MTU int32) error {
	var ifrMTU IfreqMTU
	copy(ifrMTU.Name[:], []byte(name))
	ifrMTU.MTU = MTU
	err := useSocket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0, func(socketFd int) error {
		_, _, errno := unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(socketFd),
			uintptr(unix.SIOCSIFMTU),
			uintptr(unsafe.Pointer(&ifrMTU)),
		)
		if errno != 0 {
			return E.New(errno.Error())
		}
		return nil
	})
	if err != nil {
		return os.NewSyscallError("SIOCSIFMTU", err)
	}
	return nil
}

func setTunName(name string, assignedName string) error {
	err := useSocket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0, func(socketFd int) error {
		var newName [unix.IFNAMSIZ]byte
		copy(newName[:], name)
		var ifr Ifreq
		copy(ifr.Name[:], assignedName)
		ifr.Data = uintptr(unsafe.Pointer(&newName[0]))
		_, _, errno := unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(socketFd),
			uintptr(unix.SIOCSIFNAME),
			uintptr(unsafe.Pointer(&ifr)),
		)
		if errno != 0 {
			return E.New(errno.Error())
		}
		return nil
	})
	if err != nil {
		return os.NewSyscallError("SIOCSIFNAME", err)
	}
	return nil
}

func setTunAddress(name string, options Options) error {
	if len(options.Inet4Address) > 0 {
		output, err := exec.Command(
			"/sbin/ifconfig", name, "inet",
			options.Inet4Address[0].String(), "up",
		).CombinedOutput()
		if err != nil {
			return E.New("add ipv4 address\n", string(output))
		}
		time.Sleep(2)
	}
	if len(options.Inet6Address) > 0 {
		output, err := exec.Command(
			"/sbin/ifconfig", name, "inet6",
			options.Inet6Address[0].String(), "up",
		).CombinedOutput()
		if err != nil {
			return E.New("add ipv6 address\n", string(output))
		}
		time.Sleep(2)
	}
	return nil
}

const resolvPath = "/etc/resolv.conf"

func setDNSServers(options Options) (string, error) {
	resolvByte, err := os.ReadFile(resolvPath)
	if err != nil {
		return "", err
	}
	resolvString := unix.ByteSliceToString(resolvByte[:])
	var sb strings.Builder
	sb.WriteString("search localdomain\n")
	if len(options.Inet4Address) > 0 {
		sb.WriteString(fmt.Sprintf("nameserver %s\n", options.Inet4Address[0].Addr().Next().String()))
	}
	if len(options.Inet6Address) > 0 {
		sb.WriteString(fmt.Sprintf("nameserver %s\n", options.Inet6Address[0].Addr().Next().String()))
	}
	newResolvByte := []byte(sb.String())
	err = os.WriteFile(resolvPath, newResolvByte[:], 0644)
	if err != nil {
		return resolvString, err
	}
	return resolvString, nil
}

func restoreDNSServers(resolvString string) error {
	resolvByte := []byte(resolvString)
	err := os.WriteFile(resolvPath, resolvByte[:], 0644)
	if err != nil {
		return err
	}
	return nil
}

func (t *NativeTun) UpdateRouteOptions(tunOptions Options) error {
	err := t.unsetRoutes()
	if err != nil {
		return err
	}
	t.options = tunOptions
	return t.setRoutes()
}

func (t *NativeTun) setRoutes() error {
	if t.options.FileDescriptor == 0 {
		routeRanges, err := t.options.BuildAutoRouteRanges(false)
		if err != nil {
			return err
		}
		if len(routeRanges) > 0 {
			gateway4, gateway6 := t.options.Inet4GatewayAddr(), t.options.Inet6GatewayAddr()
			for _, destination := range routeRanges {
				var gateway netip.Addr
				if destination.Addr().Is4() {
					gateway = gateway4
				} else {
					gateway = gateway6
				}
				err = execRoute(unix.RTM_ADD, destination, gateway)
				if err != nil {
					if errors.Is(err, unix.EEXIST) {
						err = execRoute(unix.RTM_DELETE, destination, gateway)
						if err != nil {
							return E.Cause(err, "remove existing route: ", destination)
						}
						err = execRoute(unix.RTM_ADD, destination, gateway)
						if err != nil {
							return E.Cause(err, "re-add route: ", destination)
						}
					} else {
						return E.Cause(err, "add route: ", destination)
					}
				}
			}
			t.routeSet = true
		}
	}
	return nil
}

func (t *NativeTun) unsetRoutes() error {
	if !t.routeSet {
		return nil
	}
	routeRanges, err := t.options.BuildAutoRouteRanges(false)
	if err != nil {
		return err
	}
	gateway4, gateway6 := t.options.Inet4GatewayAddr(), t.options.Inet6GatewayAddr()
	for _, destination := range routeRanges {
		var gateway netip.Addr
		if destination.Addr().Is4() {
			gateway = gateway4
		} else {
			gateway = gateway6
		}
		err = execRoute(unix.RTM_DELETE, destination, gateway)
		if err != nil {
			err = E.Errors(err, E.Cause(err, "delete route: ", destination))
		}
	}
	return err
}

func useSocket(domain, typ, proto int, block func(socketFd int) error) error {
	socketFd, err := unix.Socket(domain, typ, proto)
	if err != nil {
		return err
	}
	defer unix.Close(socketFd)
	return block(socketFd)
}

func useFd(tunFile *os.File, block func(fd uintptr)) error {
	sysconn, err := tunFile.SyscallConn()
	if err != nil {
		return err
	}
	return sysconn.Control(block)
}

func execRoute(rtmType int, destination netip.Prefix, gateway netip.Addr) error {
	routeMessage := route.RouteMessage{
		Type:    rtmType,
		Version: unix.RTM_VERSION,
		Flags:   unix.RTF_STATIC | unix.RTF_GATEWAY,
		Seq:     1,
	}
	if rtmType == unix.RTM_ADD {
		routeMessage.Flags |= unix.RTF_UP
	}
	if gateway.Is4() {
		routeMessage.Addrs = []route.Addr{
			syscall.RTAX_DST:     &route.Inet4Addr{IP: destination.Addr().As4()},
			syscall.RTAX_NETMASK: &route.Inet4Addr{IP: netip.MustParseAddr(net.IP(net.CIDRMask(destination.Bits(), 32)).String()).As4()},
			syscall.RTAX_GATEWAY: &route.Inet4Addr{IP: gateway.As4()},
		}
	} else {
		routeMessage.Addrs = []route.Addr{
			syscall.RTAX_DST:     &route.Inet6Addr{IP: destination.Addr().As16()},
			syscall.RTAX_NETMASK: &route.Inet6Addr{IP: netip.MustParseAddr(net.IP(net.CIDRMask(destination.Bits(), 128)).String()).As16()},
			syscall.RTAX_GATEWAY: &route.Inet6Addr{IP: gateway.As16()},
		}
	}
	request, err := routeMessage.Marshal()
	if err != nil {
		return err
	}
	return useSocket(unix.AF_ROUTE, unix.SOCK_RAW, 0, func(socketFd int) error {
		err := unix.SetsockoptInt(socketFd, unix.SOL_SOCKET, unix.SO_SETFIB, syscall.RT_DEFAULT_FIB)
		if err != nil {
			return os.NewSyscallError("SO_SETFIB", err)
		}
		return common.Error(unix.Write(socketFd, request))
	})
}
