//go:build freebsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2025 Vincent-Loeng.
 */
// Parts of the tun device configuration were obtained from wireguard-go and
// the bsd-box project (https://github.com/Vincent-Loeng/bsd-box).

package tun

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const PacketOffset = 4

// Tun device ioctls from sys/net/if_tun.h, sys/netinet6/in6_var.h and
// sys/netinet6/nd6.h. Raw values are used since they are not exported by
// golang.org/x/sys/unix for FreeBSD.
const (
	TUNSIFHEAD             = 0x80047460 // sys/net/if_tun.h
	TUNSIFMODE             = 0x8004745E // sys/net/if_tun.h
	TUNGIFNAME             = 0x4020745D // sys/net/if_tun.h
	TUNSIFPID              = 0x2000745F // sys/net/if_tun.h
	TUNSTRANSIENT          = 0x80627404 // sys/net/if_tun.h, _IOW('t', 98, int), FreeBSD 15+
	SIOCGIFINFO_IN6        = 0xC048696C // sys/netinet6/in6_var.h
	SIOCSIFINFO_IN6        = 0xC048696D // sys/netinet6/in6_var.h
	SIOCAIFADDR_IN6        = 0x8088691B // sys/netinet6/in6_var.h
	IN6_IFF_NODAD          = 0x0020     // sys/netinet6/in6_var.h
	ND6_IFF_AUTO_LINKLOCAL = 0x20       // sys/netinet6/nd6.h
	ND6_IFF_NO_DAD         = 0x100      // sys/netinet6/nd6.h
	ND6_INFINITE_LIFETIME  = 0xFFFFFFFF // sys/netinet6/nd6.h
)

type NativeTun struct {
	tunFile      *os.File
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
		// A weird error occurs when pf is enabled.
		if options.Name == "tun" {
			return nil, E.New("bad tun name: ", options.Name)
		}

		tunFile, err := os.OpenFile("/dev/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		assignedName, err := getTunName(tunFile)
		if err != nil {
			return nil, E.Errors(err, tunFile.Close(), destroyTun("tun"))
		}
		// FreeBSD 15+: destroy the device automatically when the last
		// descriptor is closed, so it cannot outlive a killed process.
		// Unavailable on older versions, ignore the error there.
		_ = setTransient(tunFile)

		err = E.Errors(
			setIfHeadMode(tunFile),
			setIfMode(tunFile),
			setND6(assignedName),
			setPID(tunFile),
			setMTU(assignedName, int32(options.MTU)),
			setTunName(options.Name, assignedName),
		)
		if err != nil {
			return nil, E.Errors(err, tunFile.Close(), destroyTun(assignedName))
		}

		err = setTunAddress(options.Name, options)
		if err != nil {
			return nil, E.Errors(err, tunFile.Close(), destroyTun(options.Name))
		}

		if options.AutoRoute {
			err = prepareFIB(options)
			if err != nil {
				return nil, E.Errors(err, tunFile.Close(), destroyTun(options.Name))
			}
		}

		nativeTun = &NativeTun{
			tunFile: tunFile,
			options: options,
		}
	} else {
		tunFd = options.FileDescriptor
		nativeTun = &NativeTun{
			tunFile: os.NewFile(uintptr(tunFd), "tun"),
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
	err := t.unsetRoutes()
	closeErr := t.tunFile.Close()
	// On FreeBSD 15+ with TUNSTRANSIENT the device is already destroyed by
	// the close; on older versions the explicit destroy is what removes it.
	// Errors are ignored since the device may already be gone.
	_ = destroyTun(t.options.Name)
	return E.Errors(err, closeErr)
}

func (t *NativeTun) Read(p []byte) (n int, err error) {
	return t.tunFile.Read(p)
}

func (t *NativeTun) Write(p []byte) (n int, err error) {
	// Normalize the packet information header to prevent
	// "address family not supported by protocol family".
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

type ifreq struct {
	Name [unix.IFNAMSIZ]byte
	Data uintptr
}

type ifreqMTU struct {
	Name [unix.IFNAMSIZ]byte
	MTU  int32
}

type nd6Req struct {
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
	var ifr ifreq
	err := useFd(tunFile, func(fd uintptr) {
		_, _, errno = unix.Syscall(
			syscall.SYS_IOCTL,
			fd,
			uintptr(TUNGIFNAME),
			uintptr(unsafe.Pointer(&ifr)),
		)
	})
	if errno != 0 {
		return "", os.NewSyscallError("TUNGIFNAME", errno)
	}
	if err != nil {
		return "", err
	}
	return unix.ByteSliceToString(ifr.Name[:]), nil
}

func destroyTun(name string) error {
	if name == "" {
		return nil
	}
	return useSocket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0, func(socketFd int) error {
		var ifr ifreq
		copy(ifr.Name[:], name)
		_, _, errno := unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(socketFd),
			uintptr(unix.SIOCIFDESTROY),
			uintptr(unsafe.Pointer(&ifr)),
		)
		if errno != 0 {
			return os.NewSyscallError("SIOCIFDESTROY", errno)
		}
		return nil
	})
}

func setIfHeadMode(tunFile *os.File) error {
	var errno syscall.Errno
	ifheadmode := 1
	err := useFd(tunFile, func(fd uintptr) {
		_, _, errno = unix.Syscall(
			syscall.SYS_IOCTL,
			fd,
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
			fd,
			uintptr(TUNSIFMODE),
			uintptr(unsafe.Pointer(&ifflags)),
		)
	})
	if errno != 0 {
		return os.NewSyscallError("TUNSIFMODE", errno)
	}
	return err
}

// setPID makes the tun device survive the close of its file descriptors
// until the controlling process exits. The kernel ignores the ioctl data
// and always records the current process (sys/net/if_tuntap.c).
func setPID(tunFile *os.File) error {
	var errno syscall.Errno
	pid := os.Getpid()
	err := useFd(tunFile, func(fd uintptr) {
		_, _, errno = unix.Syscall(
			syscall.SYS_IOCTL,
			fd,
			uintptr(TUNSIFPID),
			uintptr(unsafe.Pointer(&pid)),
		)
	})
	if errno != 0 {
		return os.NewSyscallError("TUNSIFPID", errno)
	}
	return err
}

// setND6 disables IPv6 duplicate address detection and the automatic
// link-local address on the tun device.
func setND6(name string) error {
	var nd6req nd6Req
	copy(nd6req.Name[:], name)
	err := useSocket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0, func(socketFd int) error {
		_, _, errno := unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(socketFd),
			uintptr(SIOCGIFINFO_IN6),
			uintptr(unsafe.Pointer(&nd6req)),
		)
		if errno != 0 {
			return os.NewSyscallError("SIOCGIFINFO_IN6", errno)
		}
		return nil
	})
	if err != nil {
		return err
	}
	nd6req.Flags = nd6req.Flags &^ ND6_IFF_AUTO_LINKLOCAL
	nd6req.Flags = nd6req.Flags | ND6_IFF_NO_DAD
	return useSocket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0, func(socketFd int) error {
		_, _, errno := unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(socketFd),
			uintptr(SIOCSIFINFO_IN6),
			uintptr(unsafe.Pointer(&nd6req)),
		)
		if errno != 0 {
			return os.NewSyscallError("SIOCSIFINFO_IN6", errno)
		}
		return nil
	})
}

func setMTU(name string, mtu int32) error {
	var ifrMTU ifreqMTU
	copy(ifrMTU.Name[:], []byte(name))
	ifrMTU.MTU = mtu
	err := useSocket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0, func(socketFd int) error {
		_, _, errno := unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(socketFd),
			uintptr(unix.SIOCSIFMTU),
			uintptr(unsafe.Pointer(&ifrMTU)),
		)
		if errno != 0 {
			return os.NewSyscallError("SIOCSIFMTU", errno)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// setTransient marks the device to be destroyed automatically when the
// last descriptor is closed (FreeBSD 15+). Without it, a killed process
// leaves the device behind.
func setTransient(tunFile *os.File) error {
	var errno syscall.Errno
	transient := 1
	err := useFd(tunFile, func(fd uintptr) {
		_, _, errno = unix.Syscall(
			syscall.SYS_IOCTL,
			fd,
			uintptr(TUNSTRANSIENT),
			uintptr(unsafe.Pointer(&transient)),
		)
	})
	if errno != 0 {
		return os.NewSyscallError("TUNSTRANSIENT", errno)
	}
	return err
}

func setTunName(name string, assignedName string) error {
	if assignedName == name {
		// The clone device was assigned the requested name already.
		return nil
	}
	return useSocket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0, func(socketFd int) error {
		var newName [unix.IFNAMSIZ]byte
		copy(newName[:], name)
		var ifr ifreq
		copy(ifr.Name[:], assignedName)
		ifr.Data = uintptr(unsafe.Pointer(&newName[0]))
		_, _, errno := unix.Syscall(
			syscall.SYS_IOCTL,
			uintptr(socketFd),
			uintptr(unix.SIOCSIFNAME),
			uintptr(unsafe.Pointer(&ifr)),
		)
		if errno != 0 {
			return os.NewSyscallError("SIOCSIFNAME", errno)
		}
		return nil
	})
}

func setTunAddress(name string, options Options) error {
	if len(options.Inet4Address) > 0 {
		for _, address := range options.Inet4Address {
			ifReq := ifAliasReq{
				Addr: unix.RawSockaddrInet4{
					Len:    unix.SizeofSockaddrInet4,
					Family: unix.AF_INET,
					Addr:   address.Addr().As4(),
				},
				Dstaddr: unix.RawSockaddrInet4{
					Len:    unix.SizeofSockaddrInet4,
					Family: unix.AF_INET,
					Addr:   address.Addr().As4(),
				},
				Mask: unix.RawSockaddrInet4{
					Len:    unix.SizeofSockaddrInet4,
					Family: unix.AF_INET,
					Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(address.Bits(), 32)).String()).As4(),
				},
			}
			copy(ifReq.Name[:], name)
			err := useSocket(unix.AF_INET, unix.SOCK_DGRAM, 0, func(socketFd int) error {
				if _, _, errno := unix.Syscall(
					syscall.SYS_IOCTL,
					uintptr(socketFd),
					uintptr(unix.SIOCAIFADDR),
					uintptr(unsafe.Pointer(&ifReq)),
				); errno != 0 {
					return os.NewSyscallError("SIOCAIFADDR", errno)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	if len(options.Inet6Address) > 0 {
		for _, address := range options.Inet6Address {
			ifReq6 := ifAliasReq6{
				Addr: unix.RawSockaddrInet6{
					Len:    unix.SizeofSockaddrInet6,
					Family: unix.AF_INET6,
					Addr:   address.Addr().As16(),
				},
				Mask: unix.RawSockaddrInet6{
					Len:    unix.SizeofSockaddrInet6,
					Family: unix.AF_INET6,
					Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(address.Bits(), 128)).String()).As16(),
				},
				Flags: IN6_IFF_NODAD,
				Lifetime: addrLifetime6{
					Vltime: ND6_INFINITE_LIFETIME,
					Pltime: ND6_INFINITE_LIFETIME,
				},
			}
			if address.Bits() == 128 {
				ifReq6.Dstaddr = unix.RawSockaddrInet6{
					Len:    unix.SizeofSockaddrInet6,
					Family: unix.AF_INET6,
					Addr:   address.Addr().Next().As16(),
				}
			}
			copy(ifReq6.Name[:], name)
			err := useSocket(unix.AF_INET6, unix.SOCK_DGRAM, 0, func(socketFd int) error {
				if _, _, errno := unix.Syscall(
					syscall.SYS_IOCTL,
					uintptr(socketFd),
					uintptr(SIOCAIFADDR_IN6),
					uintptr(unsafe.Pointer(&ifReq6)),
				); errno != 0 {
					return os.NewSyscallError("SIOCAIFADDR_IN6", errno)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func sysctlReadUint32(name string) (uint32, error) {
	return unix.SysctlUint32(name)
}

func sysctlWriteUint32(name string, value uint32) error {
	_, _, errno := unix.Syscall6(
		unix.SYS___SYSCTLBYNAME,
		uintptr(unsafe.Pointer(unsafe.StringData(name))),
		uintptr(len(name)),
		0,
		0,
		uintptr(unsafe.Pointer(&value)),
		uintptr(unsafe.Sizeof(value)),
	)
	if errno != 0 {
		return os.NewSyscallError("sysctlbyname "+name, errno)
	}
	return nil
}

func fibIndex(options Options) int {
	if options.IPRoute2TableIndex > 0 {
		return options.IPRoute2TableIndex
	}
	return DefaultIPRoute2TableIndex
}

// prepareFIB sets up an isolated routing table (FIB) for loop prevention:
// the capture routes live in the default FIB while the real default
// gateway is copied into the dedicated FIB, so traffic of the proxy
// itself never matches the capture routes.
func prepareFIB(options Options) error {
	fib := fibIndex(options)

	addAddrAllFibs, err := sysctlReadUint32("net.add_addr_allfibs")
	if err != nil {
		return err
	}
	if addAddrAllFibs == 0 {
		err = sysctlWriteUint32("net.add_addr_allfibs", 1)
		if err != nil {
			return err
		}
	}

	fibs, err := sysctlReadUint32("net.fibs")
	if err != nil {
		return err
	}
	if fibs < uint32(fib+1) {
		err = sysctlWriteUint32("net.fibs", uint32(fib+1))
		if err != nil {
			return E.New(
				"failed to set net.fibs=", fib+1, ": ", err,
				". Please add `net.fibs=", fib+1,
				"` and `net.add_addr_allfibs=1` to /boot/loader.conf and reboot",
			)
		}
	}

	gateway4, gateway6, gateway6Index, err := findDefaultGateways()
	if err != nil {
		return err
	}
	if gateway4.IsValid() {
		// Remove a stale default route left by a previous run.
		_ = execRoute(fib, unix.RTM_DELETE, netip.PrefixFrom(netip.IPv4Unspecified(), 0), gateway4, 0)
		err = execRoute(fib, unix.RTM_ADD, netip.PrefixFrom(netip.IPv4Unspecified(), 0), gateway4, 0)
		if err != nil {
			return E.Cause(err, "copy IPv4 default route to FIB ", fib)
		}
	}
	if gateway6.IsValid() {
		_ = execRoute(fib, unix.RTM_DELETE, netip.PrefixFrom(netip.IPv6Unspecified(), 0), gateway6, gateway6Index)
		err = execRoute(fib, unix.RTM_ADD, netip.PrefixFrom(netip.IPv6Unspecified(), 0), gateway6, gateway6Index)
		if err != nil {
			return E.Cause(err, "copy IPv6 default route to FIB ", fib)
		}
	}
	return nil
}

func findDefaultGateways() (gateway4 netip.Addr, gateway6 netip.Addr, gateway6Index int, err error) {
	ribMessage, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return
	}
	routeMessages, err := route.ParseRIB(route.RIBTypeRoute, ribMessage)
	if err != nil {
		return
	}
	for _, rawRouteMessage := range routeMessages {
		routeMessage, isRouteMessage := rawRouteMessage.(*route.RouteMessage)
		if !isRouteMessage {
			continue
		}
		if routeMessage.Flags&unix.RTF_UP == 0 || routeMessage.Flags&unix.RTF_GATEWAY == 0 {
			continue
		}
		if len(routeMessage.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		if netmask, isIPv4Mask := routeMessage.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr); isIPv4Mask {
			if ones, _ := net.IPMask(netmask.IP[:]).Size(); ones != 0 {
				continue
			}
			gateway, isIPv4Gateway := routeMessage.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
			if isIPv4Gateway {
				gateway4 = netip.AddrFrom4(gateway.IP)
			}
			continue
		}
		if netmask, isIPv6Mask := routeMessage.Addrs[unix.RTAX_NETMASK].(*route.Inet6Addr); isIPv6Mask {
			if ones, _ := net.IPMask(netmask.IP[:]).Size(); ones != 0 {
				continue
			}
			gateway, isIPv6Gateway := routeMessage.Addrs[unix.RTAX_GATEWAY].(*route.Inet6Addr)
			if isIPv6Gateway {
				gateway6 = netip.AddrFrom16(gateway.IP)
				gateway6Index = routeMessage.Index
				if gateway6Index == 0 && len(routeMessage.Addrs) > unix.RTAX_IFP {
					if linkAddr, ok := routeMessage.Addrs[unix.RTAX_IFP].(*route.LinkAddr); ok {
						gateway6Index = linkAddr.Index
					}
				}
			}
		}
	}
	return
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
				err = execRoute(unix.RT_DEFAULT_FIB, unix.RTM_ADD, destination, gateway, 0)
				if err != nil {
					if errors.Is(err, unix.EEXIST) {
						err = execRoute(unix.RT_DEFAULT_FIB, unix.RTM_DELETE, destination, gateway, 0)
						if err != nil {
							return E.Cause(err, "remove existing route: ", destination)
						}
						err = execRoute(unix.RT_DEFAULT_FIB, unix.RTM_ADD, destination, gateway, 0)
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
		err = execRoute(unix.RT_DEFAULT_FIB, unix.RTM_DELETE, destination, gateway, 0)
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

// execRoute writes a route message into the routing socket.
// fib selects the target routing table (SO_SETFIB).
func execRoute(fib int, rtmType int, destination netip.Prefix, gateway netip.Addr, gatewayIndex int) error {
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
		// Sized to RTAX_MAX like x/net/route itself: RTAX_IFP (4) is
		// beyond a compact literal; nil slots are skipped by Marshal.
		routeMessage.Addrs = make([]route.Addr, syscall.RTAX_MAX)
		routeMessage.Addrs[syscall.RTAX_DST] = &route.Inet6Addr{IP: destination.Addr().As16()}
		routeMessage.Addrs[syscall.RTAX_NETMASK] = &route.Inet6Addr{IP: netip.MustParseAddr(net.IP(net.CIDRMask(destination.Bits(), 128)).String()).As16()}
		gatewayIP := gateway.As16()
		if gateway.IsLinkLocalUnicast() && gatewayIndex != 0 {
			// FreeBSD KAME kernel requires the interface index embedded in
			// bytes 2-3 (s6_addr16[1]) of link-local addresses for neighbor
			// discovery / L2 resolution to match the interface zone.
			gatewayIP[2] = byte(gatewayIndex >> 8)
			gatewayIP[3] = byte(gatewayIndex)
		}
		routeMessage.Addrs[syscall.RTAX_GATEWAY] = &route.Inet6Addr{IP: gatewayIP}
		if gatewayIndex != 0 {
			// Scope the gateway to its interface, which is required for
			// link-local IPv6 gateways.
			routeMessage.Addrs[syscall.RTAX_IFP] = &route.LinkAddr{Index: gatewayIndex}
		}
	}
	request, err := routeMessage.Marshal()
	if err != nil {
		return err
	}
	return useSocket(unix.AF_ROUTE, unix.SOCK_RAW, 0, func(socketFd int) error {
		err := unix.SetsockoptInt(socketFd, unix.SOL_SOCKET, unix.SO_SETFIB, fib)
		if err != nil {
			return os.NewSyscallError("SO_SETFIB", err)
		}
		return common.Error(unix.Write(socketFd, request))
	})
}
