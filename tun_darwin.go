package tun

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/shell"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

const PacketOffset = 4

type NativeTun struct {
	tunFile      *os.File
	tunWriter    N.VectorisedWriter
	options      Options
	inet4Address [4]byte
	inet6Address [16]byte
	routerSet    bool
}

func New(options Options) (Tun, error) {
	var tunFd int
	if options.FileDescriptor == 0 {
		ifIndex := -1
		_, err := fmt.Sscanf(options.Name, "utun%d", &ifIndex)
		if err != nil {
			return nil, E.New("bad tun name: ", options.Name)
		}

		tunFd, err = unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
		if err != nil {
			return nil, err
		}

		err = configure(tunFd, ifIndex, options.Name, options)
		if err != nil {
			unix.Close(tunFd)
			return nil, err
		}
	} else {
		tunFd = options.FileDescriptor
	}

	nativeTun := &NativeTun{
		tunFile: os.NewFile(uintptr(tunFd), "utun"),
		options: options,
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
	return t.setRoutes()
}

func (t *NativeTun) Close() error {
	defer flushDNSCache()
	return E.Errors(t.unsetRoutes(), t.tunFile.Close())
}

func (t *NativeTun) Read(p []byte) (n int, err error) {
	return t.tunFile.Read(p)
}

func (t *NativeTun) Write(p []byte) (n int, err error) {
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

const utunControlName = "com.apple.net.utun_control"

const (
	SIOCAIFADDR_IN6       = 2155899162 // netinet6/in6_var.h
	IN6_IFF_NODAD         = 0x0020     // netinet6/in6_var.h
	IN6_IFF_SECURED       = 0x0400     // netinet6/in6_var.h
	ND6_INFINITE_LIFETIME = 0xFFFFFFFF // netinet6/nd6.h
)

type ifAliasReq struct {
	Name    [unix.IFNAMSIZ]byte
	Addr    unix.RawSockaddrInet4
	Dstaddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
}

type ifAliasReq6 struct {
	Name     [16]byte
	Addr     unix.RawSockaddrInet6
	Dstaddr  unix.RawSockaddrInet6
	Mask     unix.RawSockaddrInet6
	Flags    uint32
	Lifetime addrLifetime6
}

type addrLifetime6 struct {
	Expire    float64
	Preferred float64
	Vltime    uint32
	Pltime    uint32
}

func configure(tunFd int, ifIndex int, name string, options Options) error {
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)
	err := unix.IoctlCtlInfo(tunFd, ctlInfo)
	if err != nil {
		return os.NewSyscallError("IoctlCtlInfo", err)
	}

	err = unix.Connect(tunFd, &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(ifIndex) + 1,
	})
	if err != nil {
		return os.NewSyscallError("Connect", err)
	}

	err = unix.SetNonblock(tunFd, true)
	if err != nil {
		return os.NewSyscallError("SetNonblock", err)
	}

	err = useSocket(unix.AF_INET, unix.SOCK_DGRAM, 0, func(socketFd int) error {
		var ifr unix.IfreqMTU
		copy(ifr.Name[:], name)
		ifr.MTU = int32(options.MTU)
		return unix.IoctlSetIfreqMTU(socketFd, &ifr)
	})
	if err != nil {
		return os.NewSyscallError("IoctlSetIfreqMTU", err)
	}
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
			err = useSocket(unix.AF_INET, unix.SOCK_DGRAM, 0, func(socketFd int) error {
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
				Flags: IN6_IFF_NODAD | IN6_IFF_SECURED,
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
			err = useSocket(unix.AF_INET6, unix.SOCK_DGRAM, 0, func(socketFd int) error {
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

func (t *NativeTun) setRoutes() error {
	if t.options.AutoRoute && t.options.FileDescriptor == 0 {

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
			var interfaceIndex int
			if t.options.InterfaceScope {
				iff, err := t.options.InterfaceFinder.ByName(t.options.Name)
				if err != nil {
					return err
				}
				interfaceIndex = iff.Index
			}
			err = execRoute(unix.RTM_ADD, t.options.InterfaceScope, interfaceIndex, destination, gateway)
			if err != nil {
				if errors.Is(err, unix.EEXIST) {
					err = execRoute(unix.RTM_DELETE, false, 0, destination, gateway)
					if err != nil {
						return E.Cause(err, "remove existing route: ", destination)
					}
					err = execRoute(unix.RTM_ADD, t.options.InterfaceScope, interfaceIndex, destination, gateway)
					if err != nil {
						return E.Cause(err, "re-add route: ", destination)
					}
				} else {
					return E.Cause(err, "add route: ", destination)
				}
			}
		}
		flushDNSCache()
		t.routerSet = true
	}
	return nil
}

func (t *NativeTun) unsetRoutes() error {
	if !t.routerSet {
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
		err = execRoute(unix.RTM_DELETE, false, 0, destination, gateway)
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

func execRoute(rtmType int, interfaceScope bool, interfaceIndex int, destination netip.Prefix, gateway netip.Addr) error {
	routeMessage := route.RouteMessage{
		Type:    rtmType,
		Version: unix.RTM_VERSION,
		Flags:   unix.RTF_STATIC | unix.RTF_GATEWAY,
		Seq:     1,
	}
	if rtmType == unix.RTM_ADD {
		routeMessage.Flags |= unix.RTF_UP
		if interfaceScope {
			routeMessage.Flags |= unix.RTF_IFSCOPE
			routeMessage.Index = interfaceIndex
		}
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
		return common.Error(unix.Write(socketFd, request))
	})
}

func flushDNSCache() {
	go shell.Exec("dscacheutil", "-flushcache").Run()
}
