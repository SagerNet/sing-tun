package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type NativeTun struct {
	tunFd        uintptr
	tunFile      *os.File
	inet4Address tcpip.Address
	inet6Address tcpip.Address
	mtu          uint32
}

func Open(name string, inet4Address netip.Prefix, inet6Address netip.Prefix, mtu uint32, autoRoute bool) (Tun, error) {
	ifIndex := -1
	_, err := fmt.Sscanf(name, "utun%d", &ifIndex)
	if err != nil {
		return nil, E.New("bad tun name: ", name)
	}

	tunFd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return nil, err
	}

	err = configure(tunFd, ifIndex, name, inet4Address, inet6Address, mtu, autoRoute)
	if err != nil {
		unix.Close(tunFd)
		return nil, err
	}

	return &NativeTun{
		tunFd:        uintptr(tunFd),
		tunFile:      os.NewFile(uintptr(tunFd), "utun"),
		inet4Address: tcpip.Address(inet4Address.Addr().AsSlice()),
		inet6Address: tcpip.Address(inet6Address.Addr().AsSlice()),
		mtu:          mtu,
	}, nil
}

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, error) {
	return &DarwinEndpoint{tun: t}, nil
}

func (t *NativeTun) Close() error {
	return t.tunFile.Close()
}

var _ stack.LinkEndpoint = (*DarwinEndpoint)(nil)

type DarwinEndpoint struct {
	tun        *NativeTun
	dispatcher stack.NetworkDispatcher
}

func (e *DarwinEndpoint) MTU() uint32 {
	return e.tun.mtu
}

func (e *DarwinEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *DarwinEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *DarwinEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (e *DarwinEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil && e.dispatcher != nil {
		e.dispatcher = nil
		return
	}
	if dispatcher != nil && e.dispatcher == nil {
		e.dispatcher = dispatcher
		go e.dispatchLoop()
	}
}

func (e *DarwinEndpoint) dispatchLoop() {
	_buffer := buf.StackNewSize(int(e.tun.mtu) + 4)
	defer common.KeepAlive(_buffer)
	buffer := common.Dup(_buffer)
	defer buffer.Release()
	data := buffer.FreeBytes()
	for {
		n, err := e.tun.tunFile.Read(data)
		if err != nil {
			break
		}
		packet := data[4:n]
		var networkProtocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(packet) {
		case header.IPv4Version:
			networkProtocol = header.IPv4ProtocolNumber
			if header.IPv4(packet).DestinationAddress() == e.tun.inet4Address {
				e.tun.tunFile.Write(data[:n])
				continue
			}
		case header.IPv6Version:
			networkProtocol = header.IPv6ProtocolNumber
			if header.IPv6(packet).DestinationAddress() == e.tun.inet6Address {
				e.tun.tunFile.Write(data[:n])
				continue
			}
		default:
			e.tun.tunFile.Write(data[:n])
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           bufferv2.MakeWithData(data[4:n]),
			IsForwardedPacket: true,
		})
		pkt.NetworkProtocolNumber = networkProtocol
		dispatcher := e.dispatcher
		if dispatcher == nil {
			pkt.DecRef()
			return
		}
		dispatcher.DeliverNetworkPacket(networkProtocol, pkt)
		pkt.DecRef()
	}
}

func (e *DarwinEndpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *DarwinEndpoint) Wait() {
}

func (e *DarwinEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *DarwinEndpoint) AddHeader(buffer *stack.PacketBuffer) {
}

var (
	packetHeader4 = [4]byte{0x00, 0x00, 0x00, unix.AF_INET}
	packetHeader6 = [4]byte{0x00, 0x00, 0x00, unix.AF_INET6}
)

func (e *DarwinEndpoint) WritePackets(packetBufferList stack.PacketBufferList) (int, tcpip.Error) {
	var n int
	for _, packet := range packetBufferList.AsSlice() {
		var packetHeader []byte
		switch packet.NetworkProtocolNumber {
		case header.IPv4ProtocolNumber:
			packetHeader = packetHeader4[:]
		case header.IPv6ProtocolNumber:
			packetHeader = packetHeader6[:]
		}
		_, err := rw.WriteV(e.tun.tunFd, append([][]byte{packetHeader}, packet.AsSlices()...))
		if err != nil {
			return n, &tcpip.ErrAborted{}
		}
		n++
	}
	return n, nil
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

func configure(tunFd int, ifIndex int, name string, inet4Address netip.Prefix, inet6Address netip.Prefix, mtu uint32, autoRoute bool) error {
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)
	err := unix.IoctlCtlInfo(tunFd, ctlInfo)
	if err != nil {
		return err
	}

	err = unix.Connect(tunFd, &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(ifIndex) + 1,
	})
	if err != nil {
		return err
	}

	err = unix.SetNonblock(tunFd, true)
	if err != nil {
		return err
	}

	err = useSocket(unix.AF_INET, unix.SOCK_DGRAM, 0, func(socketFd int) error {
		var ifr unix.IfreqMTU
		copy(ifr.Name[:], name)
		ifr.MTU = int32(mtu)
		return unix.IoctlSetIfreqMTU(socketFd, &ifr)
	})
	if err != nil {
		return err
	}
	if inet4Address.IsValid() {
		ifReq := ifAliasReq{
			Addr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   inet4Address.Addr().As4(),
			},
			Dstaddr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   inet4Address.Addr().As4(),
			},
			Mask: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(inet4Address.Bits(), 32)).String()).As4(),
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
	if inet6Address.IsValid() {
		ifReq6 := ifAliasReq6{
			Addr: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   inet6Address.Addr().As16(),
			},
			Mask: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(inet6Address.Bits(), 128)).String()).As16(),
			},
			Flags: IN6_IFF_NODAD | IN6_IFF_SECURED,
			Lifetime: addrLifetime6{
				Vltime: ND6_INFINITE_LIFETIME,
				Pltime: ND6_INFINITE_LIFETIME,
			},
		}
		if inet6Address.Bits() == 128 {
			ifReq6.Dstaddr = unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   inet6Address.Addr().Next().As16(),
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
	if autoRoute {
		if inet4Address.IsValid() {
			for _, subnet := range []netip.Prefix{
				netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 0, 0, 0}), 8),
				netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 0, 0, 0}), 7),
				netip.PrefixFrom(netip.AddrFrom4([4]byte{4, 0, 0, 0}), 6),
				netip.PrefixFrom(netip.AddrFrom4([4]byte{8, 0, 0, 0}), 5),
				netip.PrefixFrom(netip.AddrFrom4([4]byte{16, 0, 0, 0}), 4),
				netip.PrefixFrom(netip.AddrFrom4([4]byte{32, 0, 0, 0}), 3),
				netip.PrefixFrom(netip.AddrFrom4([4]byte{64, 0, 0, 0}), 2),
				netip.PrefixFrom(netip.AddrFrom4([4]byte{128, 0, 0, 0}), 1),
			} {
				err = addRoute(subnet, inet4Address.Addr())
				if err != nil {
					return err
				}
			}
		}
		if inet6Address.IsValid() {
			subnet := netip.PrefixFrom(netip.AddrFrom16([16]byte{32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), 3)
			err = addRoute(subnet, inet6Address.Addr())
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func useSocket(domain, typ, proto int, block func(socketFd int) error) error {
	socketFd, err := unix.Socket(domain, typ, proto)
	if err != nil {
		return err
	}
	defer unix.Close(socketFd)
	return block(socketFd)
}

func addRoute(destination netip.Prefix, gateway netip.Addr) error {
	routeMessage := route.RouteMessage{
		Type:    unix.RTM_ADD,
		Flags:   unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY,
		Version: unix.RTM_VERSION,
		Seq:     1,
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
