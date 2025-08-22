package tun

import (
	"context"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing-tun/internal/gtcpip/checksum"
	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

type UnprivilegedICMPDestination struct {
	ctx          context.Context
	cancel       context.CancelCauseFunc
	logger       logger.Logger
	routeContext DirectRouteContext
	isIPv6       bool
	localAddr    atomic.TypedValue[netip.Addr]
	rawConn      net.Conn
	ipHdr        bool
}

func NewUnprivilegedICMPDestination(ctx context.Context, logger logger.Logger, dialer net.Dialer, network string, address netip.Addr, routeContext DirectRouteContext) (DirectRouteDestination, error) {
	var (
		isIPv6 bool
		fd     int
		ipHdr  bool
		err    error
	)
	var dialNetwork string
	switch network {
	case N.NetworkICMPv4:
		dialNetwork = "ip4:icmp"
	case N.NetworkICMPv6:
		dialNetwork = "ip6:icmp"
		isIPv6 = true
	default:
		return nil, E.New("unsupported network: ", network)
	}
	if !isIPv6 {
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	} else {
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
	}
	if err != nil {
		return nil, err
	}
	name, nameLen := bufio.ToSockaddr(M.SocksaddrFrom(address, 0).AddrPort())
	err = unixConnect(fd, name, nameLen)
	if err != nil {
		return nil, err
	}
	rawConn, err := net.FileConn(os.NewFile(uintptr(fd), "datagram-oriented icmp"))
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if dialer.Control != nil {
		var syscallConn syscall.RawConn
		syscallConn, err = rawConn.(syscall.Conn).SyscallConn()
		if err != nil {
			return nil, err
		}
		err = dialer.Control(dialNetwork, address.String(), syscallConn)
		if err != nil {
			return nil, err
		}
	}
	d := &UnprivilegedICMPDestination{
		ctx:          ctx,
		logger:       logger,
		routeContext: routeContext,
		isIPv6:       network == N.NetworkICMPv6,
		rawConn:      rawConn,
		ipHdr:        ipHdr,
	}
	go d.loopRead()
	return d, nil
}

//go:linkname unixConnect golang.org/x/sys/unix.connect
func unixConnect(fd int, addr unsafe.Pointer, addrlen uint32) error

func (d *UnprivilegedICMPDestination) loopRead() {
	for {
		buffer := buf.NewPacket()
		_, err := buffer.ReadOnceFrom(d.rawConn)
		if err != nil {
			return
		}
		if d.ipHdr {
			if !d.isIPv6 {
				ipHdr := header.IPv4(buffer.Bytes())
				ipHdr.SetDestinationAddr(d.localAddr.Load())
				ipHdr.SetChecksum(0)
				ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
				icmpHdr := header.ICMPv4(ipHdr.Payload())
				icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(icmpHdr.Payload(), 0)))
			} else {
				ipHdr := header.IPv6(buffer.Bytes())
				ipHdr.SetDestinationAddr(d.localAddr.Load())
				icmpHdr := header.ICMPv6(ipHdr.Payload())
				icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
					Header: icmpHdr,
					Src:    ipHdr.SourceAddress(),
					Dst:    ipHdr.DestinationAddress(),
				}))
			}
			err = d.routeContext.WritePacket(buffer.Bytes())
			if err != nil {
				d.logger.Error(err)
			}
		} else {
			panic("impl no hdr version for windows and linux")
		}
	}
}

func (d *UnprivilegedICMPDestination) WritePacket(packet *buf.Buffer) error {
	if !d.isIPv6 {
		ipHdr := header.IPv4(packet.Bytes())
		d.localAddr.Store(M.AddrFromIP(ipHdr.SourceAddressSlice()))
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		_, err := d.rawConn.Write(icmpHdr)
		if err != nil {
			return err
		}
	} else {
		ipHdr := header.IPv6(packet.Bytes())
		d.localAddr.Store(M.AddrFromIP(ipHdr.SourceAddressSlice()))
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		_, err := d.rawConn.Write(icmpHdr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *UnprivilegedICMPDestination) Close() error {
	d.cancel(os.ErrClosed)
	return d.rawConn.Close()
}
