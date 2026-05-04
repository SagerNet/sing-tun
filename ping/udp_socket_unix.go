//go:build unix

package ping

import (
	"net"
	"net/netip"
	"syscall"

	"os"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/unix"
)

func connectUDP(controlFunc control.Func, destination netip.Addr) (*net.UDPConn, error) {
	var (
		network string
		fd      int
		err     error
	)
	if destination.Is4() {
		network = "udp4"
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	} else {
		network = "udp6"
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	}
	if err != nil {
		return nil, E.Cause(err, "socket()")
	}

	file := os.NewFile(uintptr(fd), "udp-traceroute")
	defer file.Close()

	if controlFunc != nil {
		var syscallConn syscall.RawConn
		syscallConn, err = file.SyscallConn()
		if err != nil {
			return nil, err
		}
		err = controlFunc(network, destination.String(), syscallConn)
		if err != nil {
			return nil, err
		}
	}

	var bindAddress netip.Addr
	if !destination.Is6() {
		bindAddress = netip.AddrFrom4([4]byte{})
	} else {
		bindAddress = netip.AddrFrom16([16]byte{})
	}

	err = unix.Bind(fd, M.AddrPortToSockaddr(netip.AddrPortFrom(bindAddress, 0)))
	if err != nil {
		return nil, E.Cause(err, "bind()")
	}

	packetConn, err := net.FilePacketConn(file)
	if err != nil {
		return nil, err
	}
	return packetConn.(*net.UDPConn), nil
}

func setUDPTTL(conn *net.UDPConn, isIPv6 bool, ttl uint8) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	return setsockoptTTL(rawConn, isIPv6, ttl)
}
