//go:build darwin || linux

package tun

import (
	"net/netip"
	"os"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const goSocketSendFlags = unix.MSG_DONTWAIT | unix.MSG_NOSIGNAL

type goIOVector = unix.Iovec

type goSocket struct {
	fd    int
	token uint32
}

func goSpliceSocket(conn syscall.Conn) (goSocket, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return goSocket{}, err
	}
	var socket goSocket
	err = rawConn.Control(func(fd uintptr) {
		socket.fd = int(fd)
	})
	if err != nil {
		return goSocket{}, err
	}
	return socket, nil
}

func newUnpolledFile(fd int, name string) *os.File {
	unix.SetNonblock(fd, false)
	file := os.NewFile(uintptr(fd), name)
	unix.SetNonblock(fd, true)
	return file
}

func (s *goSocket) shutdownWrite() {
	unix.Shutdown(s.fd, unix.SHUT_WR)
}

func (s *goSocket) family() (uint8, error) {
	name, err := unix.Getsockname(s.fd)
	if err != nil {
		return 0, err
	}
	switch name.(type) {
	case *unix.SockaddrInet4:
		return unix.AF_INET, nil
	case *unix.SockaddrInet6:
		return unix.AF_INET6, nil
	default:
		return 0, E.New("unsupported socket family")
	}
}

func (s *goSocket) peerAddress() (netip.AddrPort, bool) {
	name, err := unix.Getpeername(s.fd)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return goAddrPortFromSockaddr(name), true
}

func goAddrPortFromSockaddr(name unix.Sockaddr) netip.AddrPort {
	switch address := name.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(address.Addr), uint16(address.Port))
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(address.Addr).Unmap(), uint16(address.Port))
	default:
		return netip.AddrPort{}
	}
}

func goIovecsFromSegments(iovecs []goIOVector, segments [][]byte) []goIOVector {
	iovecs = iovecs[:0]
	for _, segment := range segments {
		if len(segment) == 0 {
			continue
		}
		vector := unix.Iovec{Base: &segment[0]}
		vector.SetLen(len(segment))
		iovecs = append(iovecs, vector)
	}
	return iovecs
}

func goSocketWouldBlock(errno syscall.Errno) bool {
	return errno == unix.EAGAIN || errno == unix.EWOULDBLOCK || errno == unix.EINTR
}

func goSocketDropped(errno syscall.Errno) bool {
	return errno == unix.EMSGSIZE || errno == unix.EAFNOSUPPORT || errno == unix.ENOBUFS
}
