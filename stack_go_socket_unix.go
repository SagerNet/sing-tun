//go:build darwin || linux

package tun

import (
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/unix"
)

const (
	goSocketSendFlags        = unix.MSG_DONTWAIT | unix.MSG_NOSIGNAL
	goSpliceDuplicatesSocket = true
)

type goIOVector = unix.Iovec

type goSocket struct {
	fd                int
	token             uint32
	registered        bool
	packetGRO         bool
	packetGSODisabled bool
}

func goSpliceSocket(conn syscall.Conn) (goSocket, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return goSocket{}, err
	}
	socket := goSocket{fd: -1}
	var duplicateError error
	err = rawConn.Control(func(fd uintptr) {
		socket.fd, duplicateError = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
	})
	err = E.Errors(err, duplicateError)
	if err != nil {
		socket.close()
		return goSocket{}, err
	}
	return socket, nil
}

func (s *goSocket) close() {
	if s.fd < 0 {
		return
	}
	descriptor := s.fd
	s.fd = -1
	unix.Close(descriptor)
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
	return M.SocksaddrFromNetIP(M.AddrPortFromSockaddr(name)).Unwrap().AddrPort(), true
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

func goFatalReadError(err error) bool {
	return E.IsMulti(err, unix.EBADF, unix.ENODEV, unix.ENXIO)
}

func (s *goSocket) readVector(iovecs []unix.Iovec) (int, syscall.Errno) {
	//nolint:staticcheck
	n, _, errno := unix.RawSyscall(unix.SYS_READV, uintptr(s.fd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
	return int(n), errno
}
