package tun

import (
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing-tun/internal/afd"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

const (
	goSocketFIONBIO       = 0x8004667e
	goSocketReceiveBuffer = 4 << 20
)

type goIOVector = windows.WSABuf

type goSocket struct {
	handle windows.Handle
	entry  *goAFDEntry
}

type goAFDEntry struct {
	ioStatusBlock windows.IO_STATUS_BLOCK
	pollInfo      afd.PollInfo
	baseHandle    windows.Handle
	token         uint32
	interest      uint8
	armed         bool
	cancelled     bool
	pinner        runtime.Pinner
}

func goSpliceSocket(conn syscall.Conn) (goSocket, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return goSocket{}, err
	}
	var handle windows.Handle
	err = rawConn.Control(func(fd uintptr) {
		handle = windows.Handle(fd)
	})
	if err != nil {
		return goSocket{}, err
	}
	var (
		mode          uint32 = 1
		bytesReturned uint32
	)
	err = windows.WSAIoctl(handle, goSocketFIONBIO, (*byte)(unsafe.Pointer(&mode)), uint32(unsafe.Sizeof(mode)), nil, 0, &bytesReturned, nil, 0)
	if err != nil {
		return goSocket{}, E.Cause(err, "set socket non-blocking")
	}
	// Without an explicit receive buffer the socket advertises 64 KiB, and readiness-driven reads
	// then cost a thread wake-up per window; the runtime poller hid this behind posted overlapped reads.
	err = windows.SetsockoptInt(handle, windows.SOL_SOCKET, windows.SO_RCVBUF, goSocketReceiveBuffer)
	if err != nil {
		return goSocket{}, E.Cause(err, "set socket receive buffer")
	}
	return goSocket{handle: handle}, nil
}

func (s *goSocket) shutdownWrite() {
	windows.Shutdown(s.handle, windows.SHUT_WR)
}

func (s *goSocket) family() (uint8, error) {
	name, err := windows.Getsockname(s.handle)
	if err != nil {
		return 0, err
	}
	switch name.(type) {
	case *windows.SockaddrInet4:
		return windows.AF_INET, nil
	case *windows.SockaddrInet6:
		return windows.AF_INET6, nil
	default:
		return 0, E.New("unsupported socket family")
	}
}

func (s *goSocket) peerAddress() (netip.AddrPort, bool) {
	name, err := windows.Getpeername(s.handle)
	if err != nil {
		return netip.AddrPort{}, false
	}
	switch address := name.(type) {
	case *windows.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(address.Addr), uint16(address.Port)), true
	case *windows.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(address.Addr).Unmap(), uint16(address.Port)), true
	default:
		return netip.AddrPort{}, false
	}
}

func goIovecsFromSegments(iovecs []goIOVector, segments [][]byte) []goIOVector {
	iovecs = iovecs[:0]
	for _, segment := range segments {
		if len(segment) == 0 {
			continue
		}
		iovecs = append(iovecs, windows.WSABuf{Len: uint32(len(segment)), Buf: &segment[0]})
	}
	return iovecs
}

func goSocketWouldBlock(errno syscall.Errno) bool {
	return errno == windows.WSAEWOULDBLOCK || errno == windows.WSAEINTR
}

func goSocketDropped(errno syscall.Errno) bool {
	return errno == windows.WSAEMSGSIZE || errno == windows.WSAEAFNOSUPPORT || errno == windows.WSAENOBUFS
}

func goErrno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	errno, isErrno := err.(syscall.Errno)
	if !isErrno {
		return windows.WSAEINVAL
	}
	return errno
}

func (s *goSocket) readVector(iovecs []goIOVector) (int, syscall.Errno) {
	var (
		received uint32
		flags    uint32
	)
	err := windows.WSARecv(s.handle, &iovecs[0], uint32(len(iovecs)), &received, &flags, nil, nil)
	if err != nil {
		return 0, goErrno(err)
	}
	return int(received), 0
}

func (s *goSocket) writeVector(iovecs []goIOVector) (int, syscall.Errno) {
	var sent uint32
	err := windows.WSASend(s.handle, &iovecs[0], uint32(len(iovecs)), &sent, 0, nil, nil)
	if err != nil {
		return 0, goErrno(err)
	}
	return int(sent), 0
}

func (s *goSocket) write(data []byte) (int, syscall.Errno) {
	vector := windows.WSABuf{Len: uint32(len(data))}
	if len(data) > 0 {
		vector.Buf = &data[0]
	}
	var sent uint32
	err := windows.WSASend(s.handle, &vector, 1, &sent, 0, nil, nil)
	if err != nil {
		return 0, goErrno(err)
	}
	return int(sent), 0
}

func (s *goSocket) sendTo(data []byte, destination netip.AddrPort, family uint8) syscall.Errno {
	var (
		storage windows.RawSockaddrAny
		length  int32
	)
	address := destination.Addr().Unmap()
	if family == windows.AF_INET {
		if !address.Is4() {
			return windows.WSAEAFNOSUPPORT
		}
		inet4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&storage))
		inet4.Family = windows.AF_INET
		inet4.Addr = address.As4()
		goEncodePort(&inet4.Port, destination.Port())
		length = int32(unsafe.Sizeof(*inet4))
	} else {
		inet6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&storage))
		inet6.Family = windows.AF_INET6
		inet6.Addr = address.As16()
		goEncodePort(&inet6.Port, destination.Port())
		length = int32(unsafe.Sizeof(*inet6))
	}
	vector := windows.WSABuf{Len: uint32(len(data))}
	if len(data) > 0 {
		vector.Buf = &data[0]
	}
	var sent uint32
	return goErrno(windows.WSASendTo(s.handle, &vector, 1, &sent, 0, &storage, length, nil, nil))
}

func (s *goSocket) receiveFrom(buffer []byte) (int, netip.AddrPort, syscall.Errno) {
	var (
		storage  windows.RawSockaddrAny
		length   = int32(unsafe.Sizeof(storage))
		received uint32
		flags    uint32
	)
	vector := windows.WSABuf{Len: uint32(len(buffer)), Buf: &buffer[0]}
	err := windows.WSARecvFrom(s.handle, &vector, 1, &received, &flags, &storage, &length, nil, nil)
	if err != nil {
		return 0, netip.AddrPort{}, goErrno(err)
	}
	return int(received), goDecodeSockaddr(&storage), 0
}

func goEncodePort(target *uint16, port uint16) {
	encoded := (*[2]byte)(unsafe.Pointer(target))
	encoded[0] = byte(port >> 8)
	encoded[1] = byte(port)
}

func goDecodeSockaddr(storage *windows.RawSockaddrAny) netip.AddrPort {
	switch storage.Addr.Family {
	case windows.AF_INET:
		inet4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(storage))
		encoded := (*[2]byte)(unsafe.Pointer(&inet4.Port))
		return netip.AddrPortFrom(netip.AddrFrom4(inet4.Addr), uint16(encoded[0])<<8|uint16(encoded[1]))
	case windows.AF_INET6:
		inet6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(storage))
		encoded := (*[2]byte)(unsafe.Pointer(&inet6.Port))
		return netip.AddrPortFrom(netip.AddrFrom16(inet6.Addr).Unmap(), uint16(encoded[0])<<8|uint16(encoded[1]))
	default:
		return netip.AddrPort{}
	}
}
