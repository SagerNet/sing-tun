package tun

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing-tun/internal/afd"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/windows"
)

const (
	goSpliceDuplicatesSocket = false
	goSocketFIONBIO          = 0x8004667e
	goSocketReceiveBuffer    = 4 << 20
)

type goIOVector = windows.WSABuf

var (
	modws2_32       = windows.NewLazySystemDLL("ws2_32.dll")
	procWSARecv     = modws2_32.NewProc("WSARecv")
	procWSARecvFrom = modws2_32.NewProc("WSARecvFrom")
	procWSASend     = modws2_32.NewProc("WSASend")
	procWSASendTo   = modws2_32.NewProc("WSASendTo")
)

const goSocketError = uintptr(^uint32(0))

func goSocketErrno(r1 uintptr, errno syscall.Errno) syscall.Errno {
	if r1 != goSocketError {
		return 0
	}
	if errno == 0 {
		return syscall.EINVAL
	}
	return errno
}

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

func (s *goSocket) close() {
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
	address := M.SocksaddrFromNetIP(M.AddrPortFromSockaddr(name)).Unwrap()
	return address.AddrPort(), address.IsValid()
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

func (s *goSocket) readVector(iovecs []goIOVector) (int, syscall.Errno) {
	var (
		received uint32
		flags    uint32
	)
	r1, _, e1 := syscall.SyscallN(procWSARecv.Addr(), uintptr(s.handle), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)), uintptr(unsafe.Pointer(&received)), uintptr(unsafe.Pointer(&flags)), 0, 0)
	errno := goSocketErrno(r1, e1)
	if errno != 0 {
		return 0, errno
	}
	return int(received), 0
}

func (s *goSocket) writeVector(iovecs []goIOVector) (int, syscall.Errno) {
	var sent uint32
	r1, _, e1 := syscall.SyscallN(procWSASend.Addr(), uintptr(s.handle), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)), uintptr(unsafe.Pointer(&sent)), 0, 0, 0)
	errno := goSocketErrno(r1, e1)
	if errno != 0 {
		return 0, errno
	}
	return int(sent), 0
}

func (s *goSocket) write(data []byte) (int, syscall.Errno) {
	vector := windows.WSABuf{Len: uint32(len(data))}
	if len(data) > 0 {
		vector.Buf = &data[0]
	}
	var sent uint32
	r1, _, e1 := syscall.SyscallN(procWSASend.Addr(), uintptr(s.handle), uintptr(unsafe.Pointer(&vector)), 1, uintptr(unsafe.Pointer(&sent)), 0, 0, 0)
	errno := goSocketErrno(r1, e1)
	if errno != 0 {
		return 0, errno
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
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&inet4.Port))[:], destination.Port())
		length = int32(unsafe.Sizeof(*inet4))
	} else {
		inet6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&storage))
		inet6.Family = windows.AF_INET6
		inet6.Addr = address.As16()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&inet6.Port))[:], destination.Port())
		length = int32(unsafe.Sizeof(*inet6))
	}
	vector := windows.WSABuf{Len: uint32(len(data))}
	if len(data) > 0 {
		vector.Buf = &data[0]
	}
	var sent uint32
	r1, _, e1 := syscall.SyscallN(procWSASendTo.Addr(), uintptr(s.handle), uintptr(unsafe.Pointer(&vector)), 1, uintptr(unsafe.Pointer(&sent)), 0, uintptr(unsafe.Pointer(&storage)), uintptr(length), 0, 0)
	return goSocketErrno(r1, e1)
}

func (s *goSocket) receiveFrom(buffer []byte) (int, netip.AddrPort, syscall.Errno) {
	var (
		storage  windows.RawSockaddrAny
		length   = int32(unsafe.Sizeof(storage))
		received uint32
		flags    uint32
	)
	vector := windows.WSABuf{Len: uint32(len(buffer)), Buf: &buffer[0]}
	r1, _, e1 := syscall.SyscallN(procWSARecvFrom.Addr(), uintptr(s.handle), uintptr(unsafe.Pointer(&vector)), 1, uintptr(unsafe.Pointer(&received)), uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Pointer(&storage)), uintptr(unsafe.Pointer(&length)), 0, 0)
	errno := goSocketErrno(r1, e1)
	if errno != 0 {
		return 0, netip.AddrPort{}, errno
	}
	return int(received), M.SocksaddrFromNetIP(M.AddrPortFromRawSockaddr(&storage.Addr)).Unwrap().AddrPort(), 0
}
