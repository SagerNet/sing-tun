package tun

import (
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func (s *goSocket) readVector(iovecs []unix.Iovec) (int, syscall.Errno) {
	//nolint:staticcheck
	n, _, errno := unix.RawSyscall(unix.SYS_READV, uintptr(s.fd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
	return int(n), errno
}

func (s *goSocket) writeVector(iovecs []unix.Iovec) (int, syscall.Errno) {
	var message unix.Msghdr
	message.Iov = &iovecs[0]
	message.SetIovlen(len(iovecs))
	//nolint:staticcheck
	n, _, errno := unix.RawSyscall(unix.SYS_SENDMSG, uintptr(s.fd), uintptr(unsafe.Pointer(&message)), goSocketSendFlags)
	return int(n), errno
}

func (s *goSocket) write(data []byte) (int, syscall.Errno) {
	var base *byte
	if len(data) > 0 {
		base = &data[0]
	}
	//nolint:staticcheck
	n, _, errno := unix.RawSyscall6(unix.SYS_SENDTO, uintptr(s.fd), uintptr(unsafe.Pointer(base)), uintptr(len(data)), goSocketSendFlags, 0, 0)
	return int(n), errno
}

func (s *goSocket) sendTo(data []byte, destination netip.AddrPort, family uint8) syscall.Errno {
	var (
		sockaddr       unsafe.Pointer
		sockaddrLength uintptr
		inet4          unix.RawSockaddrInet4
		inet6          unix.RawSockaddrInet6
	)
	address := destination.Addr().Unmap()
	if family == unix.AF_INET {
		if !address.Is4() {
			return unix.EAFNOSUPPORT
		}
		inet4.Len = unix.SizeofSockaddrInet4
		inet4.Family = unix.AF_INET
		inet4.Addr = address.As4()
		goEncodePort(&inet4.Port, destination.Port())
		sockaddr = unsafe.Pointer(&inet4)
		sockaddrLength = unix.SizeofSockaddrInet4
	} else {
		inet6.Len = unix.SizeofSockaddrInet6
		inet6.Family = unix.AF_INET6
		inet6.Addr = address.As16()
		goEncodePort(&inet6.Port, destination.Port())
		sockaddr = unsafe.Pointer(&inet6)
		sockaddrLength = unix.SizeofSockaddrInet6
	}
	var base *byte
	if len(data) > 0 {
		base = &data[0]
	}
	//nolint:staticcheck
	_, _, errno := unix.RawSyscall6(unix.SYS_SENDTO, uintptr(s.fd), uintptr(unsafe.Pointer(base)), uintptr(len(data)), goSocketSendFlags, uintptr(sockaddr), sockaddrLength)
	return errno
}

func (s *goSocket) receiveFrom(buffer []byte) (int, netip.AddrPort, syscall.Errno) {
	var storage unix.RawSockaddrInet6
	length := uint32(unsafe.Sizeof(storage))
	//nolint:staticcheck
	n, _, errno := unix.RawSyscall6(unix.SYS_RECVFROM, uintptr(s.fd), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), unix.MSG_DONTWAIT, uintptr(unsafe.Pointer(&storage)), uintptr(unsafe.Pointer(&length)))
	if errno != 0 {
		return 0, netip.AddrPort{}, errno
	}
	return int(n), goDecodeSockaddr(&storage), 0
}

func goEncodePort(target *uint16, port uint16) {
	encoded := (*[2]byte)(unsafe.Pointer(target))
	encoded[0] = byte(port >> 8)
	encoded[1] = byte(port)
}

func goDecodeSockaddr(storage *unix.RawSockaddrInet6) netip.AddrPort {
	encoded := (*[2]byte)(unsafe.Pointer(&storage.Port))
	port := uint16(encoded[0])<<8 | uint16(encoded[1])
	switch storage.Family {
	case unix.AF_INET:
		inet4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(storage))
		return netip.AddrPortFrom(netip.AddrFrom4(inet4.Addr), port)
	case unix.AF_INET6:
		return netip.AddrPortFrom(netip.AddrFrom16(storage.Addr).Unmap(), port)
	default:
		return netip.AddrPort{}
	}
}
