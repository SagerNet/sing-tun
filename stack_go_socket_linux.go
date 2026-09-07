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
	n, err := goSendmsg(s.fd, &message, goSocketSendFlags)
	return n, goErrno(err)
}

func (s *goSocket) write(data []byte) (int, syscall.Errno) {
	var vector unix.Iovec
	if len(data) > 0 {
		vector.Base = &data[0]
	}
	vector.SetLen(len(data))
	var message unix.Msghdr
	message.Iov = &vector
	message.SetIovlen(1)
	n, err := goSendmsg(s.fd, &message, goSocketSendFlags)
	return n, goErrno(err)
}

func (s *goSocket) sendTo(data []byte, destination netip.AddrPort, family uint8) syscall.Errno {
	var (
		inet4 unix.SockaddrInet4
		inet6 unix.SockaddrInet6
		to    unix.Sockaddr
	)
	address := destination.Addr().Unmap()
	if family == unix.AF_INET {
		if !address.Is4() {
			return unix.EAFNOSUPPORT
		}
		inet4.Addr = address.As4()
		inet4.Port = int(destination.Port())
		to = &inet4
	} else {
		inet6.Addr = address.As16()
		inet6.Port = int(destination.Port())
		to = &inet6
	}
	return goErrno(unix.Sendto(s.fd, data, goSocketSendFlags, to))
}

func (s *goSocket) receiveFrom(buffer []byte) (int, netip.AddrPort, syscall.Errno) {
	n, from, err := unix.Recvfrom(s.fd, buffer, unix.MSG_DONTWAIT)
	if err != nil {
		return 0, netip.AddrPort{}, goErrno(err)
	}
	return n, goAddrPortFromSockaddr(from), 0
}

func goSendmsg(fd int, message *unix.Msghdr, flags int) (int, error) {
	n, _, errno := unix.Syscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(message)), uintptr(flags))
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

func goErrno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	errno, isErrno := err.(syscall.Errno)
	if !isErrno {
		return unix.EIO
	}
	return errno
}
