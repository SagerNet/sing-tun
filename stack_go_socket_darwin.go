package tun

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"unsafe"

	rawfile "github.com/sagernet/sing-tun/internal/rawfile_darwin"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/unix"
)

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
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&inet4.Port))[:], destination.Port())
		sockaddr = unsafe.Pointer(&inet4)
		sockaddrLength = unix.SizeofSockaddrInet4
	} else {
		inet6.Len = unix.SizeofSockaddrInet6
		inet6.Family = unix.AF_INET6
		inet6.Addr = address.As16()
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&inet6.Port))[:], destination.Port())
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
	return int(n), M.SocksaddrFromNetIP(M.AddrPortFromRawSockaddr((*unix.RawSockaddr)(unsafe.Pointer(&storage)))).Unwrap().AddrPort(), 0
}

type goPacketBatchIO struct {
	headers [goPacketBatchSize]rawfile.MsgHdrX
	vectors [goPacketBatchSize]unix.Iovec
	names   [goPacketBatchSize]unix.RawSockaddrAny
}

func (b *goPacketBatchIO) reset() {
	clear(b.headers[:])
	clear(b.vectors[:])
}

func (s *goSocket) enablePacketOffload() {}

func (b *goPacketBatchIO) receive(socket *goSocket, packets []goPacketMessage, connected bool) (int, syscall.Errno) {
	for index := range packets {
		b.vectors[index] = rawfile.IovecFromBytes(packets[index].data)
		message := &b.headers[index]
		*message = rawfile.MsgHdrX{}
		message.Msg.Iov = &b.vectors[index]
		message.Msg.Iovlen = 1
		if !connected {
			b.names[index] = unix.RawSockaddrAny{}
			message.Msg.Name = (*byte)(unsafe.Pointer(&b.names[index]))
			message.Msg.Namelen = unix.SizeofSockaddrAny
		}
	}
	count, errno := receiveMessageBatch(socket.fd, b.headers[:len(packets)])
	if errno != 0 {
		return 0, errno
	}
	for index := range count {
		message := &b.headers[index]
		packet := &packets[index]
		packet.truncated = message.Msg.Flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || int(message.DataLen) > len(packet.data)
		packet.data = packet.data[:min(int(message.DataLen), len(packet.data))]
		if !connected {
			packet.destination = M.SocksaddrFromRawSockaddrAny(&b.names[index]).AddrPort()
		}
	}
	return count, 0
}

func (b *goPacketBatchIO) send(socket *goSocket, packets []goPacketMessage, connected bool, family uint8) (int, syscall.Errno) {
	sent := 0
	limit := len(packets)
	for sent < len(packets) {
		if !connected || len(packets[sent].data) == 0 {
			var errno syscall.Errno
			if connected {
				_, errno = socket.write(packets[sent].data)
			} else {
				errno = socket.sendTo(packets[sent].data, packets[sent].destination, family)
			}
			if errno == unix.EINTR {
				continue
			}
			if errno != 0 {
				return sent, errno
			}
			sent++
			continue
		}
		count := 0
		for index := sent; index < len(packets) && count < limit; index++ {
			if len(packets[index].data) == 0 {
				break
			}
			b.vectors[count] = rawfile.IovecFromBytes(packets[index].data)
			b.headers[count] = rawfile.MsgHdrX{}
			b.headers[count].Msg.Iov = &b.vectors[count]
			b.headers[count].Msg.Iovlen = 1
			count++
		}
		written, errno := rawfile.NonBlockingSendMMsg(socket.fd, b.headers[:count])
		if errno == unix.EINTR {
			continue
		}
		if errno == unix.EMSGSIZE && count > 1 {
			limit = (count + 1) / 2
			continue
		}
		if errno != 0 {
			return sent, errno
		}
		if written == 0 {
			return sent, unix.EIO
		}
		sent += written
	}
	return sent, 0
}
