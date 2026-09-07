package tun

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"unsafe"

	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/sys/unix"
)

func (s *goSocket) writeVector(iovecs []unix.Iovec) (int, syscall.Errno) {
	var message unix.Msghdr
	message.Iov = &iovecs[0]
	message.SetIovlen(len(iovecs))
	return goSendmsg(s.fd, &message, goSocketSendFlags)
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
	return goSendmsg(s.fd, &message, goSocketSendFlags)
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
	err := unix.Sendto(s.fd, data, goSocketSendFlags, to)
	if err != nil {
		return err.(syscall.Errno)
	}
	return 0
}

func (s *goSocket) receiveFrom(buffer []byte) (int, netip.AddrPort, syscall.Errno) {
	n, from, err := unix.Recvfrom(s.fd, buffer, unix.MSG_DONTWAIT)
	if err != nil {
		return 0, netip.AddrPort{}, err.(syscall.Errno)
	}
	return n, M.SocksaddrFromNetIP(M.AddrPortFromSockaddr(from)).Unwrap().AddrPort(), 0
}

func goSendmsg(fd int, message *unix.Msghdr, flags int) (int, syscall.Errno) {
	n, _, errno := unix.Syscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(message)), uintptr(flags))
	if errno != 0 {
		return 0, errno
	}
	return int(n), 0
}

type goPacketMessageHeader struct {
	header unix.Msghdr
	length uint32
}

type goPacketBatchIO struct {
	headers  [goPacketBatchSize]goPacketMessageHeader
	vectors  [goPacketBatchSize]unix.Iovec
	names    [goPacketBatchSize]unix.RawSockaddrAny
	controls [goPacketBatchSize][64]byte
	counts   [goPacketBatchSize]int
}

func (b *goPacketBatchIO) reset() {
	clear(b.headers[:])
	clear(b.vectors[:])
}

func (s *goSocket) enablePacketOffload() {
	err := unix.SetsockoptInt(s.fd, unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	s.packetGRO = err == nil
}

func (b *goPacketBatchIO) receive(socket *goSocket, packets []goPacketMessage, connected bool) (int, syscall.Errno) {
	for index := range packets {
		vector := &b.vectors[index]
		*vector = unix.Iovec{Base: &packets[index].data[0]}
		vector.SetLen(len(packets[index].data))
		message := &b.headers[index]
		*message = goPacketMessageHeader{}
		message.header.Iov = vector
		message.header.SetIovlen(1)
		if !connected {
			b.names[index] = unix.RawSockaddrAny{}
			message.header.Name = (*byte)(unsafe.Pointer(&b.names[index]))
			message.header.Namelen = unix.SizeofSockaddrAny
		}
		if socket.packetGRO {
			message.header.Control = &b.controls[index][0]
			message.header.SetControllen(len(b.controls[index]))
		}
	}
	//nolint:staticcheck
	count, _, errno := unix.RawSyscall6(unix.SYS_RECVMMSG, uintptr(socket.fd), uintptr(unsafe.Pointer(&b.headers[0])), uintptr(len(packets)), unix.MSG_DONTWAIT, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	for index := range int(count) {
		message := &b.headers[index]
		packet := &packets[index]
		packet.truncated = message.header.Flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || int(message.length) > len(packet.data)
		packet.data = packet.data[:min(int(message.length), len(packet.data))]
		if !connected {
			packet.destination = M.SocksaddrFromRawSockaddrAny(&b.names[index]).AddrPort()
		}
		if socket.packetGRO {
			control := b.controls[index][:message.header.Controllen]
			for len(control) >= unix.CmsgLen(0) {
				controlHeader := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
				length := int(controlHeader.Len)
				if length < unix.CmsgLen(0) || length > len(control) {
					packet.truncated = true
					break
				}
				if controlHeader.Level == unix.IPPROTO_UDP && controlHeader.Type == unix.UDP_GRO {
					if length < unix.CmsgLen(4) {
						packet.truncated = true
					} else {
						packet.segmentSize = int(binary.NativeEndian.Uint32(control[unix.CmsgLen(0):]))
						packet.truncated = packet.truncated || packet.segmentSize <= 0 || packet.segmentSize > 65535
					}
				}
				control = control[min(unix.CmsgSpace(length-unix.CmsgLen(0)), len(control)):]
			}
		}
	}
	return int(count), 0
}

func (b *goPacketBatchIO) send(socket *goSocket, packets []goPacketMessage, connected bool, family uint8) (int, syscall.Errno) {
	coalesce := !socket.packetGSODisabled
	sent := 0
	for sent < len(packets) {
		messageCount := 0
		hasSegments := false
		for index := sent; index < len(packets); {
			packet := &packets[index]
			segmentSize := len(packet.data)
			end := index + 1
			length := segmentSize
			if coalesce && segmentSize > 0 {
				for end < len(packets) && end-index < 64 {
					next := &packets[end]
					if !connected && next.destination != packet.destination || len(next.data) == 0 || len(next.data) > segmentSize || length+len(next.data) > 65507 {
						break
					}
					length += len(next.data)
					end++
					if len(next.data) < segmentSize {
						break
					}
				}
			}
			message := &b.headers[messageCount]
			*message = goPacketMessageHeader{}
			for vectorIndex := index; vectorIndex < end; vectorIndex++ {
				data := packets[vectorIndex].data
				vector := &b.vectors[vectorIndex-sent]
				*vector = unix.Iovec{}
				if len(data) > 0 {
					vector.Base = &data[0]
				}
				vector.SetLen(len(data))
			}
			message.header.Iov = &b.vectors[index-sent]
			message.header.SetIovlen(end - index)
			if !connected {
				name := &b.names[messageCount]
				*name = unix.RawSockaddrAny{}
				address := packet.destination.Addr().Unmap()
				if family == unix.AF_INET {
					if !address.Is4() {
						return sent, unix.EAFNOSUPPORT
					}
					inet4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(name))
					inet4.Family = unix.AF_INET
					inet4.Addr = address.As4()
					binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&inet4.Port))[:], packet.destination.Port())
					message.header.Namelen = unix.SizeofSockaddrInet4
				} else {
					inet6 := (*unix.RawSockaddrInet6)(unsafe.Pointer(name))
					inet6.Family = unix.AF_INET6
					inet6.Addr = address.As16()
					binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&inet6.Port))[:], packet.destination.Port())
					message.header.Namelen = unix.SizeofSockaddrInet6
				}
				message.header.Name = (*byte)(unsafe.Pointer(name))
			}
			if end-index > 1 {
				hasSegments = true
				control := b.controls[messageCount][:unix.CmsgSpace(2)]
				clear(control)
				controlHeader := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
				controlHeader.Level = unix.IPPROTO_UDP
				controlHeader.Type = unix.UDP_SEGMENT
				controlHeader.SetLen(unix.CmsgLen(2))
				binary.NativeEndian.PutUint16(control[unix.CmsgLen(0):], uint16(segmentSize))
				message.header.Control = &control[0]
				message.header.SetControllen(len(control))
			}
			b.counts[messageCount] = end - index
			messageCount++
			index = end
		}
		//nolint:staticcheck
		count, _, errno := unix.RawSyscall6(unix.SYS_SENDMMSG, uintptr(socket.fd), uintptr(unsafe.Pointer(&b.headers[0])), uintptr(messageCount), goSocketSendFlags, 0, 0)
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			if hasSegments {
				switch errno {
				case unix.EINVAL, unix.EIO, unix.ENOPROTOOPT, unix.EOPNOTSUPP:
					socket.packetGSODisabled = true
					coalesce = false
					continue
				case unix.EMSGSIZE:
					coalesce = false
					continue
				}
			}
			return sent, errno
		}
		if count == 0 {
			return sent, unix.EIO
		}
		for index := range int(count) {
			sent += b.counts[index]
		}
	}
	return sent, 0
}
