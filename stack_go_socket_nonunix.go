//go:build !linux && !darwin

package tun

import "syscall"

type goPacketBatchIO struct{}

func (b *goPacketBatchIO) reset() {}

func (s *goSocket) enablePacketOffload() {}

func (b *goPacketBatchIO) receive(socket *goSocket, packets []goPacketMessage, connected bool) (int, syscall.Errno) {
	for index := range packets {
		length, source, errno := socket.receiveFrom(packets[index].data)
		if errno != 0 {
			return index, errno
		}
		packets[index].data = packets[index].data[:length]
		packets[index].destination = source
	}
	return len(packets), 0
}

func (b *goPacketBatchIO) send(socket *goSocket, packets []goPacketMessage, connected bool, family uint8) (int, syscall.Errno) {
	for index, packet := range packets {
		var errno syscall.Errno
		if connected {
			_, errno = socket.write(packet.data)
		} else {
			errno = socket.sendTo(packet.data, packet.destination, family)
		}
		if errno != 0 {
			return index, errno
		}
	}
	return len(packets), 0
}
