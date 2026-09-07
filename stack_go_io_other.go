//go:build !(linux || windows || darwin)

package tun

import (
	"net/netip"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"
)

const goEngineInlineTransmit = false

func newGoPlatformQueues(stack *Go) ([]goPlatformIO, error) {
	return nil, E.New("go: unsupported platform")
}

func goFatalReadError(err error) bool {
	return true
}

const goSpliceDuplicatesSocket = false

type goIOVector struct{}

type goSocket struct{}

func goSpliceSocket(conn syscall.Conn) (goSocket, error) {
	return goSocket{}, E.New("go: splice not supported")
}

func (s *goSocket) close() {
}

func (s *goSocket) readVector(iovecs []goIOVector) (int, syscall.Errno) {
	return 0, syscall.ENOSYS
}

func (s *goSocket) writeVector(iovecs []goIOVector) (int, syscall.Errno) {
	return 0, syscall.ENOSYS
}

func (s *goSocket) write(data []byte) (int, syscall.Errno) {
	return 0, syscall.ENOSYS
}

func (s *goSocket) sendTo(data []byte, destination netip.AddrPort, family uint8) syscall.Errno {
	return syscall.ENOSYS
}

func (s *goSocket) receiveFrom(buffer []byte) (int, netip.AddrPort, syscall.Errno) {
	return 0, netip.AddrPort{}, syscall.ENOSYS
}

func (s *goSocket) shutdownWrite() {
}

func (s *goSocket) family() (uint8, error) {
	return 0, syscall.ENOSYS
}

func (s *goSocket) peerAddress() (netip.AddrPort, bool) {
	return netip.AddrPort{}, false
}

func goIovecsFromSegments(iovecs []goIOVector, segments [][]byte) []goIOVector {
	return iovecs[:0]
}

func goSocketWouldBlock(errno syscall.Errno) bool {
	return errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK || errno == syscall.EINTR
}

func goSocketDropped(errno syscall.Errno) bool {
	return errno == syscall.EMSGSIZE || errno == syscall.EAFNOSUPPORT || errno == syscall.ENOBUFS
}
