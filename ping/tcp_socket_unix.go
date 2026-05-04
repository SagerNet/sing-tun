//go:build unix

package ping

import (
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// tcpRawConn wraps a raw socket for sending TCP SYN packets.
// IPv4: IPPROTO_RAW (IP_HDRINCL automatic, sends full IP+TCP packet).
// IPv6: IPPROTO_TCP raw socket (kernel adds IPv6 header, sends TCP segment only).
type tcpRawConn struct {
	fd     int
	file   *os.File
	conn   net.PacketConn
	isIPv6 bool
}

func connectTCPRaw(controlFunc control.Func, destination netip.Addr) (*tcpRawConn, error) {
	var (
		network string
		fd      int
		err     error
	)
	isIPv6 := destination.Is6()
	if !isIPv6 {
		network = "ip4"
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	} else {
		network = "ip6"
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP)
	}
	if err != nil {
		return nil, E.Cause(err, "socket()")
	}

	file := os.NewFile(uintptr(fd), "tcp-raw")

	if controlFunc != nil {
		var syscallConn syscall.RawConn
		syscallConn, err = file.SyscallConn()
		if err != nil {
			file.Close()
			return nil, err
		}
		err = controlFunc(network, destination.String(), syscallConn)
		if err != nil {
			file.Close()
			return nil, err
		}
	}

	packetConn, err := net.FilePacketConn(file)
	if err != nil {
		file.Close()
		return nil, err
	}

	return &tcpRawConn{
		fd:     fd,
		file:   file,
		conn:   packetConn,
		isIPv6: isIPv6,
	}, nil
}

func (c *tcpRawConn) SetHopLimit(hopLimit uint8) error {
	rawConn, err := c.conn.(*net.IPConn).SyscallConn()
	if err != nil {
		return err
	}
	return setsockoptTTL(rawConn, c.isIPv6, hopLimit)
}

func (c *tcpRawConn) Close() error {
	c.file.Close()
	return c.conn.Close()
}
