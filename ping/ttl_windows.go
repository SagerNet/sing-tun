package ping

import (
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// setsockoptTTL sets IP_TTL or IPV6_UNICAST_HOPS on a raw connection.
func setsockoptTTL(rawConn syscall.RawConn, isIPv6 bool, ttl uint8) error {
	var sockErr error
	var err error
	if !isIPv6 {
		err = rawConn.Control(func(fd uintptr) {
			sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL, int(ttl))
		})
	} else {
		err = rawConn.Control(func(fd uintptr) {
			sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_UNICAST_HOPS, int(ttl))
		})
	}
	if err != nil {
		return err
	}
	return sockErr
}

func (c *Conn) SetTTL(ttl uint8) error {
	if setter, ok := c.conn.(ttlSetter); ok {
		setter.SetTTL(ttl)
		return nil
	}
	syscallConn, ok := c.conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return nil
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return err
	}
	return setsockoptTTL(rawConn, c.destination.Is6(), ttl)
}

func (c *UnprivilegedConn) setTTL(conn net.Conn, ttl uint8) error {
	return nil
}
