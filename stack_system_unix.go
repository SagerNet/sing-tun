//go:build !windows

package tun

import (
	"net"

	"github.com/metacubex/sing/common/control"

	"golang.org/x/sys/unix"
)

func acceptConn(conn net.Conn) error {
	return control.Conn(conn.(*net.TCPConn), func(fd uintptr) error {
		const bufferSize = 1024 * 1024
		oErr := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, bufferSize)
		if oErr != nil {
			return oErr
		}
		oErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, bufferSize)
		if oErr != nil {
			return oErr
		}
		return nil
	})
}
