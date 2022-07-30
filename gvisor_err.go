package tun

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type gTCPConn struct {
	*gonet.TCPConn
}

func (c *gTCPConn) Upstream() any {
	return c.TCPConn
}

func (c *gTCPConn) Write(b []byte) (n int, err error) {
	n, err = c.TCPConn.Write(b)
	if err == nil {
		return
	}
	err = wrapError(err)
	return
}

type gUDPConn struct {
	*gonet.UDPConn
}

func (c *gUDPConn) Read(b []byte) (n int, err error) {
	n, err = c.UDPConn.Read(b)
	if err == nil {
		return
	}
	err = wrapError(err)
	return
}

func (c *gUDPConn) Write(b []byte) (n int, err error) {
	n, err = c.UDPConn.Write(b)
	if err == nil {
		return
	}
	err = wrapError(err)
	return
}

func wrapStackError(err tcpip.Error) error {
	switch err.(type) {
	case *tcpip.ErrClosedForSend:
		return net.ErrClosed
	case *tcpip.ErrClosedForReceive:
		return net.ErrClosed
	}
	return wrapStackError(err)
}

func wrapError(err error) error {
	if opErr, isOpErr := err.(*net.OpError); isOpErr {
		switch opErr.Err.Error() {
		case "endpoint is closed for send":
			return net.ErrClosed
		case "endpoint is closed for receive":
			return net.ErrClosed
		}
	}
	return err
}
