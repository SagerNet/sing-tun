//go:build with_gvisor

package tun

import (
	"net"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	E "github.com/sagernet/sing/common/exceptions"
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

func wrapStackError(err tcpip.Error) error {
	switch err.(type) {
	case *tcpip.ErrClosedForSend,
		*tcpip.ErrClosedForReceive,
		*tcpip.ErrAborted:
		return net.ErrClosed
	}
	return E.New(err.String())
}

func wrapError(err error) error {
	if opErr, isOpErr := err.(*net.OpError); isOpErr {
		switch opErr.Err.Error() {
		case "endpoint is closed for send",
			"endpoint is closed for receive",
			"operation aborted":
			return net.ErrClosed
		}
	}
	return err
}
