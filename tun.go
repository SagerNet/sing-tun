//go:build !no_gvisor

package tun

import (
	N "github.com/sagernet/sing/common/network"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Handler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
}

type Tun interface {
	NewEndpoint() (stack.LinkEndpoint, error)
	Close() error
}
