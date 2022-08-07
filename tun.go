package tun

import (
	N "github.com/sagernet/sing/common/network"
)

type Handler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
}

type Tun interface {
	Close() error
}
