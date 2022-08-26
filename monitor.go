package tun

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
)

var ErrNoRoute = E.New("no route to internet")

type (
	NetworkUpdateCallback          = func() error
	DefaultInterfaceUpdateCallback = func() error
)

type NetworkUpdateMonitor interface {
	Start() error
	Close() error
	RegisterCallback(callback NetworkUpdateCallback) *list.Element[NetworkUpdateCallback]
	UnregisterCallback(element *list.Element[NetworkUpdateCallback])
	E.Handler
}

type DefaultInterfaceMonitor interface {
	Start() error
	Close() error
	DefaultInterfaceName(destination netip.Addr) string
	DefaultInterfaceIndex(destination netip.Addr) int
	RegisterCallback(callback DefaultInterfaceUpdateCallback) *list.Element[DefaultInterfaceUpdateCallback]
	UnregisterCallback(element *list.Element[DefaultInterfaceUpdateCallback])
}
