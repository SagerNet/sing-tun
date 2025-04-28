package tun

import (
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
)

var ErrNoRoute = E.New("no route to internet")

type (
	NetworkUpdateCallback          = func()
	DefaultInterfaceUpdateCallback = func(defaultInterface *control.Interface, flags int)
)

const FlagAndroidVPNUpdate = 1 << iota

type NetworkUpdateMonitor interface {
	Start() error
	Close() error
	RegisterCallback(callback NetworkUpdateCallback) *list.Element[NetworkUpdateCallback]
	UnregisterCallback(element *list.Element[NetworkUpdateCallback])
}

type DefaultInterfaceMonitor interface {
	Start() error
	Close() error
	DefaultInterface() *control.Interface
	OverrideAndroidVPN() bool
	AndroidVPNEnabled() bool
	RegisterCallback(callback DefaultInterfaceUpdateCallback) *list.Element[DefaultInterfaceUpdateCallback]
	UnregisterCallback(element *list.Element[DefaultInterfaceUpdateCallback])
	RegisterMyInterface(interfaceName string)
	MyInterface() string
}

type DefaultInterfaceMonitorOptions struct {
	InterfaceFinder       control.InterfaceFinder
	OverrideAndroidVPN    bool
	UnderNetworkExtension bool
}
