package tun

import E "github.com/sagernet/sing/common/exceptions"

var ErrNoRoute = E.New("no route to internet")

type InterfaceMonitor interface {
	Start() error
	Close() error
	DefaultInterfaceName() string
	DefaultInterfaceIndex() int
}

type InterfaceMonitorCallback func()
