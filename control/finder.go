package control

import (
	"net"
	"net/netip"
	"unsafe"

	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/exp/slices"
)

type InterfaceFinder interface {
	Update() error
	Interfaces() []Interface
	ByName(name string) (*Interface, error)
	ByIndex(index int) (*Interface, error)
	ByAddr(addr netip.Addr) (*Interface, error)
}

type Interface struct {
	Index        int
	MTU          int
	Name         string
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
	Addresses    []netip.Prefix
}

func (i Interface) Equals(other Interface) bool {
	return i.Index == other.Index &&
		i.MTU == other.MTU &&
		i.Name == other.Name &&
		slices.Equal(i.HardwareAddr, other.HardwareAddr) &&
		i.Flags == other.Flags &&
		slices.Equal(i.Addresses, other.Addresses)
}

func (i Interface) NetInterface() net.Interface {
	return *(*net.Interface)(unsafe.Pointer(&i))
}

func InterfaceFromNet(iif net.Interface) (Interface, error) {
	ifAddrs, err := iif.Addrs()
	if err != nil {
		return Interface{}, err
	}
	return InterfaceFromNetAddrs(iif, common.Map(ifAddrs, M.PrefixFromNet)), nil
}

func InterfaceFromNetAddrs(iif net.Interface, addresses []netip.Prefix) Interface {
	return Interface{
		Index:        iif.Index,
		MTU:          iif.MTU,
		Name:         iif.Name,
		HardwareAddr: iif.HardwareAddr,
		Flags:        iif.Flags,
		Addresses:    addresses,
	}
}
