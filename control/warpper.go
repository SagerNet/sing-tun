package control

import (
	"net/netip"
	"syscall"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
)

func Append(oldFunc control.Func, newFunc control.Func) control.Func {
	return control.Append(oldFunc, newFunc)
}

func BindToInterface0(finder InterfaceFinder, conn syscall.RawConn, network string, address string, interfaceName string, interfaceIndex int, preferInterfaceName bool) error {
	return control.BindToInterface0(interfaceFinderWrapper{finder}, conn, network, address, interfaceName, interfaceIndex, preferInterfaceName)
}

type interfaceFinderWrapper struct {
	finder InterfaceFinder
}

func (i interfaceFinderWrapper) Update() error {
	return i.finder.Update()
}

func (i interfaceFinderWrapper) Interfaces() []control.Interface {
	return common.Map(i.finder.Interfaces(), controlInterface)
}

func (i interfaceFinderWrapper) InterfaceIndexByName(name string) (int, error) {
	if netIf, err := i.finder.ByName(name); err == nil {
		return netIf.Index, nil
	} else {
		return 0, err
	}
}

func (i interfaceFinderWrapper) InterfaceNameByIndex(index int) (string, error) {
	if netIf, err := i.finder.ByIndex(index); err == nil {
		return netIf.Name, nil
	} else {
		return "", err
	}
}

func (i interfaceFinderWrapper) InterfaceByAddr(addr netip.Addr) (*control.Interface, error) {
	if netIf, err := i.finder.ByAddr(addr); err == nil {
		cif := controlInterface(*netIf)
		return &cif, nil
	} else {
		return nil, err
	}
}

var _ control.InterfaceFinder = &interfaceFinderWrapper{}

func controlInterface(i Interface) control.Interface {
	return control.Interface{
		Index:        i.Index,
		Name:         i.Name,
		Flags:        i.Flags,
		Addresses:    i.Addresses,
		HardwareAddr: i.HardwareAddr,
	}
}
