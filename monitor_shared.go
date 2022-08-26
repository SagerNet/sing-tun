//go:build linux || windows || darwin

package tun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
)

func (m *networkUpdateMonitor) RegisterCallback(callback NetworkUpdateCallback) *list.Element[NetworkUpdateCallback] {
	m.access.Lock()
	defer m.access.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *networkUpdateMonitor) UnregisterCallback(element *list.Element[NetworkUpdateCallback]) {
	m.access.Lock()
	defer m.access.Unlock()
	m.callbacks.Remove(element)
}

func (m *networkUpdateMonitor) emit() {
	m.access.Lock()
	callbacks := m.callbacks.Array()
	m.access.Unlock()
	for _, callback := range callbacks {
		err := callback()
		if err != nil {
			m.NewError(context.Background(), err)
		}
	}
}

func (m *networkUpdateMonitor) NewError(ctx context.Context, err error) {
	m.errorHandler.NewError(ctx, err)
}

type defaultInterfaceMonitor struct {
	networkAddresses      []networkAddress
	defaultInterfaceName  string
	defaultInterfaceIndex int
	networkMonitor        NetworkUpdateMonitor
	element               *list.Element[NetworkUpdateCallback]
	access                sync.Mutex
	callbacks             list.List[DefaultInterfaceUpdateCallback]
}

type networkAddress struct {
	interfaceName  string
	interfaceIndex int
	addresses      []netip.Prefix
}

func NewDefaultInterfaceMonitor(networkMonitor NetworkUpdateMonitor) (DefaultInterfaceMonitor, error) {
	return &defaultInterfaceMonitor{
		networkMonitor: networkMonitor,
	}, nil
}

func (m *defaultInterfaceMonitor) Start() error {
	err := m.checkUpdate()
	if err != nil {
		return err
	}
	m.element = m.networkMonitor.RegisterCallback(m.delayCheckUpdate)
	return nil
}

func (m *defaultInterfaceMonitor) delayCheckUpdate() error {
	time.Sleep(time.Second)
	err := m.updateInterfaces()
	if err != nil {
		m.networkMonitor.NewError(context.Background(), E.Cause(err, "update interfaces"))
	}
	return m.checkUpdate()
}

func (m *defaultInterfaceMonitor) updateInterfaces() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	var addresses []networkAddress
	for _, iif := range interfaces {
		var netAddresses []net.Addr
		netAddresses, err = iif.Addrs()
		if err != nil {
			return err
		}
		var address networkAddress
		address.interfaceName = iif.Name
		address.interfaceIndex = iif.Index
		address.addresses = common.Map(common.FilterIsInstance(netAddresses, func(it net.Addr) (*net.IPNet, bool) {
			value, loaded := it.(*net.IPNet)
			return value, loaded
		}), func(it *net.IPNet) netip.Prefix {
			bits, _ := it.Mask.Size()
			return netip.PrefixFrom(M.AddrFromIP(it.IP), bits)
		})
		addresses = append(addresses, address)
	}
	m.networkAddresses = addresses
	return nil
}

func (m *defaultInterfaceMonitor) Close() error {
	if m.element != nil {
		m.networkMonitor.UnregisterCallback(m.element)
	}
	return nil
}

func (m *defaultInterfaceMonitor) DefaultInterfaceName(destination netip.Addr) string {
	for _, address := range m.networkAddresses {
		for _, prefix := range address.addresses {
			if prefix.Contains(destination) {
				return address.interfaceName
			}
		}
	}
	return m.defaultInterfaceName
}

func (m *defaultInterfaceMonitor) DefaultInterfaceIndex(destination netip.Addr) int {
	for _, address := range m.networkAddresses {
		for _, prefix := range address.addresses {
			if prefix.Contains(destination) {
				return address.interfaceIndex
			}
		}
	}
	return m.defaultInterfaceIndex
}

func (m *defaultInterfaceMonitor) RegisterCallback(callback DefaultInterfaceUpdateCallback) *list.Element[DefaultInterfaceUpdateCallback] {
	m.access.Lock()
	defer m.access.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *defaultInterfaceMonitor) UnregisterCallback(element *list.Element[DefaultInterfaceUpdateCallback]) {
	m.access.Lock()
	defer m.access.Unlock()
	m.callbacks.Remove(element)
}

func (m *defaultInterfaceMonitor) emit() {
	m.access.Lock()
	callbacks := m.callbacks.Array()
	m.access.Unlock()
	for _, callback := range callbacks {
		err := callback()
		if err != nil {
			m.networkMonitor.NewError(context.Background(), err)
		}
	}
}
