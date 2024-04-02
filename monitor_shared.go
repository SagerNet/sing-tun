//go:build linux || windows || darwin

package tun

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"
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
		callback()
	}
}

type defaultInterfaceMonitor struct {
	options               DefaultInterfaceMonitorOptions
	networkAddresses      []networkAddress
	defaultInterfaceName  string
	defaultInterfaceIndex int
	androidVPNEnabled     bool
	networkMonitor        NetworkUpdateMonitor
	checkUpdateTimer      *time.Timer
	element               *list.Element[NetworkUpdateCallback]
	access                sync.Mutex
	callbacks             list.List[DefaultInterfaceUpdateCallback]
	logger                logger.Logger
}

type networkAddress struct {
	interfaceName  string
	interfaceIndex int
	addresses      []netip.Prefix
}

func NewDefaultInterfaceMonitor(networkMonitor NetworkUpdateMonitor, logger logger.Logger, options DefaultInterfaceMonitorOptions) (DefaultInterfaceMonitor, error) {
	return &defaultInterfaceMonitor{
		options:               options,
		networkMonitor:        networkMonitor,
		defaultInterfaceIndex: -1,
		logger:                logger,
	}, nil
}

func (m *defaultInterfaceMonitor) Start() error {
	_ = m.checkUpdate()
	m.element = m.networkMonitor.RegisterCallback(m.delayCheckUpdate)
	return nil
}

func (m *defaultInterfaceMonitor) delayCheckUpdate() {
	if m.checkUpdateTimer == nil {
		m.checkUpdateTimer = time.AfterFunc(time.Second, m.postCheckUpdate)
	} else {
		m.checkUpdateTimer.Reset(time.Second)
	}
}

func (m *defaultInterfaceMonitor) postCheckUpdate() {
	err := m.updateInterfaces()
	if err != nil {
		m.logger.Error("update interfaces: ", err)
	}
	err = m.checkUpdate()
	if errors.Is(err, ErrNoRoute) {
		m.defaultInterfaceName = ""
		m.defaultInterfaceIndex = -1
		m.emit(EventNoRoute)
	} else if err != nil {
		m.logger.Error("check interface: ", err)
	}
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

func (m *defaultInterfaceMonitor) DefaultInterface(destination netip.Addr) (string, int) {
	for _, address := range m.networkAddresses {
		for _, prefix := range address.addresses {
			if prefix.Contains(destination) {
				return address.interfaceName, address.interfaceIndex
			}
		}
	}
	return m.defaultInterfaceName, m.defaultInterfaceIndex
}

func (m *defaultInterfaceMonitor) OverrideAndroidVPN() bool {
	return m.options.OverrideAndroidVPN
}

func (m *defaultInterfaceMonitor) AndroidVPNEnabled() bool {
	return m.androidVPNEnabled
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

func (m *defaultInterfaceMonitor) emit(event int) {
	m.access.Lock()
	callbacks := m.callbacks.Array()
	m.access.Unlock()
	for _, callback := range callbacks {
		callback(event)
	}
}
