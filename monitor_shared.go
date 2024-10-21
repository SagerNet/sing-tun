//go:build linux || windows || darwin

package tun

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
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
	interfaceFinder       control.InterfaceFinder
	overrideAndroidVPN    bool
	underNetworkExtension bool
	defaultInterfaceName  string
	defaultInterfaceIndex int
	androidVPNEnabled     bool
	noRoute               bool
	networkMonitor        NetworkUpdateMonitor
	checkUpdateTimer      *time.Timer
	element               *list.Element[NetworkUpdateCallback]
	access                sync.Mutex
	callbacks             list.List[DefaultInterfaceUpdateCallback]
	logger                logger.Logger
}

func NewDefaultInterfaceMonitor(networkMonitor NetworkUpdateMonitor, logger logger.Logger, options DefaultInterfaceMonitorOptions) (DefaultInterfaceMonitor, error) {
	return &defaultInterfaceMonitor{
		interfaceFinder:       options.InterfaceFinder,
		overrideAndroidVPN:    options.OverrideAndroidVPN,
		underNetworkExtension: options.UnderNetworkExtension,
		networkMonitor:        networkMonitor,
		defaultInterfaceIndex: -1,
		logger: logger,
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
	err := m.interfaceFinder.Update()
	if err != nil {
		m.logger.Error("update interfaces: ", err)
	}
	err = m.checkUpdate()
	if errors.Is(err, ErrNoRoute) {
		if !m.noRoute {
			m.noRoute = true
			m.defaultInterfaceName = ""
			m.defaultInterfaceIndex = -1
			m.emit(EventNoRoute)
		}
	} else if err != nil {
		m.logger.Error("check interface: ", err)
	} else {
		m.noRoute = false
	}
}

func (m *defaultInterfaceMonitor) Close() error {
	if m.element != nil {
		m.networkMonitor.UnregisterCallback(m.element)
	}
	return nil
}

func (m *defaultInterfaceMonitor) DefaultInterfaceName(destination netip.Addr) string {
	for _, address := range m.interfaceFinder.Interfaces() {
		for _, prefix := range address.Addresses {
			if prefix.Contains(destination) {
				return address.Name
			}
		}
	}
	return m.defaultInterfaceName
}

func (m *defaultInterfaceMonitor) DefaultInterfaceIndex(destination netip.Addr) int {
	for _, address := range m.interfaceFinder.Interfaces() {
		for _, prefix := range address.Addresses {
			if prefix.Contains(destination) {
				return address.Index
			}
		}
	}
	return m.defaultInterfaceIndex
}

func (m *defaultInterfaceMonitor) DefaultInterface(destination netip.Addr) (string, int) {
	for _, address := range m.interfaceFinder.Interfaces() {
		for _, prefix := range address.Addresses {
			if prefix.Contains(destination) {
				return address.Name, address.Index
			}
		}
	}
	return m.defaultInterfaceName, m.defaultInterfaceIndex
}

func (m *defaultInterfaceMonitor) OverrideAndroidVPN() bool {
	return m.overrideAndroidVPN
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
