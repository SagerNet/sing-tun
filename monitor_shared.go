//go:build linux || windows || darwin

package tun

import (
	"context"
	"sync"

	"github.com/sagernet/sing/common/x/list"
	"time"
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
	defaultInterfaceName  string
	defaultInterfaceIndex int
	networkMonitor        NetworkUpdateMonitor
	element               *list.Element[NetworkUpdateCallback]
	access                sync.Mutex
	callbacks             list.List[DefaultInterfaceUpdateCallback]
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
	return m.checkUpdate()
}

func (m *defaultInterfaceMonitor) Close() error {
	m.networkMonitor.UnregisterCallback(m.element)
	return nil
}

func (m *defaultInterfaceMonitor) DefaultInterfaceName() string {
	return m.defaultInterfaceName
}

func (m *defaultInterfaceMonitor) DefaultInterfaceIndex() int {
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
