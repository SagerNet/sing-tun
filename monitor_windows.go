package tun

import (
	"context"
	"sync"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/windows"
)

type networkUpdateMonitor struct {
	routeListener     *winipcfg.RouteChangeCallback
	interfaceListener *winipcfg.InterfaceChangeCallback
	errorHandler      E.Handler

	access    sync.Mutex
	callbacks list.List[NetworkUpdateCallback]
}

func NewNetworkUpdateMonitor(errorHandler E.Handler) (NetworkUpdateMonitor, error) {
	return &networkUpdateMonitor{
		errorHandler: errorHandler,
	}, nil
}

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
			m.errorHandler.NewError(context.Background(), err)
		}
	}
}

func (m *networkUpdateMonitor) Start() error {
	routeListener, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		m.emit()
	})
	if err != nil {
		return err
	}
	m.routeListener = routeListener
	interfaceListener, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		m.emit()
	})
	if err != nil {
		routeListener.Unregister()
		return err
	}
	m.interfaceListener = interfaceListener
	return nil
}

func (m *networkUpdateMonitor) Close() error {
	return E.Errors(
		m.routeListener.Unregister(),
		m.interfaceListener.Unregister(),
	)
}

type defaultInterfaceMonitor struct {
	defaultInterfaceName  string
	defaultInterfaceIndex int
	networkMonitor        NetworkUpdateMonitor
	element               *list.Element[NetworkUpdateCallback]
	callback              DefaultInterfaceUpdateCallback
}

func NewDefaultInterfaceMonitor(networkMonitor NetworkUpdateMonitor, callback DefaultInterfaceUpdateCallback) (DefaultInterfaceMonitor, error) {
	return &defaultInterfaceMonitor{
		networkMonitor: networkMonitor,
		callback:       callback,
	}, nil
}

func (m *defaultInterfaceMonitor) Start() error {
	err := m.checkUpdate()
	if err != nil {
		return err
	}
	m.element = m.networkMonitor.RegisterCallback(m.checkUpdate)
	return nil
}

func (m *defaultInterfaceMonitor) Close() error {
	m.networkMonitor.UnregisterCallback(m.element)
	return nil
}

func (m *defaultInterfaceMonitor) checkUpdate() error {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return err
	}

	lowestMetric := ^uint32(0)
	alias := ""
	var index int

	for _, row := range rows {
		ifrow, err := row.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		iface, err := row.InterfaceLUID.IPInterface(windows.AF_INET)
		if err != nil {
			continue
		}

		if ifrow.Type == winipcfg.IfTypePropVirtual || ifrow.Type == winipcfg.IfTypeSoftwareLoopback {
			continue
		}

		metric := row.Metric + iface.Metric
		if metric < lowestMetric {
			lowestMetric = metric
			alias = ifrow.Alias()
			index = int(ifrow.InterfaceIndex)
		}
	}

	if alias == "" {
		return ErrNoRoute
	}

	oldInterface := m.defaultInterfaceName
	oldIndex := m.defaultInterfaceIndex

	m.defaultInterfaceName = alias
	m.defaultInterfaceIndex = index

	if oldInterface == m.defaultInterfaceName && oldIndex == m.defaultInterfaceIndex {
		return nil
	}

	m.callback()
	return nil
}

func (m *defaultInterfaceMonitor) DefaultInterfaceName() string {
	return m.defaultInterfaceName
}

func (m *defaultInterfaceMonitor) DefaultInterfaceIndex() int {
	return m.defaultInterfaceIndex
}
