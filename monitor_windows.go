package tun

import (
	"github.com/sagernet/sing-tun/internal/winipcfg"

	"golang.org/x/sys/windows"
)

var _ InterfaceMonitor = (*NativeMonitor)(nil)

type NativeMonitor struct {
	listener              *winipcfg.RouteChangeCallback
	callback              InterfaceMonitorCallback
	defaultInterfaceName  string
	defaultInterfaceIndex int
}

func NewMonitor(callback InterfaceMonitorCallback) (InterfaceMonitor, error) {
	return &NativeMonitor{callback: callback}, nil
}

func (m *NativeMonitor) Start() error {
	err := m.checkUpdate()
	if err != nil {
		return err
	}
	listener, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		m.checkUpdate()
	})
	if err != nil {
		return err
	}
	m.listener = listener
	return nil
}

func (m *NativeMonitor) checkUpdate() error {
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

func (m *NativeMonitor) Close() error {
	return m.listener.Unregister()
}

func (m *NativeMonitor) DefaultInterfaceName() string {
	return m.defaultInterfaceName
}

func (m *NativeMonitor) DefaultInterfaceIndex() int {
	return m.defaultInterfaceIndex
}
