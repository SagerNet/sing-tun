package tun

import (
	"os"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/vishvananda/netlink"
)

type NativeMonitor struct {
	defaultInterfaceName  string
	defaultInterfaceIndex int
	update                chan netlink.RouteUpdate
	close                 chan struct{}
	callback              InterfaceMonitorCallback
}

func NewMonitor(callback InterfaceMonitorCallback) (InterfaceMonitor, error) {
	return &NativeMonitor{
		callback: callback,
		update:   make(chan netlink.RouteUpdate, 2),
		close:    make(chan struct{}),
	}, nil
}

func (m *NativeMonitor) Start() error {
	err := netlink.RouteSubscribe(m.update, m.close)
	if err != nil {
		return err
	}
	err = m.checkUpdate()
	if err != nil {
		return err
	}
	go m.loopUpdate()
	return nil
}

func (m *NativeMonitor) loopUpdate() {
	for {
		select {
		case <-m.close:
			return
		case <-m.update:
			m.checkUpdate()
		}
	}
}

func (m *NativeMonitor) checkUpdate() error {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.Dst != nil {
			continue
		}
		var link netlink.Link
		link, err = netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			return err
		}

		if link.Type() == "tuntap" {
			continue
		}

		oldInterface := m.defaultInterfaceName
		oldIndex := m.defaultInterfaceIndex

		m.defaultInterfaceName = link.Attrs().Name
		m.defaultInterfaceIndex = link.Attrs().Index

		if oldInterface == m.defaultInterfaceName && oldIndex == m.defaultInterfaceIndex {
			return nil
		}
		m.callback()
		return nil
	}
	return E.New("no route to internet")
}

func (m *NativeMonitor) Close() error {
	select {
	case <-m.close:
		return os.ErrClosed
	default:
	}
	close(m.close)
	return nil
}

func (m *NativeMonitor) DefaultInterfaceName() string {
	return m.defaultInterfaceName
}

func (m *NativeMonitor) DefaultInterfaceIndex() int {
	return m.defaultInterfaceIndex
}
