package tun

import (
	"context"
	"net"
	"os"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"

	"github.com/vishvananda/netlink"
)

type networkUpdateMonitor struct {
	routeUpdate  chan netlink.RouteUpdate
	linkUpdate   chan netlink.LinkUpdate
	close        chan struct{}
	errorHandler E.Handler

	access    sync.Mutex
	callbacks list.List[NetworkUpdateCallback]
}

func NewNetworkUpdateMonitor(errorHandler E.Handler) (NetworkUpdateMonitor, error) {
	return &networkUpdateMonitor{
		routeUpdate:  make(chan netlink.RouteUpdate, 2),
		linkUpdate:   make(chan netlink.LinkUpdate, 2),
		close:        make(chan struct{}),
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
	err := netlink.RouteSubscribe(m.routeUpdate, m.close)
	if err != nil {
		return err
	}
	err = netlink.LinkSubscribe(m.linkUpdate, m.close)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	go m.loopUpdate()
	return nil
}

func (m *networkUpdateMonitor) loopUpdate() {
	for {
		select {
		case <-m.close:
			return
		case <-m.routeUpdate:
		case <-m.linkUpdate:
		}
		m.emit()
	}
}

func (m *networkUpdateMonitor) Close() error {
	select {
	case <-m.close:
		return os.ErrClosed
	default:
	}
	close(m.close)
	return nil
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
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, route := range routes {
		var link netlink.Link
		link, err = netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			return err
		}

		if link.Attrs().Flags&net.FlagUp == 0 {
			continue
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

func (m *defaultInterfaceMonitor) DefaultInterfaceName() string {
	return m.defaultInterfaceName
}

func (m *defaultInterfaceMonitor) DefaultInterfaceIndex() int {
	return m.defaultInterfaceIndex
}
