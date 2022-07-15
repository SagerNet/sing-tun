//go:build linux && !android

package tun

import (
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (m *defaultInterfaceMonitor) checkUpdate() error {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
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
