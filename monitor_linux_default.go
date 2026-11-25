//go:build linux && !android

package tun

import (
	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func (m *defaultInterfaceMonitor) checkUpdate() error {
	var defaultRoute *netlink.Route
	err := netlink.RouteListFilteredIter(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE, func(route netlink.Route) bool {
		if route.Dst != nil {
			return true
		}
		defaultRoute = &route
		return false
	})
	if err != nil {
		return E.Cause(err, "list routes")
	}
	if defaultRoute == nil {
		return ErrNoRoute
	}

	link, err := netlink.LinkByIndex(defaultRoute.LinkIndex)
	if err != nil {
		return E.Cause(err, "find link by index")
	}

	newInterface, err := m.interfaceFinder.ByIndex(link.Attrs().Index)
	if err != nil {
		return E.Cause(err, "find updated interface: ", link.Attrs().Name)
	}
	oldInterface := m.defaultInterface.Swap(newInterface)
	if !defaultInterfaceChanged(oldInterface, newInterface) {
		return nil
	}
	m.emit(newInterface, 0)
	return nil
}
