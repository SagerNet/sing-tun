//go:build linux && !android

package tun

import (
	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

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

		oldInterface := m.defaultInterface.Load()
		newInterface, err := m.interfaceFinder.ByIndex(link.Attrs().Index)
		if err != nil {
			return E.Cause(err, "find updated interface: ", link.Attrs().Name)
		}
		m.defaultInterface.Store(newInterface)
		if oldInterface != nil && oldInterface.Equals(*newInterface) {
			return nil
		}
		m.emit(newInterface, 0)
		return nil
	}
	return ErrNoRoute
}
