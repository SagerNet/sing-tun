package tun

import (
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/vishvananda/netlink"
)

func (m *defaultInterfaceMonitor) checkUpdate() error {
	ruleList, err := netlink.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	var defaultTableIndex int
	for _, rule := range ruleList {
		if rule.Mask == 0xFFFF {
			defaultTableIndex = rule.Table
		}
	}

	if defaultTableIndex == 0 {
		return E.New("no route to internet")
	}

	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: defaultTableIndex}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}

	for _, route := range routes {
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

	return E.New("no route in the system table")
}
