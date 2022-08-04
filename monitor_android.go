package tun

import (
	"github.com/sagernet/netlink"
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
		return ErrNoRoute
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
		m.emit()
		return nil
	}

	return ErrNoRoute
}
