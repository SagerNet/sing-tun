//go:build linux && !android

package tun

import (
	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func (m *defaultInterfaceMonitor) checkUpdate() error {
	var linkIndex int
	err := netlink.RouteListFilteredIter(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE, func(route netlink.Route) bool {
		if route.Dst != nil || route.Type != unix.RTN_UNICAST {
			return true
		}
		if len(route.MultiPath) == 0 {
			linkIndex = route.LinkIndex
		} else if nexthop := common.Find(route.MultiPath, func(it *netlink.NexthopInfo) bool {
			return it.Flags&unix.RTNH_F_DEAD == 0
		}); nexthop != nil {
			linkIndex = nexthop.LinkIndex
		}
		return linkIndex == 0
	})
	if err != nil {
		return E.Cause(err, "list routes")
	}
	if linkIndex == 0 {
		return ErrNoRoute
	}

	link, err := netlink.LinkByIndex(linkIndex)
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
