//go:build linux

package tun

import (
	"errors"
	"math/rand"
	"net"
	"slices"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const redirectRouteRulePriority = 1

func (r *autoRedirect) setupRedirectRoutes() error {
	err := r.interfaceFinder.Update()
	if err != nil {
		return E.Cause(err, "update interfaces")
	}
	redirectInterfaces := r.currentRedirectInterfaces()
	r.redirectRouteAccess.Lock()
	defer r.redirectRouteAccess.Unlock()
	r.redirectRoutesActive = false
	r.cleanupRedirectRoutesLocked()
	r.cleanupStaleRouteRules(redirectRouteRulePriority, 0)
	if r.tproxyEnabled() {
		r.cleanupStaleRouteRules(redirectRouteRulePriority, r.tunOptions.AutoRedirectTProxyMark)
	}
	r.redirectRouteTableIndex = chooseRouteTableIndex(r.tunOptions.IPRoute2TableIndex, r.tproxyRouteTableIndex)
	defer func() {
		if err != nil {
			r.cleanupRedirectRoutesLocked()
		}
	}()
	err = r.reconcileRedirectRoutesLocked(redirectInterfaces)
	if err != nil {
		return err
	}
	if r.enableIPv4 {
		rule := netlink.NewRule()
		rule.Priority = redirectRouteRulePriority
		rule.Table = r.redirectRouteTableIndex
		rule.Family = unix.AF_INET
		err = netlink.RuleAdd(rule)
		if err != nil {
			return E.Cause(err, "add ipv4 redirect rule")
		}
	}
	if r.enableIPv6 {
		rule := netlink.NewRule()
		rule.Priority = redirectRouteRulePriority
		rule.Table = r.redirectRouteTableIndex
		rule.Family = unix.AF_INET6
		err = netlink.RuleAdd(rule)
		if err != nil {
			return E.Cause(err, "add ipv6 redirect rule")
		}
	}
	if r.tproxyEnabled() {
		err = r.setupTProxyRouteLocked()
		if err != nil {
			return err
		}
	}
	r.redirectRoutesActive = true
	return nil
}

func (r *autoRedirect) setupTProxyRouteLocked() error {
	r.tproxyRouteTableIndex = chooseRouteTableIndex(r.tunOptions.IPRoute2TableIndex, r.redirectRouteTableIndex)
	loopbackLink, err := netlink.LinkByName("lo")
	if err != nil {
		return E.Cause(err, "find loopback interface")
	}
	route := netlink.Route{
		LinkIndex: loopbackLink.Attrs().Index,
		Dst:       defaultDestination(unix.AF_INET6),
		Table:     r.tproxyRouteTableIndex,
		Type:      unix.RTN_LOCAL,
		Scope:     netlink.SCOPE_HOST,
	}
	err = netlink.RouteAdd(&route)
	if err != nil {
		return E.Cause(err, "add tproxy route")
	}
	rule := r.tproxyRouteRule()
	err = netlink.RuleAdd(rule)
	if err != nil {
		return E.Cause(err, "add tproxy rule")
	}
	return nil
}

func (r *autoRedirect) tproxyRouteRule() *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = redirectRouteRulePriority
	rule.Family = unix.AF_INET6
	rule.Mark = r.tunOptions.AutoRedirectTProxyMark
	rule.MarkSet = true
	rule.Mask = int(r.effectiveMarkMask())
	rule.Table = r.tproxyRouteTableIndex
	return rule
}

func (r *autoRedirect) currentRedirectInterfaces() []control.Interface {
	tunName := r.tunOptions.Name
	return common.Filter(r.interfaceFinder.Interfaces(), func(it control.Interface) bool {
		return it.Name != "lo" && it.Name != tunName && it.Flags&net.FlagUp != 0
	})
}

func redirectRouteAddressFamilies(iface control.Interface) (hasIPv4Address bool, hasIPv6Address bool) {
	for _, prefix := range iface.Addresses {
		address := prefix.Addr()
		if address.Is4() {
			hasIPv4Address = true
		} else if address.Is6() && !address.Is4In6() {
			hasIPv6Address = true
		}
	}
	return
}

func (r *autoRedirect) updateRedirectRoutes() error {
	err := r.interfaceFinder.Update()
	if err != nil {
		return E.Cause(err, "update interfaces")
	}
	redirectInterfaces := r.currentRedirectInterfaces()
	r.redirectRouteAccess.Lock()
	defer r.redirectRouteAccess.Unlock()
	if !r.redirectRoutesActive {
		return nil
	}
	return r.reconcileRedirectRoutesLocked(redirectInterfaces)
}

func (r *autoRedirect) cleanupRedirectRoutes() {
	r.redirectRouteAccess.Lock()
	defer r.redirectRouteAccess.Unlock()
	r.redirectRoutesActive = false
	r.cleanupRedirectRoutesLocked()
}

func (r *autoRedirect) cleanupRedirectRoutesLocked() {
	if r.redirectRouteTableIndex == 0 {
		return
	}
	routes, _ := netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{Table: r.redirectRouteTableIndex},
		netlink.RT_FILTER_TABLE)
	for _, route := range routes {
		_ = netlink.RouteDel(&route)
	}
	if r.enableIPv4 {
		rule := netlink.NewRule()
		rule.Priority = redirectRouteRulePriority
		rule.Table = r.redirectRouteTableIndex
		rule.Family = unix.AF_INET
		_ = netlink.RuleDel(rule)
	}
	if r.enableIPv6 {
		rule := netlink.NewRule()
		rule.Priority = redirectRouteRulePriority
		rule.Table = r.redirectRouteTableIndex
		rule.Family = unix.AF_INET6
		_ = netlink.RuleDel(rule)
	}
	if r.tproxyRouteTableIndex != 0 {
		flushRouteTable(r.tproxyRouteTableIndex)
		_ = netlink.RuleDel(r.tproxyRouteRule())
	}
}

type redirectRouteKey struct {
	linkIndex int
	family    int
}

func (r *autoRedirect) reconcileRedirectRoutesLocked(redirectInterfaces []control.Interface) error {
	currentRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{Table: r.redirectRouteTableIndex},
		netlink.RT_FILTER_TABLE)
	if err != nil {
		return E.Cause(err, "list redirect routes")
	}
	routesToAdd, routesToDelete := calculateRedirectRouteChanges(
		r.redirectRouteTableIndex,
		redirectInterfaces,
		currentRoutes,
		r.enableIPv4,
		r.enableIPv6,
	)
	for index := range routesToDelete {
		route := &routesToDelete[index]
		err = netlink.RouteDel(route)
		if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
			return E.Cause(err, "delete redirect route ", route)
		}
	}
	for index := range routesToAdd {
		route := &routesToAdd[index]
		err = netlink.RouteAppend(route)
		if err != nil {
			return E.Cause(err, "append redirect route ", route)
		}
	}
	return nil
}

func calculateRedirectRouteChanges(
	tableIndex int,
	redirectInterfaces []control.Interface,
	currentRoutes []netlink.Route,
	enableIPv4 bool,
	enableIPv6 bool,
) (routesToAdd []netlink.Route, routesToDelete []netlink.Route) {
	desiredRoutes := make(map[redirectRouteKey]struct{}, len(redirectInterfaces)*2)
	for _, iface := range redirectInterfaces {
		hasIPv4Address, hasIPv6Address := redirectRouteAddressFamilies(iface)
		if enableIPv4 && hasIPv4Address {
			desiredRoutes[redirectRouteKey{linkIndex: iface.Index, family: unix.AF_INET}] = struct{}{}
		}
		if enableIPv6 && hasIPv6Address {
			desiredRoutes[redirectRouteKey{linkIndex: iface.Index, family: unix.AF_INET6}] = struct{}{}
		}
	}
	for _, route := range currentRoutes {
		key, isRedirectRoute := redirectRouteKeyFromRoute(route)
		if !isRedirectRoute {
			continue
		}
		if _, desired := desiredRoutes[key]; desired {
			delete(desiredRoutes, key)
			continue
		}
		routesToDelete = append(routesToDelete, route)
	}
	for key := range desiredRoutes {
		routesToAdd = append(routesToAdd, newRedirectRoute(tableIndex, key))
	}
	return
}

func newRedirectRoute(tableIndex int, key redirectRouteKey) netlink.Route {
	destination := net.IPv6loopback
	if key.family == unix.AF_INET {
		destination = net.IPv4(127, 0, 0, 1)
	}
	return netlink.Route{
		LinkIndex: key.linkIndex,
		Dst:       netlink.NewIPNet(destination),
		Table:     tableIndex,
		Type:      unix.RTN_LOCAL,
		Scope:     netlink.SCOPE_HOST,
	}
}

func redirectRouteKeyFromRoute(route netlink.Route) (redirectRouteKey, bool) {
	if redirectRouteDestinationMatches(route.Dst, net.IPv4(127, 0, 0, 1), 32) {
		return redirectRouteKey{linkIndex: route.LinkIndex, family: unix.AF_INET}, true
	}
	if redirectRouteDestinationMatches(route.Dst, net.IPv6loopback, 128) {
		return redirectRouteKey{linkIndex: route.LinkIndex, family: unix.AF_INET6}, true
	}
	return redirectRouteKey{}, false
}

func redirectRouteDestinationMatches(destination *net.IPNet, address net.IP, prefixBits int) bool {
	if destination == nil || !destination.IP.Equal(address) {
		return false
	}
	ones, bits := destination.Mask.Size()
	return ones == prefixBits && bits == prefixBits
}

func chooseRouteTableIndex(excludedIndexes ...int) int {
	for {
		tableIndex := int(rand.Uint32() & 0x7fffffff)
		if tableIndex <= 255 || slices.Contains(excludedIndexes, tableIndex) {
			continue
		}
		if !routeTableOccupied(tableIndex) {
			return tableIndex
		}
	}
}

func routeTableOccupied(tableIndex int) bool {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		routes, err := netlink.RouteListFiltered(family,
			&netlink.Route{Table: tableIndex},
			netlink.RT_FILTER_TABLE)
		if err == nil && len(routes) > 0 {
			return true
		}
	}
	return false
}

func flushRouteTable(tableIndex int) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		flushRouteTableFamily(tableIndex, family)
	}
}

func flushRouteTableFamily(tableIndex int, family int) {
	routes, _ := netlink.RouteListFiltered(family,
		&netlink.Route{Table: tableIndex},
		netlink.RT_FILTER_TABLE)
	for index := range routes {
		route := &routes[index]
		if route.Dst == nil {
			route.Dst = defaultDestination(family)
		}
		_ = netlink.RouteDel(route)
	}
}

func (r *autoRedirect) cleanupStaleRouteRules(priority int, mark uint32) {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := netlink.RuleListFiltered(family,
			&netlink.Rule{Priority: priority},
			netlink.RT_FILTER_PRIORITY)
		if err != nil {
			continue
		}
		for index := range rules {
			staleRule := &rules[index]
			if staleRule.Mark != mark || staleRule.Table <= 255 {
				continue
			}
			flushRouteTable(staleRule.Table)
			_ = netlink.RuleDel(staleRule)
		}
	}
}

func defaultDestination(family int) *net.IPNet {
	if family == unix.AF_INET6 {
		return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	return &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
}
