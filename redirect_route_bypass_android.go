package tun

import (
	"net"
	"net/netip"
	"slices"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

	"go4.org/netipx"
	"golang.org/x/sys/unix"
)

func (r *autoRedirect) setupBypassRoute() {
	if r.routeAddressSet == nil {
		return
	}
	r.bypassRouteAccess.Lock()
	defer r.bypassRouteAccess.Unlock()
	r.cleanupStaleRouteRules(r.androidVPNServiceRulePriority(), 0)
	r.bypassRouteTableIndex = chooseRouteTableIndex(r.tunOptions.IPRoute2TableIndex, r.redirectRouteTableIndex, r.tproxyRouteTableIndex)
	err := r.refreshBypassAddressesLocked()
	if err == nil {
		err = r.rebuildBypassRouteLocked()
	}
	if err != nil {
		r.cleanupBypassRouteLocked()
		r.logger.Warn("address set destinations keep their pre-match bypass: setup bypass route: ", err)
		return
	}
	r.bypassRouteActive = true
}

func (r *autoRedirect) updateBypassRoute() error {
	r.bypassRouteAccess.Lock()
	defer r.bypassRouteAccess.Unlock()
	if !r.bypassRouteActive {
		return nil
	}
	return r.rebuildBypassRouteLocked()
}

func (r *autoRedirect) UpdateRouteAddressSet() error {
	r.bypassRouteAccess.Lock()
	defer r.bypassRouteAccess.Unlock()
	if !r.bypassRouteActive {
		return nil
	}
	err := r.refreshBypassAddressesLocked()
	if err != nil {
		return err
	}
	return r.rebuildBypassRouteLocked()
}

func (r *autoRedirect) refreshBypassAddressesLocked() error {
	include, exclude, err := r.routeAddressSet()
	if err != nil {
		return E.Cause(err, "fetch route address set")
	}
	r.bypassIncludeAddresses = include
	r.bypassExcludeAddresses = exclude
	return nil
}

func (r *autoRedirect) cleanupBypassRoute() {
	r.bypassRouteAccess.Lock()
	defer r.bypassRouteAccess.Unlock()
	r.bypassRouteActive = false
	r.cleanupBypassRouteLocked()
}

func (r *autoRedirect) cleanupBypassRouteLocked() {
	if r.bypassRouteTableIndex == 0 {
		return
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		_ = netlink.RuleDel(r.bypassRouteRule(family))
	}
	flushRouteTable(r.bypassRouteTableIndex)
}

func (r *autoRedirect) rebuildBypassRouteLocked() error {
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if family == unix.AF_INET && !r.enableIPv4 || family == unix.AF_INET6 && !r.enableIPv6 {
			continue
		}
		err := r.rebuildBypassRouteFamilyLocked(family)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *autoRedirect) rebuildBypassRouteFamilyLocked(family int) error {
	tunPrefixes := r.tunOptions.Inet4Address
	if family == unix.AF_INET6 {
		tunPrefixes = r.tunOptions.Inet6Address
	}
	set, err := bypassAddressSet(family, r.bypassIncludeAddresses, r.bypassExcludeAddresses, tunPrefixes)
	if err != nil {
		return E.Cause(err, "build bypass address set")
	}
	rule := r.bypassRouteRule(family)
	if len(set.Ranges()) == 0 {
		_ = netlink.RuleDel(rule)
		flushRouteTableFamily(r.bypassRouteTableIndex, family)
		return nil
	}
	ruleList, err := netlink.RuleList(family)
	if err != nil {
		return E.Cause(err, "list rules")
	}
	sources := r.bypassRouteSources(family, ruleList)
	// netd rebuilds its rules and tables asynchronously after a network
	// change, so an update can observe them half-built; the repopulated
	// tables generate route events that schedule another rebuild.
	if len(sources) == 0 {
		r.logger.Debug("bypass route family ", family, ": no source tables, keeping current routes")
		return nil
	}
	routes, err := buildBypassRoutes(family, set, sources, r.bypassRouteTableIndex)
	if err != nil {
		return E.Cause(err, "build bypass routes")
	}
	if len(routes) == 0 {
		r.logger.Debug("bypass route family ", family, ": no routes built from ", len(sources), " sources, keeping current routes")
		return nil
	}
	changed, err := r.reconcileBypassRoutesLocked(family, routes)
	if err != nil {
		return err
	}
	if changed > 0 {
		r.logger.Debug("bypass route family ", family, ": ", changed, " of ", len(routes), " routes changed, from ", len(sources), " sources")
	}
	if !slices.ContainsFunc(ruleList, func(it netlink.Rule) bool {
		return it.Table == r.bypassRouteTableIndex
	}) {
		err = netlink.RuleAdd(rule)
		if err != nil {
			return E.Cause(err, "add bypass rule")
		}
	}
	return nil
}

func (r *autoRedirect) reconcileBypassRoutesLocked(family int, desired []netlink.Route) (int, error) {
	current, err := netlink.RouteListFiltered(family, &netlink.Route{Table: r.bypassRouteTableIndex}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, E.Cause(err, "list bypass routes")
	}
	desiredByDestination := make(map[string]*netlink.Route, len(desired))
	for index := range desired {
		desiredByDestination[desired[index].Dst.String()] = &desired[index]
	}
	matched := make(map[string]bool, len(desired))
	var changed int
	for index := range current {
		currentRoute := &current[index]
		if currentRoute.Dst == nil {
			currentRoute.Dst = defaultDestination(family)
		}
		destination := currentRoute.Dst.String()
		desiredRoute, exists := desiredByDestination[destination]
		if exists && bypassRouteEquals(currentRoute, desiredRoute) {
			matched[destination] = true
			continue
		}
		// RouteReplace only overwrites a route with the same metric; a
		// current route with another metric would survive alongside it.
		if !exists || currentRoute.Priority != desiredRoute.Priority {
			_ = netlink.RouteDel(currentRoute)
			changed++
		}
	}
	for index := range desired {
		desiredRoute := &desired[index]
		if matched[desiredRoute.Dst.String()] {
			continue
		}
		err = netlink.RouteReplace(desiredRoute)
		if err != nil {
			return changed, E.Cause(err, "add bypass route ", desiredRoute.Dst)
		}
		changed++
	}
	return changed, nil
}

func bypassRouteEquals(left *netlink.Route, right *netlink.Route) bool {
	return left.LinkIndex == right.LinkIndex &&
		left.Scope == right.Scope &&
		left.Priority == right.Priority &&
		left.Gw.Equal(right.Gw) &&
		routeSourceEquals(left.Src, right.Src)
}

func routeSourceEquals(left *net.IPNet, right *net.IPNet) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.IP.Equal(right.IP) && slices.Equal(left.Mask, right.Mask)
}

func (r *autoRedirect) bypassRouteRule(family int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = r.androidVPNServiceRulePriority()
	rule.Family = family
	rule.Table = r.bypassRouteTableIndex
	if r.tunOptions.DNSModeOrDefault() == DNSModeHijack {
		rule.Invert = true
		rule.Dport = netlink.NewRulePortRange(53, 53)
	}
	return rule
}

func (r *autoRedirect) bypassRouteSources(family int, ruleList []netlink.Rule) []netlink.Route {
	tables := discoverAndroidVPNServiceTables(ruleList, r.tunOptions.Name)
	var sourceTables []int
	if tables.localNetwork > 0 {
		sourceTables = append(sourceTables, tables.localNetwork)
	}
	sourceTables = append(sourceTables, tables.physical...)
	var specificRoutes []netlink.Route
	var defaultRoutes []netlink.Route
	for _, sourceTable := range sourceTables {
		routes, listErr := netlink.RouteListFiltered(family, &netlink.Route{Table: sourceTable}, netlink.RT_FILTER_TABLE)
		if listErr != nil {
			continue
		}
		for _, route := range routes {
			if route.Type != 0 && route.Type != unix.RTN_UNICAST {
				continue
			}
			if routeDestination(family, route.Dst).Bits() == 0 {
				defaultRoutes = append(defaultRoutes, route)
			} else {
				specificRoutes = append(specificRoutes, route)
			}
		}
	}
	slices.SortStableFunc(specificRoutes, func(left netlink.Route, right netlink.Route) int {
		return routeDestination(family, right.Dst).Bits() - routeDestination(family, left.Dst).Bits()
	})
	return append(specificRoutes, defaultRoutes...)
}

func buildBypassRoutes(family int, set *netipx.IPSet, sources []netlink.Route, tableIndex int) ([]netlink.Route, error) {
	remaining := set
	var routes []netlink.Route
	for _, source := range sources {
		if len(remaining.Ranges()) == 0 {
			break
		}
		destination := routeDestination(family, source.Dst)
		if !destination.IsValid() {
			continue
		}
		part, err := intersectPrefix(remaining, destination)
		if err != nil {
			return nil, err
		}
		if len(part.Ranges()) == 0 {
			continue
		}
		for _, prefix := range part.Prefixes() {
			route := source
			route.Dst = prefixToIPNet(prefix)
			route.Table = tableIndex
			routes = append(routes, route)
		}
		var remainingBuilder netipx.IPSetBuilder
		remainingBuilder.AddSet(remaining)
		remainingBuilder.RemoveSet(part)
		remaining, err = remainingBuilder.IPSet()
		if err != nil {
			return nil, err
		}
	}
	return routes, nil
}

func bypassAddressSet(family int, include []netip.Prefix, exclude []netip.Prefix, tunPrefixes []netip.Prefix) (*netipx.IPSet, error) {
	var builder netipx.IPSetBuilder
	for _, prefix := range exclude {
		if prefixMatchesFamily(family, prefix) {
			builder.AddPrefix(prefix)
		}
	}
	if len(include) > 0 {
		builder.AddPrefix(unspecifiedPrefix(family))
		for _, prefix := range include {
			if prefixMatchesFamily(family, prefix) {
				builder.RemovePrefix(prefix)
			}
		}
	}
	for _, prefix := range tunPrefixes {
		builder.RemovePrefix(prefix.Masked())
	}
	return builder.IPSet()
}

func prefixMatchesFamily(family int, prefix netip.Prefix) bool {
	return (family == unix.AF_INET) == prefix.Addr().Is4()
}

func unspecifiedPrefix(family int) netip.Prefix {
	if family == unix.AF_INET {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
}

func intersectPrefix(set *netipx.IPSet, prefix netip.Prefix) (*netipx.IPSet, error) {
	var prefixBuilder netipx.IPSetBuilder
	prefixBuilder.AddPrefix(prefix)
	prefixSet, err := prefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	var builder netipx.IPSetBuilder
	builder.AddSet(set)
	builder.Intersect(prefixSet)
	return builder.IPSet()
}

func routeDestination(family int, destination *net.IPNet) netip.Prefix {
	if destination == nil {
		return unspecifiedPrefix(family)
	}
	prefix, valid := netipx.FromStdIPNet(destination)
	if !valid {
		return netip.Prefix{}
	}
	return prefix
}
