package tun

import (
	"net/netip"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

type DirectRouteSession struct {
	// IPVersion uint8
	// Network     uint8
	Source      netip.Addr
	Destination netip.Addr
}

type RouteMapping struct {
	status freelru.Cache[DirectRouteSession, DirectRouteDestination]
}

func NewRouteMapping(timeout time.Duration) *RouteMapping {
	status := common.Must1(freelru.NewSharded[DirectRouteSession, DirectRouteDestination](1024, maphash.NewHasher[DirectRouteSession]().Hash32))
	status.SetOnEvict(func(session DirectRouteSession, action DirectRouteDestination) {
		action.Close()
	})
	status.SetLifetime(timeout)
	return &RouteMapping{status}
}

func (m *RouteMapping) Lookup(session DirectRouteSession, constructor func() (DirectRouteDestination, error)) (DirectRouteDestination, error) {
	var (
		created DirectRouteDestination
		err     error
	)
	action, _, ok := m.status.GetAndRefreshOrAdd(session, func() (DirectRouteDestination, bool) {
		created, err = constructor()
		return created, err != nil
	})
	if !ok {
		return created, err
	}
	return action, nil
}
