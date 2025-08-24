package tun

import (
	"net/netip"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

type DirectRouteDestination interface {
	WritePacket(packet *buf.Buffer) error
	Close() error
	IsClosed() bool
}

type DirectRouteSession struct {
	// IPVersion uint8
	// Network     uint8
	Source      netip.Addr
	Destination netip.Addr
}

type DirectRouteMapping struct {
	mapping freelru.Cache[DirectRouteSession, DirectRouteDestination]
}

func NewDirectRouteMapping(timeout time.Duration) *DirectRouteMapping {
	mapping := common.Must1(freelru.NewSharded[DirectRouteSession, DirectRouteDestination](1024, maphash.NewHasher[DirectRouteSession]().Hash32))
	mapping.SetHealthCheck(func(session DirectRouteSession, destination DirectRouteDestination) bool {
		return !destination.IsClosed()
	})
	mapping.SetOnEvict(func(session DirectRouteSession, action DirectRouteDestination) {
		action.Close()
	})
	mapping.SetLifetime(timeout)
	return &DirectRouteMapping{mapping}
}

func (m *DirectRouteMapping) Lookup(session DirectRouteSession, constructor func() (DirectRouteDestination, error)) (DirectRouteDestination, error) {
	var (
		created DirectRouteDestination
		err     error
	)
	action, _, ok := m.mapping.GetAndRefreshOrAdd(session, func() (DirectRouteDestination, bool) {
		created, err = constructor()
		return created, err == nil
	})
	if !ok {
		return nil, err
	}
	return action, nil
}
