//go:build !with_gvisor

package tun

import (
	"github.com/sagernet/sing/common/buf"
)

type DirectRouteDestination interface {
	DirectRouteAction
	WritePacket(packet *buf.Buffer) error
}
