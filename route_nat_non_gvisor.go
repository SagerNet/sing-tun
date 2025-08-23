//go:build !with_gvisor

package tun

import (
	"github.com/sagernet/sing/common/buf"
)

type DirectRouteDestination interface {
	WritePacket(packet *buf.Buffer) error
	Close() error
}
