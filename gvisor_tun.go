//go:build !(no_gvisor || !(linux || windows || darwin))

package tun

import "gvisor.dev/gvisor/pkg/tcpip/stack"

type GVisorTun interface {
	Tun
	NewEndpoint() (stack.LinkEndpoint, error)
}
