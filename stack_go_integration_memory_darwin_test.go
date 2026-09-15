//go:build darwin && !ios

package tun

import (
	"net/netip"
	"testing"
)

func kernelAddUnreachableRoute(t *testing.T, prefix netip.Prefix) bool {
	return false
}

// net.inet.udp.maxdgram caps a datagram at 9216 bytes.
const kernelMaxDatagram = 9216
