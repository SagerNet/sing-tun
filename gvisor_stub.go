//go:build no_gvisor && (linux || windows || darwin)

package tun

import "context"

func NewGVisor(
	ctx context.Context,
	tun Tun,
	tunMtu uint32,
	endpointIndependentNat bool,
	endpointIndependentNatTimeout int64,
	handler Handler,
) (Stack, error) {
	return nil, ErrGVisorNotIncluded
}
