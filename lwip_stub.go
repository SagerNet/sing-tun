//go:build !with_lwip

package tun

import "context"

func NewLWIP(
	ctx context.Context,
	tun Tun,
	tunMtu uint32,
	udpTimeout int64,
	handler Handler,
) (Stack, error) {
	return nil, ErrLWIPNotIncluded
}
