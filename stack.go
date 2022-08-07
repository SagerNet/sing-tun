package tun

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
)

var (
	ErrGVisorNotIncluded = E.New("gVisor is disabled in current build, try build without -tags `no_gvisor`")
	ErrGVisorUnsupported = E.New("gVisor stack is unsupported on current platform")
	ErrLWIPNotIncluded   = E.New("LWIP stack is disabled in current build, try build with -tags `with_lwip` and CGO_ENABLED=1")
)

type Stack interface {
	Start() error
	Close() error
}

func NewStack(
	ctx context.Context,
	stack string,
	tun Tun,
	tunMtu uint32,
	endpointIndependentNat bool,
	udpTimeout int64,
	handler Handler,
) (Stack, error) {
	switch stack {
	case "gvisor", "":
		return NewGVisor(ctx, tun, tunMtu, endpointIndependentNat, udpTimeout, handler)
	case "lwip":
		return NewLWIP(ctx, tun, tunMtu, udpTimeout, handler)
	default:
		return nil, E.New("unknown stack: ", stack)
	}
}
