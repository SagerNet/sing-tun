package tun

import (
	"context"
	"net/netip"

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

type StackOptions struct {
	Context                context.Context
	Tun                    Tun
	Name                   string
	MTU                    uint32
	Inet4Address           []netip.Prefix
	Inet6Address           []netip.Prefix
	EndpointIndependentNat bool
	UDPTimeout             int64
	Handler                Handler
}

func NewStack(
	stack string,
	options StackOptions,
) (Stack, error) {
	switch stack {
	case "gvisor", "":
		return NewGVisor(options)
	case "system":
		return NewSystem(options)
	case "lwip":
		return NewLWIP(options)
	default:
		return nil, E.New("unknown stack: ", stack)
	}
}
