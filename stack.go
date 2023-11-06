package tun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
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
	Logger                 logger.Logger
	ForwarderBindInterface bool
	InterfaceFinder        control.InterfaceFinder
}

func NewStack(
	stack string,
	options StackOptions,
) (Stack, error) {
	switch stack {
	case "":
		if WithGVisor {
			return NewMixed(options)
		} else {
			return NewSystem(options)
		}
	case "gvisor":
		return NewGVisor(options)
	case "mixed":
		return NewMixed(options)
	case "system":
		return NewSystem(options)
	case "lwip":
		return NewLWIP(options)
	default:
		return nil, E.New("unknown stack: ", stack)
	}
}

func BroadcastAddr(inet4Address []netip.Prefix) netip.Addr {
	if len(inet4Address) == 0 {
		return netip.Addr{}
	}
	prefix := inet4Address[0]
	var broadcastAddr [4]byte
	binary.BigEndian.PutUint32(broadcastAddr[:], binary.BigEndian.Uint32(prefix.Masked().Addr().AsSlice())|^binary.BigEndian.Uint32(net.CIDRMask(prefix.Bits(), 32)))
	return netip.AddrFrom4(broadcastAddr)
}
