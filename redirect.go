package tun

import (
	"context"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"

	"go4.org/netipx"
)

const (
	DefaultAutoRedirectInputMark  = 0x2023
	DefaultAutoRedirectOutputMark = 0x2024
	DefaultAutoRedirectResetMark  = 0x2025
	DefaultAutoRedirectNFQueue    = 100

	// AutoRedirectMarkMask defines which bits of the 32-bit mark field are
	// reserved for auto_redirect loop prevention. Bits outside this mask
	// (the upper 16) are available for routing_mark / WAN selection.
	AutoRedirectMarkMask = 0x0000FFFF
)

type AutoRedirect interface {
	Start() error
	Close() error
	UpdateRouteAddressSet()
}

type AutoRedirectOptions struct {
	TunOptions             *Options
	Context                context.Context
	Handler                Handler
	Logger                 logger.Logger
	NetworkMonitor         NetworkUpdateMonitor
	InterfaceFinder        control.InterfaceFinder
	TableName              string
	DisableNFTables        bool
	CustomRedirectPort     func() int
	RouteAddressSet        *[]*netipx.IPSet
	RouteExcludeAddressSet *[]*netipx.IPSet
}
