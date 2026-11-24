package tun

import (
	"context"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"

	"go4.org/netipx"
)

const (
	DefaultAutoRedirectInputMark  = 0x04000000
	DefaultAutoRedirectOutputMark = 0x08000000
	DefaultAutoRedirectResetMark  = 0x10000000
	DefaultAutoRedirectNFQueue    = 100
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
