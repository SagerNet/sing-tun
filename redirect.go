package tun

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

const (
	DefaultAutoRedirectInputMark  = 0x2023
	DefaultAutoRedirectOutputMark = 0x2024
	DefaultAutoRedirectResetMark  = 0x2025
	DefaultAutoRedirectTProxyMark = 0x2026
	DefaultAutoRedirectNFQueue    = 100

	DefaultAutoRedirectInputMarkAndroid  = 0x400000
	DefaultAutoRedirectOutputMarkAndroid = 0x200000
	DefaultAutoRedirectResetMarkAndroid  = 0x600000
	DefaultAutoRedirectTProxyMarkAndroid = 0x800000
)

type AutoRedirect interface {
	Start() error
	Close() error
	UpdateRouteAddressSet() error
}

type AutoRedirectHandler interface {
	JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) FlowVerdict
	N.TCPConnectionHandlerEx
}

type AutoRedirectOptions struct {
	TunOptions               *Options
	Context                  context.Context
	Handler                  AutoRedirectHandler
	Logger                   logger.Logger
	NetworkMonitor           NetworkUpdateMonitor
	InterfaceFinder          control.InterfaceFinder
	TableName                string
	DisableNFTables          bool
	CustomRedirectPort       func() int
	CustomRedirectListenerFD func() (int, error)
	RouteAddressSet          func() (include []netip.Prefix, exclude []netip.Prefix, err error)
	AndroidVPNService        bool
}
