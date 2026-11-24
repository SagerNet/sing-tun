package tun

import (
	"context"
	"net/netip"
	"runtime"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	DefaultAutoRedirectInputMark  = 0x04000000
	DefaultAutoRedirectOutputMark = 0x08000000
	DefaultAutoRedirectResetMark  = 0x10000000
	DefaultAutoRedirectTProxyMark = 0x0c000000
	DefaultAutoRedirectNFQueue    = 100
)

type AutoRedirect interface {
	Start() error
	Close() error
	UpdateRouteAddressSet() error
}

type AutoRedirectHandler interface {
	JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) FlowVerdict
	NewDNSPacket(payload []byte, source M.Socksaddr, destination M.Socksaddr, writer N.PacketWriter)
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

// netd's Fwmark owns bits 0-19 (netId, explicitlySelected, protectedFromVpn,
// permission) and bit 20 (uidBillingDone, written by the bw_* chains); bits
// 29-30 are the vendor field and bit 31 is ingress_cpu_wakeup. The mark is also
// mirrored into the connmark, where netd's StrictController owns bits 24-25.
const androidReservedMarkMask = 0xE31FFFFF

func effectiveMark(value uint32, defaultValue uint32) uint32 {
	if value == 0 || runtime.GOOS == "android" && value&androidReservedMarkMask != 0 {
		return defaultValue
	}
	return value
}
