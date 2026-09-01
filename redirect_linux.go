package tun

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"

	"github.com/sagernet/netlink"
	"github.com/sagernet/nftables"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/unix"
)

type autoRedirect struct {
	tunOptions                   *Options
	ctx                          context.Context
	handler                      AutoRedirectHandler
	logger                       logger.Logger
	tableName                    string
	networkMonitor               NetworkUpdateMonitor
	ownedNetworkMonitor          bool
	networkListener              *list.Element[NetworkUpdateCallback]
	interfaceListener            *list.Element[DefaultInterfaceUpdateCallback]
	interfaceFinder              control.InterfaceFinder
	localAddresses               []netip.Prefix
	customRedirectPortFunc       func() int
	customRedirectPort           int
	customRedirectListenerFD     func() (int, error)
	customRedirectTransparent    bool
	routeAddressSet              func() ([]netip.Prefix, []netip.Prefix, error)
	bypassRouteTableIndex        int
	bypassRouteAccess            sync.Mutex
	bypassRouteActive            bool
	bypassIncludeAddresses       []netip.Prefix
	bypassExcludeAddresses       []netip.Prefix
	redirectServer               *RedirectServer
	enableIPv4                   bool
	enableIPv6                   bool
	iptablesPath                 string
	ip6tablesPath                string
	useNFTables                  bool
	androidVPNService            bool
	nfqueueHandler               *nfqueueHandler
	iptablesAccess               sync.Mutex
	iptablesLocalChains          []iptablesLocalChain
	redirectRouteTableIndex      int
	tproxyRouteTableIndex        int
	redirectRouteAccess          sync.Mutex
	redirectRoutesActive         bool
	androidVPNServiceRuleAccess  sync.Mutex
	androidVPNServiceRules       []*netlink.Rule
	androidVPNServiceRulesActive bool
	dockerFirewallMonitor        *nftables.Monitor
	dockerFirewallDone           chan struct{}
}

func NewAutoRedirect(options AutoRedirectOptions) (AutoRedirect, error) {
	r := &autoRedirect{
		tunOptions:               options.TunOptions,
		ctx:                      options.Context,
		handler:                  options.Handler,
		logger:                   options.Logger,
		networkMonitor:           options.NetworkMonitor,
		interfaceFinder:          options.InterfaceFinder,
		tableName:                options.TableName,
		useNFTables:              runtime.GOOS != "android" && !options.DisableNFTables,
		androidVPNService:        options.AndroidVPNService,
		customRedirectPortFunc:   options.CustomRedirectPort,
		customRedirectListenerFD: options.CustomRedirectListenerFD,
		routeAddressSet:          options.RouteAddressSet,
	}
	if options.TunOptions.NetNs != "" {
		r.interfaceFinder = &networkNamespaceInterfaceFinder{control.NewDefaultInterfaceFinder(), options.TunOptions}
	}
	for _, mark := range []struct {
		field               *uint32
		defaultValue        uint32
		androidDefaultValue uint32
	}{
		{&r.tunOptions.AutoRedirectInputMark, DefaultAutoRedirectInputMark, DefaultAutoRedirectInputMarkAndroid},
		{&r.tunOptions.AutoRedirectOutputMark, DefaultAutoRedirectOutputMark, DefaultAutoRedirectOutputMarkAndroid},
		{&r.tunOptions.AutoRedirectResetMark, DefaultAutoRedirectResetMark, DefaultAutoRedirectResetMarkAndroid},
		{&r.tunOptions.AutoRedirectTProxyMark, DefaultAutoRedirectTProxyMark, DefaultAutoRedirectTProxyMarkAndroid},
	} {
		value := effectiveMark(*mark.field, mark.defaultValue, mark.androidDefaultValue)
		if *mark.field != 0 && *mark.field != value {
			r.logger.Warn("configured mark ", iptablesHex(*mark.field), " overlaps the fwmark bits reserved by Android and is replaced by ", iptablesHex(value))
		}
		*mark.field = value
	}
	return r, nil
}

func (r *autoRedirect) Start() error {
	err := r.initializeBackend()
	if err != nil {
		return err
	}
	err = r.startRedirectServer()
	if err != nil {
		return err
	}
	err = r.startNFQueue()
	if err != nil {
		_ = r.Close()
		return E.Cause(err, "start nfqueue")
	}
	if r.useNFTables {
		if r.tunOptions.NetNs != "" {
			var monitor NetworkUpdateMonitor
			monitor, err = NewNetworkUpdateMonitor(r.logger)
			if err != nil {
				_ = r.Close()
				return E.Cause(err, "create netns network monitor")
			}
			err = runInNetworkNamespace(r.tunOptions.NetNs, monitor.Start)
			if err != nil {
				_ = monitor.Close()
				_ = r.Close()
				return E.Cause(err, "start netns network monitor")
			}
			r.networkMonitor = monitor
			r.ownedNetworkMonitor = true
		}
		err = runInNetworkNamespace(r.tunOptions.NetNs, func() error {
			r.cleanupNFTables()
			setupErr := r.setupNFTables()
			if setupErr != nil {
				return E.Cause(setupErr, "setup nftables")
			}
			if r.tunOptions.AutoRedirectMarkMode {
				setupErr = r.setupRedirectRoutes()
				if setupErr != nil {
					return E.Cause(setupErr, "setup redirect routes")
				}
			}
			return nil
		})
		if err != nil {
			_ = r.Close()
			return err
		}
		return nil
	}
	r.cleanupIPTables()
	err = r.setupRedirectRoutes()
	if err != nil {
		_ = r.Close()
		return E.Cause(err, "setup redirect routes")
	}
	if r.androidVPNService {
		err = r.setupAndroidVPNServiceRules()
		if err != nil {
			_ = r.Close()
			return E.Cause(err, "setup android vpn service rules")
		}
		r.setupBypassRoute()
	}
	err = r.setupIPTables()
	if err != nil {
		_ = r.Close()
		return E.Cause(err, "setup iptables")
	}
	r.registerNetworkCallback(func() {
		updateErr := r.updateIPTablesNetwork()
		if updateErr != nil {
			r.logger.Error(updateErr)
		}
	})
	return nil
}

func (r *autoRedirect) registerNetworkCallback(callback NetworkUpdateCallback) {
	if r.networkMonitor != nil {
		r.networkListener = r.networkMonitor.RegisterCallback(callback)
		return
	}
	if r.tunOptions.InterfaceMonitor != nil {
		r.interfaceListener = r.tunOptions.InterfaceMonitor.RegisterCallback(func(defaultInterface *control.Interface, flags int) {
			callback()
		})
		return
	}
	r.logger.Warn("no network monitor available, address and route updates are disabled")
}

func (r *autoRedirect) unregisterNetworkCallback() {
	if r.networkListener != nil {
		r.networkMonitor.UnregisterCallback(r.networkListener)
		r.networkListener = nil
	}
	if r.interfaceListener != nil {
		r.tunOptions.InterfaceMonitor.UnregisterCallback(r.interfaceListener)
		r.interfaceListener = nil
	}
}

func (r *autoRedirect) initializeBackend() error {
	var err error
	// iptables-nft refuses DROP in the nat table, where the MPTCP fallback drop belongs.
	if r.tunOptions.ExcludeMPTCP && !r.useNFTables {
		return E.New("exclude_mptcp requires nftables")
	}
	if runtime.GOOS == "android" {
		if os.Getuid() != 0 {
			return E.New("auto_redirect requires root")
		}
		if len(r.tunOptions.Inet4Address) > 0 {
			r.iptablesPath, err = findIPTablesBinary(false)
			if err != nil {
				return E.Cause(err, "iptables is required")
			}
			r.enableIPv4 = true
		}
		if len(r.tunOptions.Inet6Address) > 0 {
			r.ip6tablesPath, err = findIPTablesBinary(true)
			if err != nil {
				return E.Cause(err, "ip6tables is required")
			}
			r.enableIPv6 = true
		}
		return nil
	}
	if r.tunOptions.NetNs != "" && !r.useNFTables {
		return E.New("auto_redirect in network namespace requires nftables")
	}
	if r.useNFTables {
		err = runInNetworkNamespace(r.tunOptions.NetNs, r.initializeNFTables)
		if err != nil {
			return E.Cause(err, "missing nftables support")
		}
	}
	if len(r.tunOptions.Inet4Address) > 0 {
		r.enableIPv4 = true
		if !r.useNFTables {
			r.iptablesPath, err = exec.LookPath("iptables")
			if err != nil {
				return E.Cause(err, "iptables is required")
			}
			err = exec.Command(r.iptablesPath, "-w", "-t", iptablesTableNAT, "-S").Run()
			if err != nil {
				return E.Cause(err, "iptables nat table is required")
			}
		}
	}
	if len(r.tunOptions.Inet6Address) > 0 {
		r.enableIPv6 = true
		if !r.useNFTables {
			r.ip6tablesPath, err = exec.LookPath("ip6tables")
			if err != nil {
				return E.Cause(err, "ip6tables is required")
			}
		}
	}
	return nil
}

func (r *autoRedirect) tproxyEnabled() bool {
	return !r.useNFTables && r.enableIPv6 && (!r.androidVPNService || r.customRedirectTransparent)
}

func (r *autoRedirect) prepareCustomTransparentListener() error {
	fd, err := r.customRedirectListenerFD()
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	err = syscall.SetsockoptInt(fd, syscall.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	if err != nil {
		return E.Cause(err, "set IPV6_TRANSPARENT")
	}
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(r.tunOptions.AutoRedirectOutputMark))
	if err != nil {
		return E.Cause(err, "set SO_MARK")
	}
	return nil
}

func (r *autoRedirect) startRedirectServer() error {
	if r.customRedirectPortFunc != nil {
		r.customRedirectPort = r.customRedirectPortFunc()
	}
	if r.customRedirectPort > 0 {
		if !r.useNFTables && r.enableIPv6 && r.androidVPNService && r.customRedirectListenerFD != nil {
			err := r.prepareCustomTransparentListener()
			if err != nil {
				r.logger.Warn("IPv6 TCP falls back to the tun stack: prepare transparent listener: ", err)
			} else {
				r.customRedirectTransparent = true
			}
		}
		return nil
	}
	var listenAddress netip.Addr
	if r.enableIPv6 {
		listenAddress = netip.IPv6Unspecified()
	} else {
		listenAddress = netip.IPv4Unspecified()
	}
	server := NewRedirectServer(r.ctx, r.handler, r.logger, listenAddress)
	if r.tproxyEnabled() {
		server.transparent = true
		server.listenMark = r.tunOptions.AutoRedirectOutputMark
	}
	err := runInNetworkNamespace(r.tunOptions.NetNs, server.Start)
	if err != nil {
		return E.Cause(err, "start redirect server")
	}
	r.redirectServer = server
	return nil
}

const tcpOptionMultipathTCP = 30

func (r *autoRedirect) startNFQueue() error {
	var markMask uint32
	if !r.useNFTables {
		markMask = r.effectiveMarkMask()
	}
	var tproxyMark uint32
	if r.tproxyEnabled() {
		tproxyMark = r.tunOptions.AutoRedirectTProxyMark
	}
	handler := &nfqueueHandler{
		handler:    r.handler,
		logger:     r.logger,
		queue:      r.effectiveNFQueue(),
		inputMark:  r.tunOptions.AutoRedirectInputMark,
		outputMark: r.tunOptions.AutoRedirectOutputMark,
		resetMark:  r.tunOptions.AutoRedirectResetMark,
		tproxyMark: tproxyMark,
		markMask:   markMask,
		// A queue verdict leaves the whole iptables mangle hook, while nftables base chains
		// continue on NF_ACCEPT.
		repeatOnAccept: !r.useNFTables,
	}
	err := runInNetworkNamespace(r.tunOptions.NetNs, handler.Start)
	if err != nil {
		return err
	}
	r.nfqueueHandler = handler
	return nil
}

func (r *autoRedirect) updateIPTablesNetwork() error {
	r.iptablesAccess.Lock()
	defer r.iptablesAccess.Unlock()
	err := r.updateIPTablesLocalAddresses()
	if err != nil {
		err = E.Cause(err, "update local address chains")
	}
	routeErr := r.updateRedirectRoutes()
	if routeErr != nil {
		routeErr = E.Cause(routeErr, "update redirect routes")
	}
	var vpnServiceErr error
	var bypassErr error
	if r.androidVPNService {
		vpnServiceErr = r.updateAndroidVPNServiceRules()
		if vpnServiceErr != nil {
			vpnServiceErr = E.Cause(vpnServiceErr, "update android vpn service rules")
		}
		bypassErr = r.updateBypassRoute()
		if bypassErr != nil {
			bypassErr = E.Cause(bypassErr, "update bypass route")
		}
	}
	return E.Errors(err, routeErr, vpnServiceErr, bypassErr)
}

func (r *autoRedirect) Close() error {
	if r.useNFTables {
		_ = runInNetworkNamespace(r.tunOptions.NetNs, func() error {
			r.cleanupNFTables()
			r.cleanupRedirectRoutes()
			return nil
		})
		if r.ownedNetworkMonitor {
			_ = r.networkMonitor.Close()
			r.ownedNetworkMonitor = false
		}
	} else {
		r.unregisterNetworkCallback()
		r.cleanupIPTables()
		r.cleanupRedirectRoutes()
		if r.androidVPNService {
			r.cleanupBypassRoute()
			r.cleanupAndroidVPNServiceRules()
		}
	}
	if r.nfqueueHandler != nil {
		r.nfqueueHandler.Close()
		r.nfqueueHandler = nil
	}
	if r.redirectServer != nil {
		err := r.redirectServer.Close()
		r.redirectServer = nil
		return err
	}
	return nil
}

func (r *autoRedirect) initializeNFTables() error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	_, err = nft.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return err
	}
	r.useNFTables = true
	return nil
}

func (r *autoRedirect) redirectPort() uint16 {
	if r.customRedirectPort > 0 {
		return uint16(r.customRedirectPort)
	}
	return r.redirectServer.Port()
}

// netd's Fwmark owns bits 0-19 (netId, explicitlySelected, protectedFromVpn,
// permission) and bit 20 (uidBillingDone, written by the bw_* chains); bits
// 29-30 are the vendor field and bit 31 is ingress_cpu_wakeup. The mark is also
// mirrored into the connmark, where netd's StrictController owns bits 24-25.
const androidReservedMarkMask = 0xE31FFFFF

// netd (server/RouteController.cpp) identifies a network's route table as
// ifindex + ROUTE_TABLE_OFFSET_FROM_INDEX, selects VPN traffic with the
// secure (fwmark 0x0/0x20000) and bypassable (fwmark 0x0/0x30000) uid range
// rules, the local network with a rule matching fwmark 0x0/0x10000, and the
// default network with a rule matching fwmark 0x0/0xffff without a uid range.
const (
	androidRouteTableOffsetFromIndex = 1000
	androidExplicitSelectMask        = 0x10000
	androidSecureVPNMask             = 0x20000
	androidBypassableVPNMask         = 0x30000
	androidNetIDMask                 = 0xFFFF
)

func (r *autoRedirect) effectiveMarkMask() uint32 {
	return r.tunOptions.AutoRedirectInputMark | r.tunOptions.AutoRedirectOutputMark | r.tunOptions.AutoRedirectResetMark | r.tunOptions.AutoRedirectTProxyMark
}

func effectiveMark(value uint32, defaultValue uint32, androidDefaultValue uint32) uint32 {
	if runtime.GOOS == "android" {
		if value != 0 && value&androidReservedMarkMask == 0 {
			return value
		}
		return androidDefaultValue
	}
	if value != 0 {
		return value
	}
	return defaultValue
}

func (r *autoRedirect) effectiveNFQueue() uint16 {
	if r.tunOptions.AutoRedirectNFQueue != 0 {
		return r.tunOptions.AutoRedirectNFQueue
	}
	return DefaultAutoRedirectNFQueue
}

func (r *autoRedirect) shouldSkipOutputChain() bool {
	return len(r.tunOptions.IncludeInterface) > 0 && !common.Contains(r.tunOptions.IncludeInterface, "lo") || common.Contains(r.tunOptions.ExcludeInterface, "lo")
}
