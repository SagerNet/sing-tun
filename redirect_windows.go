package tun

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/sagernet/sing-tun/internal/winredirect"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"

	"go4.org/netipx"
	"golang.org/x/sys/windows"
)

type autoRedirect struct {
	tunOptions             *Options
	ctx                    context.Context
	handler                Handler
	logger                 logger.Logger
	networkMonitor         NetworkUpdateMonitor
	networkListener        *list.Element[NetworkUpdateCallback]
	interfaceFinder        control.InterfaceFinder
	driverManager          *winredirect.Manager
	redirectServer         *redirectServer
	routeAddressSet        *[]*netipx.IPSet
	routeExcludeAddressSet *[]*netipx.IPSet

	enableIPv4 bool
	enableIPv6 bool

	localAddressMu sync.RWMutex
	localAddresses []netip.Prefix

	workerCount int
}

func NewAutoRedirect(options AutoRedirectOptions) (AutoRedirect, error) {
	r := &autoRedirect{
		tunOptions:             options.TunOptions,
		ctx:                    options.Context,
		handler:                options.Handler,
		logger:                 options.Logger,
		networkMonitor:         options.NetworkMonitor,
		interfaceFinder:        options.InterfaceFinder,
		routeAddressSet:        options.RouteAddressSet,
		routeExcludeAddressSet: options.RouteExcludeAddressSet,
		workerCount:            4,
	}
	return r, nil
}

func (r *autoRedirect) Start() error {
	r.enableIPv4 = len(r.tunOptions.Inet4Address) > 0
	r.enableIPv6 = len(r.tunOptions.Inet6Address) > 0
	if !r.enableIPv4 && !r.enableIPv6 {
		return E.New("no address configured")
	}

	manager, err := winredirect.NewManager()
	if err != nil {
		return E.Cause(err, "create driver manager")
	}
	r.driverManager = manager

	err = manager.Install()
	if err != nil {
		manager.Close()
		return E.Cause(err, "install driver")
	}

	err = manager.Start()
	if err != nil {
		manager.Close()
		return E.Cause(err, "start driver")
	}

	err = manager.OpenDevice()
	if err != nil {
		manager.Close()
		return E.Cause(err, "open driver device")
	}

	var listenAddr netip.Addr
	if r.enableIPv6 {
		listenAddr = netip.IPv6Unspecified()
	} else {
		listenAddr = netip.IPv4Unspecified()
	}
	server := newRedirectServerWindows(r.ctx, r.handler, r.logger, listenAddr)
	err = server.Start()
	if err != nil {
		manager.Close()
		return E.Cause(err, "start redirect server")
	}
	r.redirectServer = server

	redirectPort := M.AddrPortFromNet(server.listener.Addr()).Port()
	err = manager.SetConfig(&winredirect.Config{
		RedirectPort: redirectPort,
		ProxyPID:     uint32(os.Getpid()),
	})
	if err != nil {
		server.Close()
		manager.Close()
		return E.Cause(err, "set driver config")
	}

	err = manager.StartRedirect()
	if err != nil {
		server.Close()
		manager.Close()
		return E.Cause(err, "start redirect")
	}

	r.updateLocalAddresses()
	if r.networkMonitor != nil {
		r.networkListener = r.networkMonitor.RegisterCallback(func() {
			r.updateLocalAddresses()
		})
	}

	for i := 0; i < r.workerCount; i++ {
		go r.preMatchWorker()
	}

	return nil
}

func (r *autoRedirect) Close() error {
	if r.networkMonitor != nil && r.networkListener != nil {
		r.networkMonitor.UnregisterCallback(r.networkListener)
	}
	return common.Close(
		common.PtrOrNil(r.redirectServer),
		common.PtrOrNil(r.driverManager),
	)
}

func (r *autoRedirect) UpdateRouteAddressSet() {
	// Dynamic route address sets are updated via pointer indirection.
	// The IPSet pointers are swapped atomically by the caller.
	// No driver communication needed — all filtering is in Go.
}

func (r *autoRedirect) preMatchWorker() {
	for {
		conn, err := r.driverManager.GetPendingConn()
		if err != nil {
			return
		}
		verdict := r.evaluateConnection(conn)
		r.driverManager.SetVerdict(&winredirect.Verdict{
			ConnID:  conn.ConnID,
			Verdict: verdict,
		})
	}
}

func (r *autoRedirect) evaluateConnection(conn *winredirect.PendingConn) uint32 {
	dst := pendingConnDst(conn)
	src := pendingConnSrc(conn)

	// 1. Loopback destinations
	if dst.Addr.IsLoopback() {
		return winredirect.VerdictBypass
	}

	// 2. Static route address whitelist (Inet4/6RouteAddress)
	if r.hasStaticRouteAddress() && !r.matchStaticRouteAddress(dst.Addr) {
		return winredirect.VerdictBypass
	}

	// 3. Static route address blacklist (Inet4/6RouteExcludeAddress)
	if r.matchStaticRouteExcludeAddress(dst.Addr) {
		return winredirect.VerdictBypass
	}

	// 4. DNS hijack: port 53 from local network → redirect to DNS server
	if !r.tunOptions.EXP_DisableDNSHijack && dst.Port == 53 {
		if r.isLocalAddress(src.Addr) {
			dnsServer := r.dnsServerForFamily(dst.Addr)
			if dnsServer.IsValid() {
				metadata := r.resolveMetadata(conn)
				r.redirectServer.connTable.StoreDNS(src, dst, M.SocksaddrFrom(dnsServer, 53), metadata)
				return winredirect.VerdictRedirect
			}
		}
	}

	// 5. Local address exclusion
	if r.isLocalAddress(dst.Addr) {
		return winredirect.VerdictBypass
	}

	// 6. Dynamic route address set whitelist
	if r.hasDynamicRouteAddressSet() && !r.matchDynamicRouteAddressSet(dst.Addr) {
		return winredirect.VerdictBypass
	}

	// 7. Dynamic route address set blacklist
	if r.matchDynamicRouteExcludeAddressSet(dst.Addr) {
		return winredirect.VerdictBypass
	}

	// 8. Strict route: reject disabled address family
	if r.tunOptions.StrictRoute && r.isDisabledFamily(dst.Addr) {
		return winredirect.VerdictDrop
	}

	// 9. Resolve PID → process path
	metadata := r.resolveMetadata(conn)

	// 10. PrepareConnection (NFQUEUE equivalent)
	_, err := r.handler.PrepareConnection("tcp", src, dst, nil, 0)
	if errors.Is(err, ErrBypass) {
		return winredirect.VerdictBypass
	}
	if errors.Is(err, ErrDrop) || errors.Is(err, ErrReset) || err != nil {
		return winredirect.VerdictDrop
	}

	// 11. Store metadata for redirect server
	r.redirectServer.connTable.Store(src, dst, metadata)

	return winredirect.VerdictRedirect
}

func (r *autoRedirect) resolveMetadata(conn *winredirect.PendingConn) *AutoRedirectMetadata {
	processPath, _ := queryFullProcessImageName(conn.ProcessID)
	return &AutoRedirectMetadata{
		ProcessID:   conn.ProcessID,
		ProcessPath: processPath,
		UserId:      -1,
	}
}

func (r *autoRedirect) updateLocalAddresses() {
	if r.interfaceFinder == nil {
		return
	}
	r.interfaceFinder.Update()
	newLocalAddresses := common.FlatMap(r.interfaceFinder.Interfaces(), func(it control.Interface) []netip.Prefix {
		return common.Filter(it.Addresses, func(prefix netip.Prefix) bool {
			return it.Name == "Loopback Pseudo-Interface 1" || prefix.Addr().IsGlobalUnicast()
		})
	})
	r.localAddressMu.Lock()
	defer r.localAddressMu.Unlock()
	if slices.Equal(newLocalAddresses, r.localAddresses) {
		return
	}
	r.localAddresses = newLocalAddresses
	if r.logger != nil {
		r.logger.Debug("updating local address set to [", strings.Join(common.Map(newLocalAddresses, func(it netip.Prefix) string {
			return it.String()
		}), ", ")+"]")
	}
}

func (r *autoRedirect) isLocalAddress(addr netip.Addr) bool {
	r.localAddressMu.RLock()
	defer r.localAddressMu.RUnlock()
	for _, prefix := range r.localAddresses {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (r *autoRedirect) hasStaticRouteAddress() bool {
	return len(r.tunOptions.Inet4RouteAddress) > 0 || len(r.tunOptions.Inet6RouteAddress) > 0
}

func (r *autoRedirect) matchStaticRouteAddress(addr netip.Addr) bool {
	var prefixes []netip.Prefix
	if addr.Is4() {
		prefixes = r.tunOptions.Inet4RouteAddress
	} else {
		prefixes = r.tunOptions.Inet6RouteAddress
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (r *autoRedirect) matchStaticRouteExcludeAddress(addr netip.Addr) bool {
	var prefixes []netip.Prefix
	if addr.Is4() {
		prefixes = r.tunOptions.Inet4RouteExcludeAddress
	} else {
		prefixes = r.tunOptions.Inet6RouteExcludeAddress
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (r *autoRedirect) hasDynamicRouteAddressSet() bool {
	if r.routeAddressSet == nil {
		return false
	}
	sets := *r.routeAddressSet
	return len(sets) > 0
}

func (r *autoRedirect) matchDynamicRouteAddressSet(addr netip.Addr) bool {
	if r.routeAddressSet == nil {
		return true
	}
	for _, set := range *r.routeAddressSet {
		if set.Contains(addr) {
			return true
		}
	}
	return false
}

func (r *autoRedirect) matchDynamicRouteExcludeAddressSet(addr netip.Addr) bool {
	if r.routeExcludeAddressSet == nil {
		return false
	}
	for _, set := range *r.routeExcludeAddressSet {
		if set.Contains(addr) {
			return true
		}
	}
	return false
}

func (r *autoRedirect) isDisabledFamily(addr netip.Addr) bool {
	if addr.Is4() {
		return !r.enableIPv4
	}
	return !r.enableIPv6
}

func (r *autoRedirect) dnsServerForFamily(addr netip.Addr) netip.Addr {
	isV4 := addr.Is4()
	dnsServer := common.Find(r.tunOptions.DNSServers, func(it netip.Addr) bool {
		return it.Is4() == isV4
	})
	if dnsServer.IsValid() {
		return dnsServer
	}
	if isV4 {
		if len(r.tunOptions.Inet4Address) > 0 && HasNextAddress(r.tunOptions.Inet4Address[0], 1) {
			return r.tunOptions.Inet4Address[0].Addr().Next()
		}
	} else {
		if len(r.tunOptions.Inet6Address) > 0 && HasNextAddress(r.tunOptions.Inet6Address[0], 1) {
			return r.tunOptions.Inet6Address[0].Addr().Next()
		}
	}
	return netip.Addr{}
}

func pendingConnSrc(conn *winredirect.PendingConn) M.Socksaddr {
	return M.SocksaddrFrom(pendingAddr(conn.AddressFamily, conn.SrcAddr), conn.SrcPort)
}

func pendingConnDst(conn *winredirect.PendingConn) M.Socksaddr {
	return M.SocksaddrFrom(pendingAddr(conn.AddressFamily, conn.DstAddr), conn.DstPort)
}

func pendingAddr(af uint8, raw [16]byte) netip.Addr {
	if af == 2 { // AF_INET
		return netip.AddrFrom4([4]byte(raw[:4]))
	}
	return netip.AddrFrom16(raw)
}

func queryFullProcessImageName(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	var buf [windows.MAX_PATH]uint16
	n := uint32(len(buf))
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &n)
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}
