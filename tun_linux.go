package tun

import (
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/shell"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/unix"
)

var _ LinuxTUN = (*NativeTun)(nil)

type NativeTun struct {
	tunFd             int
	tunFile           *os.File
	tunWriter         N.VectorisedWriter
	interfaceCallback *list.Element[DefaultInterfaceUpdateCallback]
	options           Options
	ruleIndex6        []int
	gsoEnabled        bool
	gsoBuffer         []byte
	gsoToWrite        []int
	gsoReadAccess     sync.Mutex
	tcpGROAccess      sync.Mutex
	tcp4GROTable      *tcpGROTable
	tcp6GROTable      *tcpGROTable
	txChecksumOffload bool
}

func New(options Options) (Tun, error) {
	var nativeTun *NativeTun
	if options.FileDescriptor == 0 {
		tunFd, err := open(options.Name, options.GSO)
		if err != nil {
			return nil, err
		}
		tunLink, err := netlink.LinkByName(options.Name)
		if err != nil {
			return nil, E.Errors(err, unix.Close(tunFd))
		}
		nativeTun = &NativeTun{
			tunFd:   tunFd,
			tunFile: os.NewFile(uintptr(tunFd), "tun"),
			options: options,
		}
		err = nativeTun.configure(tunLink)
		if err != nil {
			return nil, E.Errors(err, unix.Close(tunFd))
		}
	} else {
		nativeTun = &NativeTun{
			tunFd:   options.FileDescriptor,
			tunFile: os.NewFile(uintptr(options.FileDescriptor), "tun"),
			options: options,
		}
	}
	var ok bool
	nativeTun.tunWriter, ok = bufio.CreateVectorisedWriter(nativeTun.tunFile)
	if !ok {
		panic("create vectorised writer")
	}
	return nativeTun, nil
}

func (t *NativeTun) FrontHeadroom() int {
	if t.gsoEnabled {
		return virtioNetHdrLen
	}
	return 0
}

func (t *NativeTun) Read(p []byte) (n int, err error) {
	if t.gsoEnabled {
		n, err = t.tunFile.Read(t.gsoBuffer)
		if err != nil {
			return
		}
		var sizes [1]int
		n, err = handleVirtioRead(t.gsoBuffer[:n], [][]byte{p}, sizes[:], 0)
		if err != nil {
			return
		}
		if n == 0 {
			return
		}
		n = sizes[0]
		return
	} else {
		return t.tunFile.Read(p)
	}
}

func (t *NativeTun) Write(p []byte) (n int, err error) {
	if t.gsoEnabled {
		err = t.BatchWrite([][]byte{p}, virtioNetHdrLen)
		if err != nil {
			return
		}
		n = len(p)
		return
	}
	return t.tunFile.Write(p)
}

func (t *NativeTun) WriteVectorised(buffers []*buf.Buffer) error {
	if t.gsoEnabled {
		n := buf.LenMulti(buffers)
		buffer := buf.NewSize(virtioNetHdrLen + n)
		buffer.Truncate(virtioNetHdrLen)
		buf.CopyMulti(buffer.Extend(n), buffers)
		_, err := t.tunFile.Write(buffer.Bytes())
		buffer.Release()
		return err
	} else {
		return t.tunWriter.WriteVectorised(buffers)
	}
}

func (t *NativeTun) BatchSize() int {
	if !t.gsoEnabled {
		return 1
	}
	/* // Not works on some devices: https://github.com/SagerNet/sing-box/issues/1605
	batchSize := int(gsoMaxSize/t.options.MTU) * 2
	if batchSize > idealBatchSize {
		batchSize = idealBatchSize
	}
	return batchSize*/
	return idealBatchSize
}

func (t *NativeTun) BatchRead(buffers [][]byte, offset int, readN []int) (n int, err error) {
	t.gsoReadAccess.Lock()
	defer t.gsoReadAccess.Unlock()
	n, err = t.tunFile.Read(t.gsoBuffer)
	if err != nil {
		return
	}
	return handleVirtioRead(t.gsoBuffer[:n], buffers, readN, offset)
}

func (t *NativeTun) BatchWrite(buffers [][]byte, offset int) error {
	t.tcpGROAccess.Lock()
	defer func() {
		t.tcp4GROTable.reset()
		t.tcp6GROTable.reset()
		t.tcpGROAccess.Unlock()
	}()
	t.gsoToWrite = t.gsoToWrite[:0]
	err := handleGRO(buffers, offset, t.tcp4GROTable, t.tcp6GROTable, &t.gsoToWrite)
	if err != nil {
		return err
	}
	offset -= virtioNetHdrLen
	for _, bufferIndex := range t.gsoToWrite {
		_, err = t.tunFile.Write(buffers[bufferIndex][offset:])
		if err != nil {
			return err
		}
	}
	return nil
}

var controlPath string

func init() {
	const defaultTunPath = "/dev/net/tun"
	const androidTunPath = "/dev/tun"
	if rw.FileExists(androidTunPath) {
		controlPath = androidTunPath
	} else {
		controlPath = defaultTunPath
	}
}

func open(name string, vnetHdr bool) (int, error) {
	fd, err := unix.Open(controlPath, unix.O_RDWR, 0)
	if err != nil {
		return -1, err
	}

	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}

	copy(ifr.name[:], name)
	ifr.flags = unix.IFF_TUN | unix.IFF_NO_PI
	if vnetHdr {
		ifr.flags |= unix.IFF_VNET_HDR
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		unix.Close(fd)
		return -1, errno
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return -1, err
	}

	return fd, nil
}

func (t *NativeTun) configure(tunLink netlink.Link) error {
	err := netlink.LinkSetMTU(tunLink, int(t.options.MTU))
	if err == unix.EPERM {
		// unprivileged
		return nil
	} else if err != nil {
		return err
	}

	if len(t.options.Inet4Address) > 0 {
		for _, address := range t.options.Inet4Address {
			addr4, _ := netlink.ParseAddr(address.String())
			err = netlink.AddrAdd(tunLink, addr4)
			if err != nil {
				return err
			}
		}
	}
	if len(t.options.Inet6Address) > 0 {
		for _, address := range t.options.Inet6Address {
			addr6, _ := netlink.ParseAddr(address.String())
			err = netlink.AddrAdd(tunLink, addr6)
			if err != nil {
				return err
			}
		}
	}

	if t.options.GSO {
		var vnetHdrEnabled bool
		vnetHdrEnabled, err = checkVNETHDREnabled(t.tunFd, t.options.Name)
		if err != nil {
			return E.Cause(err, "enable offload: check IFF_VNET_HDR enabled")
		}
		if !vnetHdrEnabled {
			return E.Cause(err, "enable offload: IFF_VNET_HDR not enabled")
		}
		err = setTCPOffload(t.tunFd)
		if err != nil {
			return err
		}
		t.gsoEnabled = true
		t.gsoBuffer = make([]byte, virtioNetHdrLen+int(gsoMaxSize))
		t.tcp4GROTable = newTCPGROTable()
		t.tcp6GROTable = newTCPGROTable()
	}

	var rxChecksumOffload bool
	rxChecksumOffload, err = checkChecksumOffload(t.options.Name, unix.ETHTOOL_GRXCSUM)
	if err == nil && !rxChecksumOffload {
		_ = setChecksumOffload(t.options.Name, unix.ETHTOOL_SRXCSUM)
	}

	if t.options._TXChecksumOffload {
		var txChecksumOffload bool
		txChecksumOffload, err = checkChecksumOffload(t.options.Name, unix.ETHTOOL_GTXCSUM)
		if err != nil {
			return err
		}
		if err == nil && !txChecksumOffload {
			err = setChecksumOffload(t.options.Name, unix.ETHTOOL_STXCSUM)
			if err != nil {
				return err
			}
		}
		t.txChecksumOffload = true
	}

	err = netlink.LinkSetUp(tunLink)
	if err != nil {
		return err
	}

	if t.options.TableIndex == 0 {
		for {
			t.options.TableIndex = int(rand.Uint32())
			routeList, fErr := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: t.options.TableIndex}, netlink.RT_FILTER_TABLE)
			if len(routeList) == 0 || fErr != nil {
				break
			}
		}
	}

	err = t.setRoute(tunLink)
	if err != nil {
		_ = t.unsetRoute0(tunLink)
		return err
	}

	err = t.unsetRules()
	if err != nil {
		return E.Cause(err, "cleanup rules")
	}
	err = t.setRules()
	if err != nil {
		_ = t.unsetRules()
		return err
	}

	t.setSearchDomainForSystemdResolved()

	if t.options.AutoRoute && runtime.GOOS == "android" {
		t.interfaceCallback = t.options.InterfaceMonitor.RegisterCallback(t.routeUpdate)
	}
	return nil
}

func (t *NativeTun) Close() error {
	if t.interfaceCallback != nil {
		t.options.InterfaceMonitor.UnregisterCallback(t.interfaceCallback)
	}
	return E.Errors(t.unsetRoute(), t.unsetRules(), common.Close(common.PtrOrNil(t.tunFile)))
}

func (t *NativeTun) TXChecksumOffload() bool {
	return t.txChecksumOffload
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

func (t *NativeTun) routes(tunLink netlink.Link) ([]netlink.Route, error) {
	routeRanges, err := t.options.BuildAutoRouteRanges(false)
	if err != nil {
		return nil, err
	}
	return common.Map(routeRanges, func(it netip.Prefix) netlink.Route {
		return netlink.Route{
			Dst:       prefixToIPNet(it),
			LinkIndex: tunLink.Attrs().Index,
			Table:     t.options.TableIndex,
		}
	}), nil
}

const (
	ruleStart = 9000
	ruleEnd   = ruleStart + 10
)

func (t *NativeTun) nextIndex6() int {
	ruleList, err := netlink.RuleList(netlink.FAMILY_V6)
	if err != nil {
		return -1
	}
	var minIndex int
	for _, rule := range ruleList {
		if rule.Priority > 0 && (minIndex == 0 || rule.Priority < minIndex) {
			minIndex = rule.Priority
		}
	}
	minIndex--
	t.ruleIndex6 = append(t.ruleIndex6, minIndex)
	return minIndex
}

func (t *NativeTun) rules() []*netlink.Rule {
	if !t.options.AutoRoute {
		if len(t.options.Inet6Address) > 0 {
			it := netlink.NewRule()
			it.Priority = t.nextIndex6()
			it.Table = t.options.TableIndex
			it.Family = unix.AF_INET6
			it.OifName = t.options.Name
			return []*netlink.Rule{it}
		}
		return nil
	}

	var p4, p6 bool
	var pRule int
	if len(t.options.Inet4Address) > 0 {
		p4 = true
		pRule += 1
	}
	if len(t.options.Inet6Address) > 0 {
		p6 = true
		pRule += 1
	}
	if pRule == 0 {
		return []*netlink.Rule{}
	}

	var rules []*netlink.Rule
	var it *netlink.Rule

	excludeRanges := t.options.ExcludedRanges()
	priority := ruleStart
	priority6 := priority
	nopPriority := ruleEnd

	for _, excludeRange := range excludeRanges {
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.UIDRange = netlink.NewRuleUIDRange(excludeRange.Start, excludeRange.End)
			it.Goto = nopPriority
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.UIDRange = netlink.NewRuleUIDRange(excludeRange.Start, excludeRange.End)
			it.Goto = nopPriority
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
	}
	if len(excludeRanges) > 0 {
		if p4 {
			priority++
		}
		if p6 {
			priority6++
		}
	}
	if len(t.options.IncludeInterface) > 0 {
		matchPriority := priority + 2*len(t.options.IncludeInterface) + 1
		for _, includeInterface := range t.options.IncludeInterface {
			if p4 {
				it = netlink.NewRule()
				it.Priority = priority
				it.IifName = includeInterface
				it.Goto = matchPriority
				it.Family = unix.AF_INET
				rules = append(rules, it)
				priority++
			}
			if p6 {
				it = netlink.NewRule()
				it.Priority = priority6
				it.IifName = includeInterface
				it.Goto = matchPriority
				it.Family = unix.AF_INET6
				rules = append(rules, it)
				priority6++
			}
		}
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Family = unix.AF_INET
			it.Goto = nopPriority
			rules = append(rules, it)
			priority++

			it = netlink.NewRule()
			it.Priority = matchPriority
			it.Family = unix.AF_INET
			rules = append(rules, it)
			priority++
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Family = unix.AF_INET6
			it.Goto = nopPriority
			rules = append(rules, it)
			priority6++

			it = netlink.NewRule()
			it.Priority = matchPriority
			it.Family = unix.AF_INET6
			rules = append(rules, it)
			priority6++
		}
	} else if len(t.options.ExcludeInterface) > 0 {
		for _, excludeInterface := range t.options.ExcludeInterface {
			if p4 {
				it = netlink.NewRule()
				it.Priority = priority
				it.IifName = excludeInterface
				it.Goto = nopPriority
				it.Family = unix.AF_INET
				rules = append(rules, it)
				priority++
			}
			if p6 {
				it = netlink.NewRule()
				it.Priority = priority6
				it.IifName = excludeInterface
				it.Goto = nopPriority
				it.Family = unix.AF_INET6
				rules = append(rules, it)
				priority6++
			}
		}
	}

	if runtime.GOOS == "android" && t.options.InterfaceMonitor.AndroidVPNEnabled() {
		const protectedFromVPN = 0x20000
		if p4 || t.options.StrictRoute {
			it = netlink.NewRule()
			if t.options.InterfaceMonitor.OverrideAndroidVPN() {
				it.Mark = protectedFromVPN
			}
			it.Mask = protectedFromVPN
			it.Priority = priority
			it.Family = unix.AF_INET
			it.Goto = nopPriority
			rules = append(rules, it)
			priority++
		}
		if p6 || t.options.StrictRoute {
			it = netlink.NewRule()
			if t.options.InterfaceMonitor.OverrideAndroidVPN() {
				it.Mark = protectedFromVPN
			}
			it.Mask = protectedFromVPN
			it.Family = unix.AF_INET6
			it.Priority = priority6
			it.Goto = nopPriority
			rules = append(rules, it)
			priority6++
		}
	}

	if t.options.StrictRoute {
		if !p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Family = unix.AF_INET
			it.Type = unix.FR_ACT_UNREACHABLE
			rules = append(rules, it)
			priority++
		}
		if !p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Family = unix.AF_INET6
			it.Type = unix.FR_ACT_UNREACHABLE
			rules = append(rules, it)
			priority6++
		}
	}

	if runtime.GOOS != "android" {
		if p4 {
			for _, address := range t.options.Inet4Address {
				it = netlink.NewRule()
				it.Priority = priority
				it.Dst = address.Masked()
				it.Table = t.options.TableIndex
				it.Family = unix.AF_INET
				rules = append(rules, it)
			}
			priority++
		}
		/*if p6 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Dst = t.options.Inet6Address.Masked()
			it.Table = tunTableIndex
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}*/
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.IPProto = syscall.IPPROTO_ICMP
			it.Goto = nopPriority
			it.Family = unix.AF_INET
			rules = append(rules, it)
			priority++
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.IPProto = syscall.IPPROTO_ICMPV6
			it.Goto = nopPriority
			it.Family = unix.AF_INET6
			rules = append(rules, it)
			priority6++
		}
		if p4 {
			it = netlink.NewRule()
			it.Priority = priority
			it.Invert = true
			it.Dport = netlink.NewRulePortRange(53, 53)
			it.Table = unix.RT_TABLE_MAIN
			it.SuppressPrefixlen = 0
			it.Family = unix.AF_INET
			rules = append(rules, it)
		}
		if p6 {
			it = netlink.NewRule()
			it.Priority = priority6
			it.Invert = true
			it.Dport = netlink.NewRulePortRange(53, 53)
			it.Table = unix.RT_TABLE_MAIN
			it.SuppressPrefixlen = 0
			it.Family = unix.AF_INET6
			rules = append(rules, it)
		}
	}

	if p4 {
		if t.options.StrictRoute {
			it = netlink.NewRule()
			it.Priority = priority
			it.Table = t.options.TableIndex
			it.Family = unix.AF_INET
			rules = append(rules, it)
		} else {
			it = netlink.NewRule()
			it.Priority = priority
			it.Invert = true
			it.IifName = "lo"
			it.Table = t.options.TableIndex
			it.Family = unix.AF_INET
			rules = append(rules, it)

			it = netlink.NewRule()
			it.Priority = priority
			it.IifName = "lo"
			it.Src = netip.PrefixFrom(netip.IPv4Unspecified(), 32)
			it.Table = t.options.TableIndex
			it.Family = unix.AF_INET
			rules = append(rules, it)

			for _, address := range t.options.Inet4Address {
				it = netlink.NewRule()
				it.Priority = priority
				it.IifName = "lo"
				it.Src = address.Masked()
				it.Table = t.options.TableIndex
				it.Family = unix.AF_INET
				rules = append(rules, it)
			}
		}
		priority++
	}
	if p6 {
		if !t.options.StrictRoute {
			for _, address := range t.options.Inet6Address {
				it = netlink.NewRule()
				it.Priority = priority6
				it.IifName = "lo"
				it.Src = address.Masked()
				it.Table = t.options.TableIndex
				it.Family = unix.AF_INET6
				rules = append(rules, it)
			}
			priority6++

			it = netlink.NewRule()
			it.Priority = priority6
			it.IifName = "lo"
			it.Src = netip.PrefixFrom(netip.IPv6Unspecified(), 1)
			it.Goto = nopPriority
			it.Family = unix.AF_INET6
			rules = append(rules, it)

			it = netlink.NewRule()
			it.Priority = priority6
			it.IifName = "lo"
			it.Src = netip.PrefixFrom(netip.AddrFrom16([16]byte{0: 128}), 1)
			it.Goto = nopPriority
			it.Family = unix.AF_INET6
			rules = append(rules, it)

			priority6++
		}

		it = netlink.NewRule()
		it.Priority = priority6
		it.Table = t.options.TableIndex
		it.Family = unix.AF_INET6
		rules = append(rules, it)
		priority6++
	}
	if p4 {
		it = netlink.NewRule()
		it.Priority = nopPriority
		it.Family = unix.AF_INET
		rules = append(rules, it)
	}
	if p6 {
		it = netlink.NewRule()
		it.Priority = nopPriority
		it.Family = unix.AF_INET6
		rules = append(rules, it)
	}
	return rules
}

func (t *NativeTun) setRoute(tunLink netlink.Link) error {
	routes, err := t.routes(tunLink)
	if err != nil {
		return err
	}
	for i, route := range routes {
		err := netlink.RouteAdd(&route)
		if err != nil {
			return E.Cause(err, "add route ", i)
		}
	}
	return nil
}

func (t *NativeTun) setRules() error {
	for i, rule := range t.rules() {
		err := netlink.RuleAdd(rule)
		if err != nil {
			return E.Cause(err, "add rule ", i, "/", len(t.rules()))
		}
	}
	return nil
}

func (t *NativeTun) unsetRoute() error {
	if t.options.FileDescriptor > 0 {
		return nil
	}
	tunLink, err := netlink.LinkByName(t.options.Name)
	if err != nil {
		return err
	}
	return t.unsetRoute0(tunLink)
}

func (t *NativeTun) unsetRoute0(tunLink netlink.Link) error {
	if routes, err := t.routes(tunLink); err == nil {
		for _, route := range routes {
			_ = netlink.RouteDel(&route)
		}
	}
	return nil
}

func (t *NativeTun) unsetRules() error {
	if t.options.FileDescriptor > 0 {
		return nil
	}
	if len(t.ruleIndex6) > 0 {
		for _, index := range t.ruleIndex6 {
			ruleToDel := netlink.NewRule()
			ruleToDel.Family = unix.AF_INET6
			ruleToDel.Priority = index
			err := netlink.RuleDel(ruleToDel)
			if err != nil {
				return E.Cause(err, "unset rule6 ", index)
			}
		}
		t.ruleIndex6 = nil
	}
	if t.options.AutoRoute {
		ruleList, err := netlink.RuleList(netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		for _, rule := range ruleList {
			if rule.Priority >= ruleStart && rule.Priority <= ruleEnd {
				ruleToDel := netlink.NewRule()
				ruleToDel.Family = rule.Family
				ruleToDel.Priority = rule.Priority
				err = netlink.RuleDel(ruleToDel)
				if err != nil {
					return E.Cause(err, "unset rule ", rule.Priority, " for ", rule.Family)
				}
			}
		}
	}
	return nil
}

func (t *NativeTun) resetRules() error {
	t.unsetRules()
	return t.setRules()
}

func (t *NativeTun) routeUpdate(event int) {
	if event&EventAndroidVPNUpdate == 0 {
		return
	}
	err := t.resetRules()
	if err != nil {
		if t.options.Logger != nil {
			t.options.Logger.Error(E.Cause(err, "reset route"))
		}
	}
}

func (t *NativeTun) setSearchDomainForSystemdResolved() {
	ctlPath, err := exec.LookPath("resolvectl")
	if err != nil {
		return
	}
	var dnsServer []netip.Addr
	if len(t.options.Inet4Address) > 0 {
		dnsServer = append(dnsServer, t.options.Inet4Address[0].Addr().Next())
	}
	if len(t.options.Inet6Address) > 0 {
		dnsServer = append(dnsServer, t.options.Inet6Address[0].Addr().Next())
	}
	shell.Exec(ctlPath, "domain", t.options.Name, "~.").Start()
	if t.options.AutoRoute {
		shell.Exec(ctlPath, "default-route", t.options.Name, "true").Start()
		shell.Exec(ctlPath, append([]string{"dns", t.options.Name}, common.Map(dnsServer, netip.Addr.String)...)...).Start()
	}
}
