//go:build linux

package tun

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/ranges"
)

const (
	iptablesTableNAT    = "nat"
	iptablesTableMangle = "mangle"
	iptablesTableFilter = "filter"
)

type iptablesHook int

const (
	iptablesHookOutput iptablesHook = iota
	iptablesHookPrerouting
)

type iptablesChainKind int

const (
	iptablesKindNAT iptablesChainKind = iota
	iptablesKindRoute
	iptablesKindFilter
)

type iptablesFamily struct {
	path         string
	isIPv6       bool
	tproxy       bool
	dnsServer    netip.Addr
	chainCounter int
}

type iptablesMatch struct {
	positive []string
	negative []string
}

type iptablesLocalChain struct {
	family    *iptablesFamily
	table     string
	name      string
	next      string
	hook      iptablesHook
	kind      iptablesChainKind
	dnsHijack bool
}

type iptablesInsert struct {
	table string
	base  string
	args  []string
}

type iptablesBuilder struct {
	redirect *autoRedirect
	family   *iptablesFamily
	table    string
	name     string
	chain    string
	err      error
}

func iptablesMark(value uint32, mask uint32) string {
	return iptablesHex(value) + "/" + iptablesHex(mask)
}

func iptablesHex(value uint32) string {
	return "0x" + strconv.FormatUint(uint64(value), 16)
}

func iptablesUIDRange(uidRange ranges.Range[uint32]) string {
	if uidRange.Start == uidRange.End {
		return F.ToString(uidRange.Start)
	}
	return F.ToString(uidRange.Start, "-", uidRange.End)
}

func (r *autoRedirect) iptablesChain(family *iptablesFamily, table string, name string) *iptablesBuilder {
	builder := &iptablesBuilder{
		redirect: r,
		family:   family,
		table:    table,
		name:     name,
		chain:    name,
	}
	builder.err = iptablesRun(family.path, "-t", table, "-N", name)
	return builder
}

func (b *iptablesBuilder) add(args ...string) {
	if b.err != nil {
		return
	}
	b.err = iptablesRun(b.family.path, slices.Concat([]string{"-t", b.table, "-A", b.chain}, args)...)
}

func (b *iptablesBuilder) newChain(prefix string) string {
	b.family.chainCounter++
	name := F.ToString(b.redirect.tableName, "-", prefix, "-", b.family.chainCounter)
	if b.err == nil {
		b.err = iptablesRun(b.family.path, "-t", b.table, "-N", name)
	}
	return name
}

func (b *iptablesBuilder) includeOnly(matches []iptablesMatch) {
	if len(matches) == 0 {
		return
	}
	if len(matches) == 1 && len(matches[0].negative) > 0 {
		b.add(slices.Concat(matches[0].negative, []string{"-j", "RETURN"})...)
		return
	}
	next := b.newChain("include")
	for _, match := range matches {
		b.add(slices.Concat(match.positive, []string{"-j", next})...)
	}
	b.chain = next
}

func (b *iptablesBuilder) branch(prefix string) *iptablesBuilder {
	name := b.newChain(prefix)
	b.add("-j", name)
	return &iptablesBuilder{
		redirect: b.redirect,
		family:   b.family,
		table:    b.table,
		name:     name,
		chain:    name,
		err:      b.err,
	}
}

func (b *iptablesBuilder) absorb(child *iptablesBuilder) {
	if b.err == nil {
		b.err = child.err
	}
}

func (b *iptablesBuilder) localGate(hook iptablesHook, kind iptablesChainKind, dnsHijack bool) {
	next := b.newChain("cont")
	name := b.newChain("local")
	b.add("-j", name)
	chain := iptablesLocalChain{
		family:    b.family,
		table:     b.table,
		name:      name,
		next:      next,
		hook:      hook,
		kind:      kind,
		dnsHijack: dnsHijack,
	}
	if b.err == nil {
		b.err = b.redirect.iptablesFillLocalChain(chain, b.redirect.localAddresses)
	}
	b.redirect.iptablesLocalChains = append(b.redirect.iptablesLocalChains, chain)
	b.chain = next
}

func (b *iptablesBuilder) addVPNServiceGate() {
	if b.redirect.androidVPNService {
		b.add("!", "-o", b.redirect.tunOptions.Name, "-j", "RETURN")
	}
}

func (b *iptablesBuilder) addRedirect() {
	loopbackAddresses := b.redirect.tunOptions.Inet4LoopbackAddress
	if b.family.isIPv6 {
		loopbackAddresses = b.redirect.tunOptions.Inet6LoopbackAddress
	}
	redirect := []string{"-p", "tcp", "-j", "REDIRECT", "--to-ports", strconv.Itoa(int(b.redirect.redirectPort()))}
	if len(loopbackAddresses) == 0 {
		b.add(redirect...)
		return
	}
	name := b.newChain("redirect")
	b.add("-j", name)
	parent := b.chain
	b.chain = name
	for _, address := range loopbackAddresses {
		b.add("-d", address.String(), "-j", "RETURN")
	}
	b.add(redirect...)
	b.chain = parent
}

func (r *autoRedirect) findLocalAddresses() ([]netip.Prefix, error) {
	err := r.interfaceFinder.Update()
	if err != nil {
		return nil, E.Cause(err, "update interfaces")
	}
	return common.Uniq(common.FlatMap(r.interfaceFinder.Interfaces(), func(it control.Interface) []netip.Prefix {
		return common.Map(common.Filter(it.Addresses, func(prefix netip.Prefix) bool {
			return it.Name == "lo" || prefix.Addr().IsGlobalUnicast()
		}), netip.Prefix.Masked)
	})), nil
}

func (r *autoRedirect) iptablesFillLocalChain(chain iptablesLocalChain, addresses []netip.Prefix) error {
	prefixes := common.Filter(addresses, func(it netip.Prefix) bool {
		if chain.family.isIPv6 {
			return it.Addr().Is6() && !it.Addr().Is4In6()
		}
		return it.Addr().Is4()
	})
	if chain.dnsHijack {
		action := func(protocol string) []string {
			if chain.kind == iptablesKindFilter {
				return []string{"-j", "RETURN"}
			}
			if chain.kind == iptablesKindNAT && !chain.family.isIPv6 && protocol == "udp" {
				return []string{"-j", "DNAT", "--to-destination", chain.family.dnsServer.String()}
			}
			return []string{"-g", chain.next}
		}
		if chain.hook == iptablesHookPrerouting {
			for _, prefix := range prefixes {
				for _, protocol := range []string{"udp", "tcp"} {
					err := iptablesRun(chain.family.path, slices.Concat([]string{
						"-t", chain.table, "-A", chain.name,
						"-s", prefix.String(), "-p", protocol, "--dport", "53",
					}, action(protocol))...)
					if err != nil {
						return err
					}
				}
			}
		} else {
			for _, protocol := range []string{"udp", "tcp"} {
				err := iptablesRun(chain.family.path, slices.Concat([]string{
					"-t", chain.table, "-A", chain.name,
					"!", "-o", "lo", "-p", protocol, "--dport", "53",
				}, action(protocol))...)
				if err != nil {
					return err
				}
			}
		}
	}
	for _, prefix := range prefixes {
		err := iptablesRun(chain.family.path, "-t", chain.table, "-A", chain.name, "-d", prefix.String(), "-j", "RETURN")
		if err != nil {
			return err
		}
	}
	return iptablesRun(chain.family.path, "-t", chain.table, "-A", chain.name, "-j", chain.next)
}

func (r *autoRedirect) updateIPTablesLocalAddresses() error {
	localAddresses, err := r.findLocalAddresses()
	if err != nil {
		return err
	}
	if slices.Equal(localAddresses, r.localAddresses) {
		return nil
	}
	r.localAddresses = localAddresses
	for _, chain := range r.iptablesLocalChains {
		err = iptablesRun(chain.family.path, "-t", chain.table, "-F", chain.name)
		if err != nil {
			return err
		}
		err = r.iptablesFillLocalChain(chain, localAddresses)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *autoRedirect) iptablesAddExcludeRules(builder *iptablesBuilder, hook iptablesHook, kind iptablesChainKind, dnsHijack bool) {
	options := r.tunOptions
	mask := r.effectiveMarkMask()
	outputMark := iptablesMark(r.tunOptions.AutoRedirectOutputMark, mask)
	if hook == iptablesHookOutput && kind != iptablesKindFilter {
		builder.add("-m", "mark", "--mark", outputMark, "-j", "RETURN")
		if kind == iptablesKindRoute {
			builder.add("-m", "connmark", "--mark", outputMark, "-j", "RETURN")
		}
	}
	if kind == iptablesKindNAT {
		builder.add("-m", "connmark", "--mark", outputMark, "-j", "RETURN")
	}
	if hook == iptablesHookPrerouting {
		builder.add("-i", options.Name, "-j", "RETURN")
		builder.includeOnly(common.Map(options.IncludeInterface, func(it string) iptablesMatch {
			return iptablesMatch{positive: []string{"-i", it}, negative: []string{"!", "-i", it}}
		}))
		for _, name := range options.ExcludeInterface {
			builder.add("-i", name, "-j", "RETURN")
		}
		// xt_mac reports no match on interfaces without an ethernet header
		// before applying the invert flag, so an inverted form would keep
		// non-ethernet ingress included.
		builder.includeOnly(common.Map(options.IncludeMACAddress, func(it net.HardwareAddr) iptablesMatch {
			return iptablesMatch{positive: []string{"-m", "mac", "--mac-source", it.String()}}
		}))
		for _, address := range options.ExcludeMACAddress {
			builder.add("-m", "mac", "--mac-source", address.String(), "-j", "RETURN")
		}
	} else {
		builder.includeOnly(common.Map(options.IncludeUID, func(it ranges.Range[uint32]) iptablesMatch {
			return iptablesMatch{
				positive: []string{"-m", "owner", "--uid-owner", iptablesUIDRange(it)},
				negative: []string{"-m", "owner", "!", "--uid-owner", iptablesUIDRange(it)},
			}
		}))
		for _, uidRange := range options.ExcludeUID {
			builder.add("-m", "owner", "--uid-owner", iptablesUIDRange(uidRange), "-j", "RETURN")
		}
	}
	routeAddress := options.Inet4RouteAddress
	routeExcludeAddress := options.Inet4RouteExcludeAddress
	if builder.family.isIPv6 {
		routeAddress = options.Inet6RouteAddress
		routeExcludeAddress = options.Inet6RouteExcludeAddress
	}
	builder.includeOnly(common.Map(routeAddress, func(it netip.Prefix) iptablesMatch {
		return iptablesMatch{positive: []string{"-d", it.String()}, negative: []string{"!", "-d", it.String()}}
	}))
	for _, prefix := range routeExcludeAddress {
		builder.add("-d", prefix.String(), "-j", "RETURN")
	}
	builder.localGate(hook, kind, dnsHijack)
}

func (r *autoRedirect) iptablesAddPreMatchRules(builder *iptablesBuilder, hook iptablesHook, dnsHijack bool) {
	options := r.tunOptions
	mask := r.effectiveMarkMask()
	maskValue := iptablesHex(mask)
	inputMark := iptablesMark(r.tunOptions.AutoRedirectInputMark, mask)
	outputMark := iptablesMark(r.tunOptions.AutoRedirectOutputMark, mask)
	resetMark := iptablesMark(r.tunOptions.AutoRedirectResetMark, mask)
	if hook == iptablesHookOutput {
		if r.androidVPNService {
			builder.add("!", "-o", options.Name, "-j", "RETURN")
		} else {
			builder.add("-o", options.Name, "-j", "RETURN")
		}
	} else {
		builder.add("-i", "lo", "-j", "RETURN")
	}
	if builder.family.tproxy {
		tproxyMark := iptablesMark(r.tunOptions.AutoRedirectTProxyMark, mask)
		builder.add("-m", "connmark", "--mark", tproxyMark, "-j", "RETURN")
		builder.add("-m", "mark", "--mark", tproxyMark, "-j", "CONNMARK", "--save-mark", "--nfmask", maskValue, "--ctmask", maskValue)
		builder.add("-m", "mark", "--mark", tproxyMark, "-j", "RETURN")
	}
	builder.add("-m", "mark", "--mark", outputMark, "-j", "CONNMARK", "--save-mark", "--nfmask", maskValue, "--ctmask", maskValue)
	builder.add("-m", "mark", "--mark", outputMark, "-j", "RETURN")
	builder.add("-m", "mark", "--mark", inputMark, "-j", "CONNMARK", "--save-mark", "--nfmask", maskValue, "--ctmask", maskValue)
	builder.add("-m", "mark", "--mark", inputMark, "-j", "RETURN")
	builder.add("-p", "tcp", "-m", "mark", "--mark", resetMark, "-j", "RETURN")
	if hook == iptablesHookOutput && r.androidVPNService {
		builder.add("-m", "connmark", "--mark", outputMark, "-j", "MARK", "--set-xmark", outputMark)
	}
	builder.add("-m", "connmark", "--mark", outputMark, "-j", "RETURN")
	builder.add("-m", "connmark", "--mark", inputMark, "-j", "RETURN")
	builder.add("-p", "tcp", "!", "--tcp-flags", "SYN,ACK", "SYN", "-j", "RETURN")
	r.iptablesAddExcludeRules(builder, hook, iptablesKindFilter, dnsHijack)
	queue := []string{"-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(r.effectiveNFQueue())), "--queue-bypass"}
	builder.add(slices.Concat([]string{"-p", "tcp"}, queue)...)
	builder.add(slices.Concat([]string{"-p", "udp"}, queue)...)
	if builder.family.isIPv6 {
		builder.add(slices.Concat([]string{"-p", "icmpv6", "--icmpv6-type", strconv.Itoa(int(header.ICMPv6EchoRequest))}, queue)...)
	} else {
		builder.add(slices.Concat([]string{"-p", "icmp", "--icmp-type", strconv.Itoa(int(header.ICMPv4Echo))}, queue)...)
	}
}

func (r *autoRedirect) iptablesAddMarkRules(builder *iptablesBuilder) {
	mask := r.effectiveMarkMask()
	maskValue := iptablesHex(mask)
	inputMark := iptablesMark(r.tunOptions.AutoRedirectInputMark, mask)
	builder.add("-j", "MARK", "--set-xmark", inputMark)
	builder.add("-j", "CONNMARK", "--save-mark", "--nfmask", maskValue, "--ctmask", maskValue)
}

func (r *autoRedirect) iptablesAddLoopbackReroute(builder *iptablesBuilder, hook iptablesHook) {
	loopbackAddresses := r.tunOptions.Inet4LoopbackAddress
	if builder.family.isIPv6 {
		loopbackAddresses = r.tunOptions.Inet6LoopbackAddress
	}
	mask := r.effectiveMarkMask()
	maskValue := iptablesHex(mask)
	inputMark := iptablesMark(r.tunOptions.AutoRedirectInputMark, mask)
	for _, address := range loopbackAddresses {
		builder.add("-p", "tcp", "-d", address.String(), "-m", "mark", "!", "--mark", inputMark, "-j", "MARK", "--set-xmark", inputMark)
		if hook == iptablesHookOutput {
			builder.add("-p", "tcp", "-d", address.String(), "-m", "mark", "--mark", inputMark,
				"-j", "CONNMARK", "--save-mark", "--nfmask", maskValue, "--ctmask", maskValue)
		}
	}
}

func (r *autoRedirect) setupIPTables() error {
	r.iptablesAccess.Lock()
	defer r.iptablesAccess.Unlock()
	localAddresses, err := r.findLocalAddresses()
	if err != nil {
		return err
	}
	r.localAddresses = localAddresses
	var families []*iptablesFamily
	if r.enableIPv4 {
		families = append(families, &iptablesFamily{path: r.iptablesPath})
	}
	if r.enableIPv6 {
		families = append(families, &iptablesFamily{path: r.ip6tablesPath, isIPv6: true, tproxy: r.tproxyEnabled()})
	}
	for _, family := range families {
		err = r.setupIPTablesForFamily(family)
		if err != nil {
			return err
		}
	}
	return r.setupIPTablesUnreachable()
}

func (r *autoRedirect) setupIPTablesForFamily(family *iptablesFamily) error {
	options := r.tunOptions
	mask := r.effectiveMarkMask()
	maskValue := iptablesHex(mask)
	inputMark := iptablesMark(r.tunOptions.AutoRedirectInputMark, mask)
	outputMark := iptablesMark(r.tunOptions.AutoRedirectOutputMark, mask)
	resetMark := iptablesMark(r.tunOptions.AutoRedirectResetMark, mask)
	loopbackAddresses := options.Inet4LoopbackAddress
	if family.isIPv6 {
		loopbackAddresses = options.Inet6LoopbackAddress
	}
	dnsHijack := options.DNSModeOrDefault() == DNSModeHijack
	if dnsHijack {
		var (
			dnsServers []netip.Addr
			dnsErr     error
		)
		if family.isIPv6 {
			dnsServers, dnsErr = options.Inet6DNSAddress()
		} else {
			dnsServers, dnsErr = options.Inet4DNSAddress()
		}
		if dnsErr != nil {
			return dnsErr
		}
		if len(dnsServers) == 0 {
			dnsHijack = false
		} else {
			family.dnsServer = dnsServers[0]
		}
	}
	markProtocols := iptablesMarkProtocols(family)
	var inserts []iptablesInsert

	if len(loopbackAddresses) > 0 {
		if !r.shouldSkipOutputChain() {
			outputLoopback := r.iptablesChain(family, iptablesTableMangle, r.tableName+"-output-loopback")
			r.iptablesAddLoopbackReroute(outputLoopback, iptablesHookOutput)
			if outputLoopback.err != nil {
				return outputLoopback.err
			}
			inserts = append(inserts, iptablesInsert{iptablesTableMangle, "OUTPUT", []string{"-j", outputLoopback.name}})
		}
		preroutingLoopback := r.iptablesChain(family, iptablesTableMangle, r.tableName+"-prerouting-loopback")
		r.iptablesAddLoopbackReroute(preroutingLoopback, iptablesHookPrerouting)
		if preroutingLoopback.err != nil {
			return preroutingLoopback.err
		}
		inserts = append(inserts, iptablesInsert{iptablesTableMangle, "PREROUTING", []string{"-j", preroutingLoopback.name}})
	}

	if !r.shouldSkipOutputChain() {
		outputPreMatch := r.iptablesChain(family, iptablesTableMangle, r.tableName+"-output-prematch")
		r.iptablesAddPreMatchRules(outputPreMatch, iptablesHookOutput, dnsHijack)
		if outputPreMatch.err != nil {
			return outputPreMatch.err
		}
		inserts = append(inserts, iptablesInsert{iptablesTableMangle, "OUTPUT", []string{"-j", outputPreMatch.name}})
	}
	preroutingPreMatch := r.iptablesChain(family, iptablesTableMangle, r.tableName+"-prerouting-prematch")
	r.iptablesAddPreMatchRules(preroutingPreMatch, iptablesHookPrerouting, dnsHijack)
	if preroutingPreMatch.err != nil {
		return preroutingPreMatch.err
	}
	inserts = append(inserts, iptablesInsert{iptablesTableMangle, "PREROUTING", []string{"-j", preroutingPreMatch.name}})

	if !r.shouldSkipOutputChain() {
		outputMarkChain := r.iptablesChain(family, iptablesTableMangle, r.tableName+"-output-mark")
		outputMarkChain.addVPNServiceGate()
		if family.isIPv6 && !family.tproxy {
			outputMarkChain.add("-p", "tcp", "-m", "mark", "--mark", resetMark, "-j", "RETURN")
		}
		r.iptablesAddExcludeRules(outputMarkChain, iptablesHookOutput, iptablesKindRoute, dnsHijack)
		r.iptablesAddMarkRules(outputMarkChain)
		if outputMarkChain.err != nil {
			return outputMarkChain.err
		}
		for _, protocol := range markProtocols {
			inserts = append(inserts, iptablesInsert{iptablesTableMangle, "OUTPUT", []string{"-p", protocol, "-j", outputMarkChain.name}})
		}
	}
	preroutingMarkChain := r.iptablesChain(family, iptablesTableMangle, r.tableName+"-prerouting-mark")
	preroutingMarkChain.add("-i", options.Name, "-j", "RETURN")
	if family.isIPv6 && !family.tproxy {
		preroutingMarkChain.add("-p", "tcp", "-m", "mark", "--mark", resetMark, "-j", "RETURN")
	}
	preroutingMarkChain.add("-m", "connmark", "--mark", inputMark, "-j", "MARK", "--set-xmark", inputMark)
	preroutingMarkChain.add("-m", "connmark", "--mark", inputMark, "-j", "RETURN")
	preroutingMarkChain.add("-m", "connmark", "--mark", outputMark, "-j", "MARK", "--set-xmark", outputMark)
	preroutingMarkChain.add("-m", "connmark", "--mark", outputMark, "-j", "RETURN")
	include := preroutingMarkChain.branch("include")
	r.iptablesAddExcludeRules(include, iptablesHookPrerouting, iptablesKindRoute, dnsHijack)
	r.iptablesAddMarkRules(include)
	preroutingMarkChain.absorb(include)
	preroutingMarkChain.add("-m", "mark", "--mark", inputMark, "-j", "RETURN")
	preroutingMarkChain.add("-j", "MARK", "--set-xmark", outputMark)
	preroutingMarkChain.add("-j", "CONNMARK", "--save-mark", "--nfmask", maskValue, "--ctmask", maskValue)
	if preroutingMarkChain.err != nil {
		return preroutingMarkChain.err
	}
	for _, protocol := range markProtocols {
		inserts = append(inserts, iptablesInsert{iptablesTableMangle, "PREROUTING", []string{"-p", protocol, "-j", preroutingMarkChain.name}})
	}
	if r.androidVPNService && !family.isIPv6 {
		// A TCP flow addressed to the router itself leaves the pre-match chain
		// without a connmark, the accepted socket inherits the unmarked SYN
		// through tcp_fwmark_accept, and netd's VPN rule then routes its replies
		// into the tun.
		preroutingLocal := r.iptablesChain(family, iptablesTableMangle, r.tableName+"-prerouting-local")
		preroutingLocal.add("-i", options.Name, "-j", "RETURN")
		preroutingLocal.add("-m", "connmark", "!", "--mark", iptablesMark(0, mask), "-j", "RETURN")
		preroutingLocal.add("-j", "MARK", "--set-xmark", outputMark)
		localInclude := preroutingLocal.branch("include")
		r.iptablesAddExcludeRules(localInclude, iptablesHookPrerouting, iptablesKindRoute, dnsHijack)
		localInclude.add("-j", "MARK", "--set-xmark", iptablesMark(0, mask))
		preroutingLocal.absorb(localInclude)
		preroutingLocal.add("-m", "mark", "--mark", outputMark, "-j", "CONNMARK", "--save-mark", "--nfmask", maskValue, "--ctmask", maskValue)
		if preroutingLocal.err != nil {
			return preroutingLocal.err
		}
		inserts = append(inserts, iptablesInsert{
			iptablesTableMangle, "PREROUTING",
			[]string{"-p", "tcp", "-m", "mark", "--mark", iptablesMark(0, mask), "-j", preroutingLocal.name},
		})
	}

	if !family.isIPv6 {
		if !r.shouldSkipOutputChain() {
			outputNAT := r.iptablesChain(family, iptablesTableNAT, r.tableName+"-output")
			outputNAT.addVPNServiceGate()
			r.iptablesAddExcludeRules(outputNAT, iptablesHookOutput, iptablesKindNAT, dnsHijack)
			outputNAT.addRedirect()
			if outputNAT.err != nil {
				return outputNAT.err
			}
			inserts = append(inserts, iptablesInsert{iptablesTableNAT, "OUTPUT", []string{"-j", outputNAT.name}})
		}
		preroutingNAT := r.iptablesChain(family, iptablesTableNAT, r.tableName+"-prerouting")
		preroutingNAT.add("-p", "tcp", "-m", "mark", "--mark", resetMark, "-j", "RETURN")
		r.iptablesAddExcludeRules(preroutingNAT, iptablesHookPrerouting, iptablesKindNAT, dnsHijack)
		preroutingNAT.addRedirect()
		r.iptablesAddMarkRules(preroutingNAT)
		if preroutingNAT.err != nil {
			return preroutingNAT.err
		}
		inserts = append(inserts, iptablesInsert{iptablesTableNAT, "PREROUTING", []string{"-j", preroutingNAT.name}})
		if r.androidVPNService {
			postroutingNAT := r.iptablesChain(family, iptablesTableNAT, r.tableName+"-postrouting")
			for _, prefix := range options.Inet4Address {
				postroutingNAT.add("-s", prefix.Masked().String(), "!", "-o", options.Name, "-m", "mark", "--mark", outputMark, "-j", "MASQUERADE")
			}
			if postroutingNAT.err != nil {
				return postroutingNAT.err
			}
			inserts = append(inserts, iptablesInsert{iptablesTableNAT, "POSTROUTING", []string{"-j", postroutingNAT.name}})
		}
	}

	if r.androidVPNService && (!family.isIPv6 || family.tproxy) {
		// The redirect server runs in the app process, and without the
		// protectedFromVpn bit netd's VPN rule routes its replies back
		// into the tun instead of delivering them over loopback.
		outputProtect := r.iptablesChain(family, iptablesTableMangle, r.tableName+"-output-protect")
		if family.isIPv6 {
			outputProtect.add("-m", "connmark", "--mark", iptablesMark(r.tunOptions.AutoRedirectTProxyMark, mask),
				"-m", "conntrack", "--ctdir", "REPLY",
				"-j", "MARK", "--set-xmark", iptablesMark(androidSecureVPNMask, androidSecureVPNMask))
		} else {
			outputProtect.add("-p", "tcp", "--sport", strconv.Itoa(int(r.redirectPort())),
				"-j", "MARK", "--set-xmark", iptablesMark(androidSecureVPNMask, androidSecureVPNMask))
		}
		if outputProtect.err != nil {
			return outputProtect.err
		}
		inserts = append(inserts, iptablesInsert{iptablesTableMangle, "OUTPUT", []string{"-p", "tcp", "-j", outputProtect.name}})
	}

	if family.tproxy {
		tproxyMark := iptablesMark(r.tunOptions.AutoRedirectTProxyMark, mask)
		tproxyAction := []string{
			"-p", "tcp", "-j", "TPROXY",
			"--on-port", strconv.Itoa(int(r.redirectPort())), "--tproxy-mark", tproxyMark,
		}
		if !r.shouldSkipOutputChain() {
			outputTProxy := r.iptablesChain(family, iptablesTableMangle, r.tableName+"-output-tproxy")
			// Under VpnService the app's own sockets carry the protectedFromVpn bit instead of
			// the routing mark, so netd routes them past the tun.
			outputTProxy.addVPNServiceGate()
			outputTProxy.add("-m", "mark", "--mark", resetMark, "-j", "RETURN")
			outputTProxy.add("-m", "connmark", "--mark", tproxyMark, "-m", "conntrack", "--ctdir", "ORIGINAL",
				"-j", "MARK", "--set-xmark", tproxyMark)
			outputTProxy.add("-m", "mark", "--mark", tproxyMark, "-j", "RETURN")
			r.iptablesAddExcludeRules(outputTProxy, iptablesHookOutput, iptablesKindNAT, dnsHijack)
			outputTProxy.add("-j", "MARK", "--set-xmark", tproxyMark)
			outputTProxy.add("-j", "CONNMARK", "--set-xmark", tproxyMark)
			if outputTProxy.err != nil {
				return outputTProxy.err
			}
			inserts = append(inserts, iptablesInsert{iptablesTableMangle, "OUTPUT", []string{"-p", "tcp", "-j", outputTProxy.name}})
		}
		preroutingTProxy := r.iptablesChain(family, iptablesTableMangle, r.tableName+"-prerouting-tproxy")
		preroutingTProxy.add(slices.Concat([]string{"-m", "mark", "--mark", tproxyMark}, tproxyAction)...)
		preroutingTProxy.add("-m", "mark", "--mark", outputMark, "-j", "RETURN")
		preroutingTProxy.add("-m", "mark", "--mark", resetMark, "-j", "RETURN")
		preroutingTProxy.add(slices.Concat([]string{
			"-m", "connmark", "--mark", tproxyMark,
			"-m", "conntrack", "--ctdir", "ORIGINAL",
		}, tproxyAction)...)
		r.iptablesAddExcludeRules(preroutingTProxy, iptablesHookPrerouting, iptablesKindNAT, dnsHijack)
		preroutingTProxy.add("-j", "CONNMARK", "--set-xmark", tproxyMark)
		preroutingTProxy.add(tproxyAction...)
		if preroutingTProxy.err != nil {
			return preroutingTProxy.err
		}
		inserts = append(inserts, iptablesInsert{iptablesTableMangle, "PREROUTING", []string{"-p", "tcp", "-j", preroutingTProxy.name}})
	}

	input := r.iptablesChain(family, iptablesTableFilter, r.tableName+"-input")
	input.add("-p", "tcp", "--dport", strconv.Itoa(int(r.redirectPort())),
		"-m", "conntrack", "!", "--ctstate", "DNAT",
		"-j", "REJECT", "--reject-with", "tcp-reset")
	if input.err != nil {
		return input.err
	}
	inserts = append(inserts, iptablesInsert{iptablesTableFilter, "INPUT", []string{"-j", input.name}})

	reset := r.iptablesChain(family, iptablesTableFilter, r.tableName+"-reset")
	reset.add("-p", "tcp", "!", "--tcp-flags", "RST", "RST", "-m", "mark", "--mark", resetMark, "-j", "REJECT", "--reject-with", "tcp-reset")
	if reset.err != nil {
		return reset.err
	}
	inserts = append(inserts,
		iptablesInsert{iptablesTableFilter, "INPUT", []string{"-j", reset.name}},
		iptablesInsert{iptablesTableFilter, "OUTPUT", []string{"-j", reset.name}},
		iptablesInsert{iptablesTableFilter, "FORWARD", []string{"-j", reset.name}},
	)

	// netd ends its tetherctrl_FORWARD chain with an unconditional DROP and
	// only accepts its own downstream/upstream interface pairs, so forwarded
	// flows marked into the tun need their own accept.
	if runtime.GOOS == "android" {
		forward := r.iptablesChain(family, iptablesTableFilter, r.tableName+"-forward")
		forward.add("-o", options.Name, "-m", "mark", "--mark", inputMark, "-j", "ACCEPT")
		forward.add("-i", options.Name, "-m", "connmark", "--mark", inputMark, "-j", "ACCEPT")
		if forward.err != nil {
			return forward.err
		}
		inserts = append(inserts, iptablesInsert{iptablesTableFilter, "FORWARD", []string{"-j", forward.name}})
	}

	for _, insert := range slices.Backward(inserts) {
		err := iptablesRun(family.path, slices.Concat([]string{"-t", insert.table, "-I", insert.base}, insert.args)...)
		if err != nil {
			return err
		}
	}
	return nil
}

func iptablesMarkProtocols(family *iptablesFamily) []string {
	var protocols []string
	if family.isIPv6 {
		protocols = []string{"udp", "icmpv6"}
	} else {
		protocols = []string{"udp", "icmp"}
	}
	if family.isIPv6 && !family.tproxy {
		protocols = append(protocols, "tcp")
	}
	return protocols
}

func (r *autoRedirect) setupIPTablesUnreachable() error {
	if !r.tunOptions.StrictRoute || r.enableIPv4 == r.enableIPv6 {
		return nil
	}
	path, err := findIPTablesBinary(r.enableIPv4)
	if err != nil {
		r.logger.Warn("strict route is not available for the disabled address family: ", err)
		return nil
	}
	family := &iptablesFamily{path: path, isIPv6: r.enableIPv4}
	outputName := r.tableName + "-unreachable-output"
	outputBuilder := r.iptablesChain(family, iptablesTableFilter, outputName)
	r.iptablesAddExcludeRules(outputBuilder, iptablesHookOutput, iptablesKindFilter, false)
	outputBuilder.add("-j", "REJECT")
	if outputBuilder.err != nil {
		return outputBuilder.err
	}
	forwardName := r.tableName + "-unreachable-forward"
	forwardBuilder := r.iptablesChain(family, iptablesTableFilter, forwardName)
	r.iptablesAddExcludeRules(forwardBuilder, iptablesHookPrerouting, iptablesKindFilter, false)
	forwardBuilder.add("-j", "REJECT")
	if forwardBuilder.err != nil {
		return forwardBuilder.err
	}
	err = iptablesRun(path, "-t", iptablesTableFilter, "-I", "OUTPUT", "-j", outputName)
	if err != nil {
		return err
	}
	return iptablesRun(path, "-t", iptablesTableFilter, "-I", "FORWARD", "-j", forwardName)
}

func findIPTablesBinary(isIPv6 bool) (string, error) {
	name := "iptables"
	if isIPv6 {
		name = "ip6tables"
	}
	if runtime.GOOS == "android" {
		path := "/system/bin/" + name
		_, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		return path, nil
	}
	return exec.LookPath(name)
}

func (r *autoRedirect) cleanupIPTables() {
	r.iptablesAccess.Lock()
	defer r.iptablesAccess.Unlock()
	r.iptablesLocalChains = nil
	var paths []string
	for _, isIPv6 := range []bool{false, true} {
		path, err := findIPTablesBinary(isIPv6)
		if err == nil {
			paths = append(paths, path)
		}
	}
	for _, path := range common.Uniq(paths) {
		r.cleanupIPTablesForFamily(path)
	}
}

func (r *autoRedirect) cleanupIPTablesForFamily(iptablesPath string) {
	prefix := r.tableName + "-"
	for _, table := range []string{iptablesTableNAT, iptablesTableMangle, iptablesTableFilter} {
		output, err := iptablesRunOutput(iptablesPath, "-t", table, "-S")
		if err != nil {
			continue
		}
		var chains []string
		var references [][]string
		for line := range strings.SplitSeq(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			switch fields[0] {
			case "-N":
				if strings.HasPrefix(fields[1], prefix) {
					chains = append(chains, fields[1])
				}
			case "-A":
				if strings.HasPrefix(fields[1], prefix) {
					continue
				}
				for index := 2; index < len(fields)-1; index++ {
					if fields[index] == "-j" && strings.HasPrefix(fields[index+1], prefix) {
						references = append(references, fields[1:])
						break
					}
				}
			}
		}
		for _, reference := range references {
			_ = iptablesRun(iptablesPath, slices.Concat([]string{"-t", table, "-D"}, reference)...)
		}
		for _, chain := range chains {
			_ = iptablesRun(iptablesPath, "-t", table, "-F", chain)
		}
		for _, chain := range chains {
			_ = iptablesRun(iptablesPath, "-t", table, "-X", chain)
		}
	}
}

// netd runs its own iptables commands whenever a network (including the VPN
// interface) appears or disappears, so a run without -w fails with "Can't
// lock /system/etc/xtables.lock" while netd holds the lock.
func iptablesRun(path string, args ...string) error {
	args = append([]string{"-w"}, args...)
	combinedOutput, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return E.Extend(err, F.ToString(path, " ", strings.Join(args, " "), ": ", strings.TrimSpace(string(combinedOutput))))
	}
	return nil
}

func iptablesRunOutput(path string, args ...string) (string, error) {
	args = append([]string{"-w"}, args...)
	output, err := exec.Command(path, args...).Output()
	if err != nil {
		return "", E.Extend(err, F.ToString(path, " ", strings.Join(args, " ")))
	}
	return string(output), nil
}
