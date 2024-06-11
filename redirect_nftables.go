//go:build linux

package tun

import (
	"net/netip"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	"github.com/sagernet/sing/common"

	"golang.org/x/sys/unix"
)

func (r *autoRedirect) setupNFTables() error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()

	table := nft.AddTable(&nftables.Table{
		Name:   r.tableName,
		Family: nftables.TableFamilyINet,
	})

	chainForward := nft.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityMangle,
	})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainForward,
		Exprs: nftablesRuleIfName(expr.MetaKeyIIFNAME, r.tunOptions.Name, &expr.Verdict{
			Kind: expr.VerdictAccept,
		}),
	})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainForward,
		Exprs: nftablesRuleIfName(expr.MetaKeyOIFNAME, r.tunOptions.Name, &expr.Verdict{
			Kind: expr.VerdictAccept,
		}),
	})

	redirectPort := r.redirectPort()
	chainOutput := nft.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeNAT,
	})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainOutput,
		Exprs: nftablesRuleIfName(expr.MetaKeyOIFNAME, r.tunOptions.Name, nftablesRuleRedirectToPorts(redirectPort)...),
	})

	chainPreRouting := nft.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeNAT,
	})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainPreRouting,
		Exprs: nftablesRuleIfName(expr.MetaKeyIIFNAME, r.tunOptions.Name, &expr.Verdict{
			Kind: expr.VerdictReturn,
		}),
	})
	var (
		routeAddress        []netip.Prefix
		routeExcludeAddress []netip.Prefix
	)
	if r.enableIPv4 {
		routeAddress = append(routeAddress, r.tunOptions.Inet4RouteAddress...)
		routeExcludeAddress = append(routeExcludeAddress, r.tunOptions.Inet4RouteExcludeAddress...)
	}
	if r.enableIPv6 {
		routeAddress = append(routeAddress, r.tunOptions.Inet6RouteAddress...)
		routeExcludeAddress = append(routeExcludeAddress, r.tunOptions.Inet6RouteExcludeAddress...)
	}
	for _, address := range routeExcludeAddress {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: nftablesRuleDestinationAddress(address, &expr.Verdict{
				Kind: expr.VerdictReturn,
			}),
		})
	}
	for _, name := range r.tunOptions.ExcludeInterface {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: nftablesRuleIfName(expr.MetaKeyIIFNAME, name, &expr.Verdict{
				Kind: expr.VerdictReturn,
			}),
		})
	}
	for _, uidRange := range r.tunOptions.ExcludeUID {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: nftablesRuleMetaUInt32Range(expr.MetaKeySKUID, uidRange, &expr.Verdict{
				Kind: expr.VerdictReturn,
			}),
		})
	}

	var routeExprs []expr.Any
	if len(routeAddress) > 0 {
		for _, address := range routeAddress {
			routeExprs = append(routeExprs, nftablesRuleDestinationAddress(address)...)
		}
	}

	if !r.tunOptions.EXP_DisableDNSHijack {
		dnsServer4 := common.Find(r.tunOptions.DNSServers, func(it netip.Addr) bool {
			return it.Is4()
		})
		dnsServer6 := common.Find(r.tunOptions.DNSServers, func(it netip.Addr) bool {
			return it.Is6()
		})
		if r.enableIPv4 && !dnsServer4.IsValid() {
			dnsServer4 = r.tunOptions.Inet4Address[0].Addr().Next()
		}
		if r.enableIPv6 && !dnsServer6.IsValid() {
			dnsServer6 = r.tunOptions.Inet6Address[0].Addr().Next()
		}
		if len(r.tunOptions.IncludeInterface) > 0 || len(r.tunOptions.IncludeUID) > 0 {
			for _, name := range r.tunOptions.IncludeInterface {
				if r.enableIPv4 {
					nft.AddRule(&nftables.Rule{
						Table: table,
						Chain: chainPreRouting,
						Exprs: nftablesRuleIfName(expr.MetaKeyIIFNAME, name, append(routeExprs, nftablesRuleHijackDNS(nftables.TableFamilyIPv4, dnsServer4)...)...),
					})
				}
				if r.enableIPv6 {
					nft.AddRule(&nftables.Rule{
						Table: table,
						Chain: chainPreRouting,
						Exprs: nftablesRuleIfName(expr.MetaKeyIIFNAME, name, append(routeExprs, nftablesRuleHijackDNS(nftables.TableFamilyIPv6, dnsServer6)...)...),
					})
				}
			}
			for _, uidRange := range r.tunOptions.IncludeUID {
				if r.enableIPv4 {
					nft.AddRule(&nftables.Rule{
						Table: table,
						Chain: chainPreRouting,
						Exprs: nftablesRuleMetaUInt32Range(expr.MetaKeySKUID, uidRange, append(routeExprs, nftablesRuleHijackDNS(nftables.TableFamilyIPv4, dnsServer4)...)...),
					})
				}
				if r.enableIPv6 {
					nft.AddRule(&nftables.Rule{
						Table: table,
						Chain: chainPreRouting,
						Exprs: nftablesRuleMetaUInt32Range(expr.MetaKeySKUID, uidRange, append(routeExprs, nftablesRuleHijackDNS(nftables.TableFamilyIPv6, dnsServer6)...)...),
					})
				}
			}
		} else {
			if r.enableIPv4 {
				nft.AddRule(&nftables.Rule{
					Table: table,
					Chain: chainPreRouting,
					Exprs: append(routeExprs, nftablesRuleHijackDNS(nftables.TableFamilyIPv4, dnsServer4)...),
				})
			}
			if r.enableIPv6 {
				nft.AddRule(&nftables.Rule{
					Table: table,
					Chain: chainPreRouting,
					Exprs: append(routeExprs, nftablesRuleHijackDNS(nftables.TableFamilyIPv6, dnsServer6)...),
				})
			}
		}
	}

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainPreRouting,
		Exprs: []expr.Any{
			&expr.Fib{
				Register:       1,
				FlagDADDR:      true,
				ResultADDRTYPE: true,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(unix.RTN_LOCAL),
			},
			&expr.Verdict{
				Kind: expr.VerdictReturn,
			},
		},
	})

	if len(r.tunOptions.IncludeInterface) > 0 || len(r.tunOptions.IncludeUID) > 0 {
		for _, name := range r.tunOptions.IncludeInterface {
			nft.AddRule(&nftables.Rule{
				Table: table,
				Chain: chainPreRouting,
				Exprs: nftablesRuleIfName(expr.MetaKeyIIFNAME, name, append(routeExprs, nftablesRuleRedirectToPorts(redirectPort)...)...),
			})
		}
		for _, uidRange := range r.tunOptions.IncludeUID {
			nft.AddRule(&nftables.Rule{
				Table: table,
				Chain: chainPreRouting,
				Exprs: nftablesRuleMetaUInt32Range(expr.MetaKeySKUID, uidRange, append(routeExprs, nftablesRuleRedirectToPorts(redirectPort)...)...),
			})
		}
	} else {
		nft.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPreRouting,
			Exprs: append(routeExprs, nftablesRuleRedirectToPorts(redirectPort)...),
		})
	}
	return nft.Flush()
}

func (r *autoRedirect) cleanupNFTables() {
	conn, err := nftables.New()
	if err != nil {
		return
	}
	conn.DelTable(&nftables.Table{
		Name:   r.tableName,
		Family: nftables.TableFamilyINet,
	})
	_ = conn.Flush()
	_ = conn.CloseLasting()
}
