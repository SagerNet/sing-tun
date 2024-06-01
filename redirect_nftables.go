//go:build linux

package tun

import (
	"net/netip"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/binaryutil"
	"github.com/sagernet/nftables/expr"
	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"

	"golang.org/x/sys/unix"
)

const (
	nftablesChainOutput     = "output"
	nftablesChainForward    = "forward"
	nftablesChainPreRouting = "prerouting"
)

func nftablesFamily(family int) nftables.TableFamily {
	switch family {
	case unix.AF_INET:
		return nftables.TableFamilyIPv4
	case unix.AF_INET6:
		return nftables.TableFamilyIPv6
	default:
		panic(F.ToString("unknown family ", family))
	}
}

func (r *autoRedirect) setupNFTables(family int) error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()

	redirectPort := r.redirectPort()

	table := nft.AddTable(&nftables.Table{
		Name:   r.tableName,
		Family: nftablesFamily(family),
	})

	chainOutput := nft.AddChain(&nftables.Chain{
		Name:     nftablesChainOutput,
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

	chainForward := nft.AddChain(&nftables.Chain{
		Name:     nftablesChainForward,
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

	chainPreRouting := nft.AddChain(&nftables.Chain{
		Name:     nftablesChainPreRouting,
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
	if table.Family == nftables.TableFamilyIPv4 {
		routeAddress = r.tunOptions.Inet4RouteAddress
		routeExcludeAddress = r.tunOptions.Inet4RouteExcludeAddress
	} else {
		routeAddress = r.tunOptions.Inet6RouteAddress
		routeExcludeAddress = r.tunOptions.Inet6RouteExcludeAddress
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
		dnsServer := common.Find(r.tunOptions.DNSServers, func(it netip.Addr) bool {
			return it.Is4() == (family == unix.AF_INET)
		})
		if !dnsServer.IsValid() {
			if family == unix.AF_INET {
				dnsServer = r.tunOptions.Inet4Address[0].Addr().Next()
			} else {
				dnsServer = r.tunOptions.Inet6Address[0].Addr().Next()
			}
		}
		if len(r.tunOptions.IncludeInterface) > 0 || len(r.tunOptions.IncludeUID) > 0 {
			for _, name := range r.tunOptions.IncludeInterface {
				nft.AddRule(&nftables.Rule{
					Table: table,
					Chain: chainPreRouting,
					Exprs: nftablesRuleIfName(expr.MetaKeyIIFNAME, name, append(routeExprs, nftablesRuleHijackDNS(table.Family, dnsServer)...)...),
				})
			}
			for _, uidRange := range r.tunOptions.IncludeUID {
				nft.AddRule(&nftables.Rule{
					Table: table,
					Chain: chainPreRouting,
					Exprs: nftablesRuleMetaUInt32Range(expr.MetaKeySKUID, uidRange, append(routeExprs, nftablesRuleHijackDNS(table.Family, dnsServer)...)...),
				})
			}
		} else {
			nft.AddRule(&nftables.Rule{
				Table: table,
				Chain: chainPreRouting,
				Exprs: append(routeExprs, nftablesRuleHijackDNS(table.Family, dnsServer)...),
			})
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

func (r *autoRedirect) cleanupNFTables(family int) {
	conn, err := nftables.New()
	if err != nil {
		return
	}
	conn.FlushTable(&nftables.Table{
		Name:   r.tableName,
		Family: nftablesFamily(family),
	})
	conn.DelTable(&nftables.Table{
		Name:   r.tableName,
		Family: nftablesFamily(family),
	})
	_ = conn.Flush()
	_ = conn.CloseLasting()
}
