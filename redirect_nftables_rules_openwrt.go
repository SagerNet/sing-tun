//go:build linux

package tun

import (
	"github.com/metacubex/nftables"
	"github.com/metacubex/nftables/expr"

	"golang.org/x/exp/slices"
)

func (r *autoRedirect) configureOpenWRTFirewall4(nft *nftables.Conn, cleanup bool) error {
	tableFW4, err := nft.ListTableOfFamily("fw4", nftables.TableFamilyINet)
	if err != nil {
		return nil
	}
	if !cleanup {
		ruleIif := &nftables.Rule{
			Table: tableFW4,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:      expr.MetaKeyIIFNAME,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     nftablesIfname(r.tunOptions.Name),
				},
				&expr.Counter{},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}
		ruleOif := &nftables.Rule{
			Table: tableFW4,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:      expr.MetaKeyOIFNAME,
					Register: 1,
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     nftablesIfname(r.tunOptions.Name),
				},
				&expr.Counter{},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		}
		chainForward := &nftables.Chain{
			Name: "forward",
		}
		ruleIif.Chain = chainForward
		ruleOif.Chain = chainForward
		nft.InsertRule(ruleOif)
		nft.InsertRule(ruleIif)
		chainInput := &nftables.Chain{
			Name: "input",
		}
		ruleIif.Chain = chainInput
		ruleOif.Chain = chainInput
		nft.InsertRule(ruleOif)
		nft.InsertRule(ruleIif)
		return nil
	}
	for _, chainName := range []string{"input", "forward"} {
		var rules []*nftables.Rule
		rules, err = nft.GetRules(tableFW4, &nftables.Chain{
			Name: chainName,
		})
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if len(rule.Exprs) != 4 {
				continue
			}
			exprMeta, isMeta := rule.Exprs[0].(*expr.Meta)
			if !isMeta {
				continue
			}
			if exprMeta.Key != expr.MetaKeyIIFNAME && exprMeta.Key != expr.MetaKeyOIFNAME {
				continue
			}
			exprCmp, isCmp := rule.Exprs[1].(*expr.Cmp)
			if !isCmp {
				continue
			}
			if !slices.Equal(exprCmp.Data, nftablesIfname(r.tunOptions.Name)) {
				continue
			}
			err = nft.DelRule(rule)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
