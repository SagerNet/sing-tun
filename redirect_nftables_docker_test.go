//go:build linux

package tun

import (
	"reflect"
	"testing"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
)

func TestDockerFirewallReconcileDoesNotInsertAcceptRules(t *testing.T) {
	r := &autoRedirect{
		tunOptions: &Options{Name: "tun0"},
		tableName:  "sing-tun",
	}
	nft, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	table := &nftables.Table{Name: nftablesDockerFilterTable, Family: nftables.TableFamilyIPv4}
	chain := &nftables.Chain{Name: nftablesDockerUserChain, Table: table}

	if err := r.reconcileDockerFirewallRules(nft, table, chain, nil); err != nil {
		t.Fatal(err)
	}
	if messages := nftablesConnMessageCount(nft); messages != 0 {
		t.Fatalf("reconcile queued %d netlink messages; want 0", messages)
	}
}

func TestDockerFirewallReconcileCleansExistingCompatibilityRules(t *testing.T) {
	r := &autoRedirect{
		tunOptions: &Options{Name: "tun0"},
		tableName:  "sing-tun",
	}
	nft, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	table := &nftables.Table{Name: nftablesDockerFilterTable, Family: nftables.TableFamilyIPv4}
	chain := &nftables.Chain{Name: nftablesDockerUserChain, Table: table}
	rule := nftablesDockerCompatibilityRule(table, chain, "tun0", expr.MetaKeyOIFNAME, r.nftablesDockerCompatibilityComment("output to tun"))
	rule.Handle = 1

	if err := r.reconcileDockerFirewallRules(nft, table, chain, []*nftables.Rule{rule}); err != nil {
		t.Fatal(err)
	}
	if messages := nftablesConnMessageCount(nft); messages != 1 {
		t.Fatalf("reconcile queued %d netlink messages; want 1 cleanup delete", messages)
	}
}

func nftablesConnMessageCount(nft *nftables.Conn) int {
	return reflect.ValueOf(nft).Elem().FieldByName("messages").Len()
}
