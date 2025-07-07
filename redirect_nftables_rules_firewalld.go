//go:build linux

package tun

import (
	"time"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/godbus/dbus/v5"
	"golang.org/x/exp/slices"
)

const (
	NFT_TABLE_F_DORMANT = 0x1
	NFT_TABLE_F_OWNER   = 0x2
	NFT_TABLE_F_PERSIST = 0x4
)

const (
	firewalldInterface = "org.fedoraproject.FirewallD1"
	firewalldPath      = "/org/fedoraproject/FirewallD1"
)

func (r *autoRedirect) configureFirewalld(nft *nftables.Conn, cleanup bool) error {
	if cleanup {
		if r.firewalldListener == nil {
			return nil
		}
		r.firewalldListener.Close()
		return r.configureFirewalldRules(nft, false)
	}
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil
	}
	err = conn.Object(firewalldInterface, firewalldPath).Call("org.freedesktop.DBus.Peer.Ping", 0).Err
	if err != nil {
		return nil
	}
	err = r.configureFirewalldRules(nft, false)
	if err != nil {
		r.logger.Warn(E.Cause(err, "configure firewalld rules"))
		return nil
	}
	err = conn.BusObject().AddMatchSignal(firewalldInterface, "Reloaded").Err
	if err != nil {
		return E.Cause(err, "configure firewalld reload listener")
	}
	err = conn.BusObject().AddMatchSignal(
		"org.freedesktop.DBus",
		"NameOwnerChanged",
		dbus.WithMatchSender("org.freedesktop.DBus"),
		dbus.WithMatchArg(0, firewalldInterface),
	).Err
	if err != nil {
		return E.Cause(err, "configure firewalld restart listener")
	}
	signal := make(chan *dbus.Signal, 1)
	conn.Signal(signal)
	listener := &firewalldListener{
		autoRedirect: r,
		conn:         conn,
		signal:       signal,
		done:         make(chan struct{}),
	}
	go listener.loopReload()
	r.firewalldListener = listener
	return nil
}

type firewalldListener struct {
	*autoRedirect
	conn   *dbus.Conn
	signal chan *dbus.Signal
	done   chan struct{}
}

func (l *firewalldListener) loopReload() {
	for {
		select {
		case <-l.done:
			return
		case signal := <-l.signal:
			var restarted bool
			if signal.Name == "org.freedesktop.DBus.NameOwnerChanged" {
				if len(signal.Body) != 3 || signal.Body[2].(string) == "" {
					continue
				} else {
					restarted = true
				}
			}
			err := l.configureFirewalldRulesOnce(restarted)
			if err != nil {
				l.logger.Error(E.Cause(err, "reconfigure firewalld rules"))
			}
		}
	}
}

func (l *firewalldListener) configureFirewalldRulesOnce(restarted bool) error {
	nft, err := nftables.New()
	if err != nil {
		return err
	}
	defer nft.CloseLasting()
	if restarted {
		for i := 0; i < 10; i++ {
			_, err = nft.ListTableOfFamily("firewalld", nftables.TableFamilyINet)
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	err = l.configureFirewalldRules(nft, false)
	if err != nil {
		return err
	}
	return nft.Flush()
}

func (l *firewalldListener) Close() {
	select {
	case <-l.done:
		return
	default:
		close(l.done)
		l.conn.Close()
	}
}

func (r *autoRedirect) configureFirewalldRules(nft *nftables.Conn, cleanup bool) error {
	tableFirewalld, err := nft.ListTableOfFamily("firewalld", nftables.TableFamilyINet)
	if err != nil {
		return err
	}
	if tableFirewalld.Flags&NFT_TABLE_F_OWNER != 0 {
		var conn *dbus.Conn
		conn, err = dbus.SystemBus()
		if err != nil {
			return E.Cause(err, "connect to system bus")
		}
		err = conn.Object(firewalldInterface, firewalldPath+"/config").SetProperty(firewalldInterface+".config.NftablesTableOwner", dbus.MakeVariant("no"))
		if err != nil {
			return E.Cause(err, "take owner of firewalld table")
		}
		err = conn.Object(firewalldInterface, firewalldPath).Call(
			firewalldInterface+".reload", 0).Err
		if err != nil {
			return E.Cause(err, "reload firewalld")
		}
		tableFirewalld, err = nft.ListTableOfFamily("firewalld", nftables.TableFamilyINet)
		if err != nil {
			return E.Cause(err, "check reloaded firewalld table")
		}
		if tableFirewalld.Flags&NFT_TABLE_F_OWNER != 0 {
			return E.New("unable to take owner of firewalld table")
		}
	}
	for _, chainName := range []string{"filter_INPUT", "filter_FORWARD"} {
		var rules []*nftables.Rule
		rules, err = nft.GetRules(tableFirewalld, &nftables.Chain{
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
			if cleanup {
				err = nft.DelRule(rule)
				if err != nil {
					return err
				}
			} else {
				return nil
			}
		}
	}
	if !cleanup {
		ruleIif := &nftables.Rule{
			Table: tableFirewalld,
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
			Table: tableFirewalld,
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
			Name: "filter_FORWARD",
		}
		ruleIif.Chain = chainForward
		ruleOif.Chain = chainForward
		nft.InsertRule(ruleOif)
		nft.InsertRule(ruleIif)
		chainInput := &nftables.Chain{
			Name: "filter_INPUT",
		}
		ruleIif.Chain = chainInput
		ruleOif.Chain = chainInput
		nft.InsertRule(ruleOif)
		nft.InsertRule(ruleIif)
		return nil
	}
	return nil
}
