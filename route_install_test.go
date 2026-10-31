package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInstallRoutePrefixesEmpty(t *testing.T) {
	called := false
	err := installRoutePrefixes(nil, func(netip.Prefix) error {
		called = true
		return nil
	}, func(netip.Prefix) error {
		called = true
		return nil
	})
	if err != nil || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}

func TestInstallRoutePrefixesRollback(t *testing.T) {
	have, add, remove := routeTable()
	boom := errors.New("rejected")
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("10.0.2.0/24"),
	}
	err := installRoutePrefixes(prefixes, func(p netip.Prefix) error {
		if p == prefixes[2] {
			return boom
		}
		return add(p)
	}, remove)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if len(have) != 0 {
		t.Fatalf("leftover routes %v", have)
	}
}

func TestInstallRoutePrefixesReplaceExisting(t *testing.T) {
	have, add, remove := routeTable()
	first := netip.MustParsePrefix("10.1.0.0/24")
	second := netip.MustParsePrefix("10.1.1.0/24")
	have[first.String()] = true
	err := installRoutePrefixes([]netip.Prefix{first, second}, func(p netip.Prefix) error {
		if have[p.String()] {
			return fmt.Errorf("route socket: %w", unix.EEXIST)
		}
		return add(p)
	}, remove)
	if err != nil {
		t.Fatal(err)
	}
	if !have[first.String()] || !have[second.String()] || len(have) != 2 {
		t.Fatalf("table = %v", have)
	}
	// A second install replaces the same prefixes and leaves them in place.
	err = installRoutePrefixes([]netip.Prefix{first, second}, func(p netip.Prefix) error {
		if have[p.String()] {
			return unix.EEXIST
		}
		return add(p)
	}, remove)
	if err != nil {
		t.Fatal(err)
	}
	if len(have) != 2 {
		t.Fatalf("table = %v", have)
	}
}

func TestInstallRoutePrefixesExistingRemoveFails(t *testing.T) {
	have, add, remove := routeTable()
	keep := netip.MustParsePrefix("10.2.0.0/24")
	stuck := netip.MustParsePrefix("10.2.1.0/24")
	have[stuck.String()] = true
	removeErr := errors.New("busy")
	err := installRoutePrefixes([]netip.Prefix{keep, stuck}, add, func(p netip.Prefix) error {
		if p == stuck {
			return removeErr
		}
		return remove(p)
	})
	if !errors.Is(err, removeErr) {
		t.Fatalf("err = %v", err)
	}
	if have[keep.String()] || !have[stuck.String()] {
		t.Fatalf("table = %v", have)
	}
}

func TestInstallRoutePrefixesReAddFails(t *testing.T) {
	have, add, remove := routeTable()
	okPrefix := netip.MustParsePrefix("10.3.0.0/24")
	oldPrefix := netip.MustParsePrefix("10.3.1.0/24")
	have[oldPrefix.String()] = true
	readd := errors.New("readd")
	attempts := 0
	err := installRoutePrefixes([]netip.Prefix{okPrefix, oldPrefix}, func(p netip.Prefix) error {
		if p == oldPrefix {
			attempts++
			if attempts > 1 {
				return readd
			}
		}
		return add(p)
	}, remove)
	if !errors.Is(err, readd) {
		t.Fatalf("err = %v", err)
	}
	if len(have) != 0 {
		t.Fatalf("table = %v, pre-existing route must not be restored", have)
	}
}

func TestInstallRoutePrefixesRollbackRemoveFails(t *testing.T) {
	have, add, _ := routeTable()
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.4.0.0/24"),
		netip.MustParsePrefix("10.4.1.0/24"),
	}
	err := installRoutePrefixes(prefixes, func(p netip.Prefix) error {
		if p == prefixes[1] {
			return errors.New("no")
		}
		return add(p)
	}, func(netip.Prefix) error {
		return errors.New("remove failed")
	})
	if err == nil || !have[prefixes[0].String()] {
		t.Fatalf("err=%v table=%v", err, have)
	}
}

func routeTable() (have map[string]bool, add func(netip.Prefix) error, remove func(netip.Prefix) error) {
	have = map[string]bool{}
	add = func(p netip.Prefix) error {
		if have[p.String()] {
			return unix.EEXIST
		}
		have[p.String()] = true
		return nil
	}
	remove = func(p netip.Prefix) error {
		if !have[p.String()] {
			return unix.ESRCH
		}
		delete(have, p.String())
		return nil
	}
	return have, add, remove
}
