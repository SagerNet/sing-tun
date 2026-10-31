package tun

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"go4.org/netipx"
)

func TestBuildAutoRouteRanges(t *testing.T) {
	withSubRanges(t, true)

	v4 := netip.MustParsePrefix("172.19.0.1/30")
	v6 := netip.MustParsePrefix("fdfe:dcba:9876::1/64")
	include4 := netip.MustParsePrefix("10.0.0.0/8")
	include6 := netip.MustParsePrefix("2001:db8::/32")
	hole4 := netip.MustParsePrefix("10.1.2.0/24")
	hole6 := netip.MustParsePrefix("2001:db8:1::/48")

	t.Run("address set only", func(t *testing.T) {
		got := mustRoutes(t, Options{
			Inet4Address:      []netip.Prefix{v4},
			Inet6Address:      []netip.Prefix{v6},
			Inet4RouteAddress: []netip.Prefix{include4, include4},
			Inet6RouteAddress: []netip.Prefix{include6},
		})
		if len(got) != 3 {
			t.Fatalf("duplicates are kept when there is no exclude, got %v", got)
		}
		if !covers(got, netip.MustParseAddr("10.1.2.1")) || !covers(got, netip.MustParseAddr("2001:db8::1")) {
			t.Fatalf("missing include: %v", got)
		}
	})

	t.Run("exclude without capture", func(t *testing.T) {
		got := mustRoutes(t, Options{
			Inet4Address:             []netip.Prefix{v4},
			Inet6Address:             []netip.Prefix{v6},
			Inet4RouteExcludeAddress: []netip.Prefix{hole4},
			Inet6RouteExcludeAddress: []netip.Prefix{hole6},
		})
		if len(got) != 0 {
			t.Fatalf("exclude alone installs nothing, got %v", got)
		}
	})

	t.Run("exclude set on auto route", func(t *testing.T) {
		got := mustRoutes(t, Options{
			AutoRoute:                true,
			Inet4Address:             []netip.Prefix{v4},
			Inet4RouteExcludeAddress: []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")},
		})
		if covers(got, netip.MustParseAddr("8.8.8.8")) {
			t.Fatal("excluded address is still routed")
		}
		if !covers(got, netip.MustParseAddr("8.8.8.7")) || !covers(got, netip.MustParseAddr("1.1.1.1")) {
			t.Fatalf("capture lost: %v", got)
		}
		if covers(got, netip.MustParseAddr("0.0.0.0")) {
			t.Fatal("split default must not capture 0.0.0.0/8")
		}
	})

	t.Run("both sets and explicit prefixes", func(t *testing.T) {
		got := mustRoutes(t, Options{
			AutoRoute:                true,
			Inet4Address:             []netip.Prefix{v4},
			Inet6Address:             []netip.Prefix{v6},
			Inet4RouteAddress:        []netip.Prefix{include4, netip.MustParsePrefix("10.0.0.0/16")},
			Inet6RouteAddress:        []netip.Prefix{include6},
			Inet4RouteExcludeAddress: []netip.Prefix{hole4},
			Inet6RouteExcludeAddress: []netip.Prefix{hole6},
		})
		assertComplement(t, include4, []netip.Prefix{hole4}, v4Only(got))
		assertComplement(t, include6, []netip.Prefix{hole6}, v6Only(got))
	})

	t.Run("explicit default stays one prefix", func(t *testing.T) {
		got := mustRoutes(t, Options{
			AutoRoute:         true,
			Inet4Address:      []netip.Prefix{v4},
			Inet4RouteAddress: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		})
		if len(got) != 1 || got[0] != netip.MustParsePrefix("0.0.0.0/0") {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("route address replaces default split", func(t *testing.T) {
		got := mustRoutes(t, Options{
			AutoRoute:         true,
			Inet4Address:      []netip.Prefix{v4},
			Inet4RouteAddress: []netip.Prefix{include4},
		})
		if len(got) != 1 || got[0] != include4 {
			t.Fatalf("got %v", got)
		}
		if covers(got, netip.MustParseAddr("1.1.1.1")) {
			t.Fatal("unlisted address must bypass")
		}
	})

	t.Run("full exclude", func(t *testing.T) {
		got := mustRoutes(t, Options{
			Inet4Address:             []netip.Prefix{v4},
			Inet4RouteAddress:        []netip.Prefix{include4},
			Inet4RouteExcludeAddress: []netip.Prefix{include4},
		})
		if len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("empty", func(t *testing.T) {
		got := mustRoutes(t, Options{AutoRoute: true})
		if len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("default split", func(t *testing.T) {
		got := mustRoutes(t, Options{
			AutoRoute:    true,
			Inet4Address: []netip.Prefix{v4},
			Inet6Address: []netip.Prefix{v6},
		})
		if len(got) != 16 {
			t.Fatalf("8 IPv4 + 8 IPv6 split prefixes, got %d: %v", len(got), got)
		}
	})

	t.Run("network extension uses one default", func(t *testing.T) {
		ranges, err := (&Options{
			AutoRoute:    true,
			Inet4Address: []netip.Prefix{v4},
		}).BuildAutoRouteRanges(true)
		if err != nil {
			t.Fatal(err)
		}
		if len(ranges) != 1 || ranges[0].Bits() != 0 {
			t.Fatalf("got %v", ranges)
		}
	})
}

func TestBuildAutoRouteRangesLinuxDefault(t *testing.T) {
	withSubRanges(t, false)
	got := mustRoutes(t, Options{
		AutoRoute:    true,
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
	})
	if len(got) != 1 || got[0] != netip.MustParsePrefix("0.0.0.0/0") {
		t.Fatalf("got %v", got)
	}
}

func TestBuildAutoRouteRangesComplement(t *testing.T) {
	parent := netip.MustParsePrefix("1.0.0.0/8")
	hole := netip.MustParsePrefix("1.2.3.0/24")
	got := mustRoutes(t, Options{
		Inet4Address:             []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		Inet4RouteAddress:        []netip.Prefix{parent},
		Inet4RouteExcludeAddress: []netip.Prefix{hole, netip.MustParsePrefix("1.2.3.0/25")},
	})
	assertComplement(t, parent, []netip.Prefix{hole}, got)
	if covers(got, netip.MustParseAddr("1.2.3.10")) {
		t.Fatal("excluded address is covered")
	}
	if !covers(got, netip.MustParseAddr("1.2.2.255")) || !covers(got, netip.MustParseAddr("1.2.4.0")) {
		t.Fatal("neighbor outside the hole is not covered")
	}
}

func TestBuildAutoRouteRangesScale(t *testing.T) {
	parent := netip.MustParsePrefix("1.0.0.0/8")
	adjacent := make([]netip.Prefix, 4096)
	base := binary.BigEndian.Uint32([]byte{1, 0, 0, 0})
	for i := range adjacent {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], base+uint32(i<<8))
		adjacent[i] = netip.PrefixFrom(netip.AddrFrom4(raw), 24)
	}
	start := time.Now()
	got := mustRoutes(t, Options{
		Inet4Address:             []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		Inet4RouteAddress:        []netip.Prefix{parent},
		Inet4RouteExcludeAddress: adjacent,
	})
	t.Logf("adjacent exclude input 1+%d output %d build %s", len(adjacent), len(got), time.Since(start))
	assertComplement(t, parent, adjacent, got)

	isolated := make([]netip.Prefix, 4096)
	for i := range isolated {
		isolated[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{1, byte(i >> 8), byte(i), 1}), 32)
	}
	start = time.Now()
	got = mustRoutes(t, Options{
		Inet4Address:             []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		Inet4RouteAddress:        []netip.Prefix{parent},
		Inet4RouteExcludeAddress: isolated,
	})
	elapsed := time.Since(start)
	t.Logf("isolated exclude input 1+%d output %d build %s", len(isolated), len(got), elapsed)
	if covers(got, isolated[0].Addr()) || covers(got, isolated[len(isolated)/2].Addr()) {
		t.Fatal("isolated exclude address is covered")
	}
	if !covers(got, netip.MustParseAddr("1.255.255.255")) {
		t.Fatal("address outside the holes is not covered")
	}
	if elapsed > 30*time.Second {
		t.Fatalf("build took %s", elapsed)
	}
}

func withSubRanges(t *testing.T, enabled bool) {
	t.Helper()
	previous := autoRouteUseSubRanges
	autoRouteUseSubRanges = enabled
	t.Cleanup(func() { autoRouteUseSubRanges = previous })
}

func mustRoutes(t *testing.T, options Options) []netip.Prefix {
	t.Helper()
	got, err := options.BuildAutoRouteRanges(false)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func assertComplement(t *testing.T, parent netip.Prefix, holes, got []netip.Prefix) {
	t.Helper()
	for i := range got {
		if !prefixInside(parent, got[i]) {
			t.Fatalf("%s is outside %s", got[i], parent)
		}
		for j := i + 1; j < len(got); j++ {
			if got[i].Overlaps(got[j]) {
				t.Fatalf("%s overlaps %s", got[i], got[j])
			}
		}
	}
	for _, hole := range holes {
		if covers(got, hole.Addr()) {
			t.Fatalf("excluded %s is covered", hole)
		}
		before, beforeOK := prevAddr(hole.Masked().Addr())
		if beforeOK && parent.Contains(before) && !coversPrefixList(holes, before) && !covers(got, before) {
			t.Fatalf("neighbor %s before %s is not covered", before, hole)
		}
		last := prefixLast(hole)
		after := last.Next()
		if after.IsValid() && parent.Contains(after) && !coversPrefixList(holes, after) && !covers(got, after) {
			t.Fatalf("neighbor %s after %s is not covered", after, hole)
		}
	}
	var wantB, gotB netipx.IPSetBuilder
	wantB.AddPrefix(parent)
	for _, hole := range holes {
		wantB.RemovePrefix(hole)
	}
	for _, prefix := range got {
		gotB.AddPrefix(prefix)
	}
	want, err := wantB.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := gotB.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	if !actual.Equal(want) {
		t.Fatalf("complement has %d prefixes, want %d", len(actual.Prefixes()), len(want.Prefixes()))
	}
}

func covers(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func coversPrefixList(prefixes []netip.Prefix, addr netip.Addr) bool {
	return covers(prefixes, addr)
}

func v4Only(prefixes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			out = append(out, prefix)
		}
	}
	return out
}

func v6Only(prefixes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, prefix := range prefixes {
		if prefix.Addr().Is6() {
			out = append(out, prefix)
		}
	}
	return out
}

func prefixInside(parent, child netip.Prefix) bool {
	child = child.Masked()
	if child.Addr().BitLen() != parent.Addr().BitLen() || child.Bits() < parent.Bits() {
		return false
	}
	return parent.Contains(child.Addr()) && parent.Contains(prefixLast(child))
}

func prefixLast(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		raw := prefix.Addr().As4()
		host := 32 - prefix.Bits()
		base := binary.BigEndian.Uint32(raw[:])
		last := uint32(^uint32(0))
		if host < 32 {
			last = base | (uint32(1)<<host - 1)
		}
		binary.BigEndian.PutUint32(raw[:], last)
		return netip.AddrFrom4(raw)
	}
	raw := prefix.Addr().As16()
	host := 128 - prefix.Bits()
	for i := 15; i >= 0 && host > 0; i-- {
		if host >= 8 {
			raw[i] = 0xff
			host -= 8
			continue
		}
		raw[i] |= byte(1<<uint(host)) - 1
		host = 0
	}
	return netip.AddrFrom16(raw)
}

func prevAddr(addr netip.Addr) (netip.Addr, bool) {
	if !addr.IsValid() {
		return netip.Addr{}, false
	}
	if addr.Is4() {
		raw := addr.As4()
		value := binary.BigEndian.Uint32(raw[:])
		if value == 0 {
			return netip.Addr{}, false
		}
		binary.BigEndian.PutUint32(raw[:], value-1)
		return netip.AddrFrom4(raw), true
	}
	raw := addr.As16()
	for i := 15; i >= 0; i-- {
		if raw[i] > 0 {
			raw[i]--
			return netip.AddrFrom16(raw), true
		}
		raw[i] = 0xff
	}
	return netip.Addr{}, false
}
