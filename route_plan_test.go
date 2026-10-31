package tun

import (
	"net/netip"
	"testing"

	"go4.org/netipx"
)

func TestPlanFamilyUsesGatewayForHoles(t *testing.T) {
	capture := []netip.Prefix{netip.MustParsePrefix("1.0.0.0/8")}
	exclude := []netip.Prefix{netip.MustParsePrefix("1.2.3.0/24")}
	toTun, toGateway, err := planFamily(capture, exclude)
	if err != nil {
		t.Fatal(err)
	}
	if len(toTun) != 1 || toTun[0] != capture[0] {
		t.Fatalf("tun routes = %v", toTun)
	}
	if len(toGateway) != 1 || toGateway[0] != exclude[0] {
		t.Fatalf("gateway routes = %v", toGateway)
	}
	assertSameDelivery(t, capture, exclude, toTun, toGateway)
}

func TestPlanFamilyKeepsComplementWhenSmaller(t *testing.T) {
	capture := []netip.Prefix{netip.MustParsePrefix("1.0.0.0/8")}
	// Exclude everything in the /8 except one /24. The complement is that
	// single prefix; listing the excluded remainder would be much larger.
	var exclude []netip.Prefix
	var builder netipx.IPSetBuilder
	builder.AddPrefix(capture[0])
	builder.RemovePrefix(netip.MustParsePrefix("1.2.3.0/24"))
	removed, err := builder.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	exclude = removed.Prefixes()
	toTun, toGateway, err := planFamily(capture, exclude)
	if err != nil {
		t.Fatal(err)
	}
	if len(toGateway) != 0 {
		t.Fatalf("expected complement plan, gateway routes = %d", len(toGateway))
	}
	if len(toTun) != 1 || toTun[0] != netip.MustParsePrefix("1.2.3.0/24") {
		t.Fatalf("tun routes = %v", toTun)
	}
	assertSameDelivery(t, capture, exclude, toTun, toGateway)
}

func TestPlanFamilyDropsFullyExcludedCapture(t *testing.T) {
	capture := []netip.Prefix{netip.MustParsePrefix("1.0.0.0/8")}
	exclude := []netip.Prefix{netip.MustParsePrefix("1.0.0.0/8")}
	toTun, toGateway, err := planFamily(capture, exclude)
	if err != nil {
		t.Fatal(err)
	}
	if len(toTun) != 0 || len(toGateway) != 0 {
		t.Fatalf("fully excluded capture installed tun=%v gateway=%v", toTun, toGateway)
	}
}

func TestPlanFamilyIsolatedHolesStaySmall(t *testing.T) {
	capture := []netip.Prefix{netip.MustParsePrefix("1.0.0.0/8")}
	exclude := make([]netip.Prefix, 4096)
	for i := range exclude {
		exclude[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{1, byte(i >> 8), byte(i), 1}), 32)
	}
	toTun, toGateway, err := planFamily(capture, exclude)
	if err != nil {
		t.Fatal(err)
	}
	if len(toTun) != 1 || len(toGateway) != len(exclude) {
		t.Fatalf("tun=%d gateway=%d", len(toTun), len(toGateway))
	}
	complement, err := subtractPrefixes(capture, exclude)
	if err != nil {
		t.Fatal(err)
	}
	if len(complement) <= len(toTun)+len(toGateway) {
		t.Fatalf("complement %d should be larger than exception %d", len(complement), len(toTun)+len(toGateway))
	}
	assertSameDelivery(t, capture, exclude, toTun, toGateway)
}

func TestPrefixMask(t *testing.T) {
	if got := ipv4Mask(0); got != [4]byte{} {
		t.Fatalf("0: %v", got)
	}
	if got := ipv4Mask(1); got != [4]byte{0x80} {
		t.Fatalf("1: %v", got)
	}
	if got := ipv4Mask(24); got != [4]byte{255, 255, 255, 0} {
		t.Fatalf("24: %v", got)
	}
	if got := ipv4Mask(32); got != [4]byte{255, 255, 255, 255} {
		t.Fatalf("32: %v", got)
	}
	got6 := ipv6Mask(9)
	if got6[0] != 0xff || got6[1] != 0x80 || got6[2] != 0 {
		t.Fatalf("9: %v", got6[:3])
	}
}

func assertSameDelivery(t *testing.T, capture, exclude, toTun, toGateway []netip.Prefix) {
	t.Helper()
	want, err := subtractPrefixes(capture, exclude)
	if err != nil {
		t.Fatal(err)
	}
	got, err := subtractPrefixes(toTun, toGateway)
	if err != nil {
		t.Fatal(err)
	}
	wantSet, err := prefixSet(want)
	if err != nil {
		t.Fatal(err)
	}
	gotSet, err := prefixSet(got)
	if err != nil {
		t.Fatal(err)
	}
	if !wantSet.Equal(gotSet) {
		t.Fatalf("delivery mismatch: want %d prefixes, got %d", len(wantSet.Prefixes()), len(gotSet.Prefixes()))
	}
}
