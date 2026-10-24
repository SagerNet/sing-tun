//go:build freebsd

package tun

import "testing"

func TestTunRouteFIB(t *testing.T) {
	if got := tunRouteFIB(Options{}); got != DefaultIPRoute2TableIndex+1 {
		t.Fatalf("default tun FIB = %d, want %d", got, DefaultIPRoute2TableIndex+1)
	}
	// A configured index of 1 must not select table 1 for the tun default.
	if got := tunRouteFIB(Options{IPRoute2TableIndex: 1}); got != 2 {
		t.Fatalf("tun FIB for index 1 = %d, want 2", got)
	}
	if got := tunRouteFIB(Options{IPRoute2TableIndex: 2022}); got != 2023 {
		t.Fatalf("tun FIB for index 2022 = %d, want 2023", got)
	}
}
