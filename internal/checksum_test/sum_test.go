package checksum_test

import (
	"crypto/rand"
	mathrand "math/rand"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/internal/tschecksum"
)

func TestChecksumDifferential(t *testing.T) {
	lengths := make([]int, 0, 2054)
	for length := 0; length <= 2049; length++ {
		lengths = append(lengths, length)
	}
	lengths = append(lengths, 4096, 8500, 9000, 65535)
	backing := make([]byte, 65535+16)
	for _, pattern := range []string{"random", "ones"} {
		if pattern == "random" {
			rand.Read(backing)
		} else {
			for i := range backing {
				backing[i] = 0xff
			}
		}
		for _, length := range lengths {
			for offset := range 16 {
				data := backing[offset : offset+length]
				initial := uint16(mathrand.Uint32())
				expected := checksum.ChecksumDefault(data, initial)
				actual := tschecksum.Checksum(data, initial)
				if actual != expected {
					t.Fatalf("mismatch: pattern=%s length=%d offset=%d initial=%#04x got %#04x want %#04x",
						pattern, length, offset, initial, actual, expected)
				}
			}
		}
	}
}
