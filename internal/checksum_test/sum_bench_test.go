package checksum_test

import (
	"crypto/rand"
	"strconv"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/internal/tschecksum"
)

var benchSizes = []int{64, 128, 512, 1460, 8500, 65535}

func benchChecksum(b *testing.B, size int, fn func([]byte, uint16) uint16) {
	data := make([]byte, size)
	rand.Read(data)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn(data, 0)
	}
}

func BenchmarkTsChecksumSizes(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) { benchChecksum(b, size, tschecksum.Checksum) })
	}
}

func BenchmarkGChecksumSizes(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) { benchChecksum(b, size, checksum.ChecksumDefault) })
	}
}

func BenchmarkTsChecksum(b *testing.B) {
	packet := make([][]byte, 1000)
	for i := range 1000 {
		packet[i] = make([]byte, 1500)
		rand.Read(packet[i])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tschecksum.Checksum(packet[i%1000], 0)
	}
}

func BenchmarkGChecksum(b *testing.B) {
	packet := make([][]byte, 1000)
	for i := range 1000 {
		packet[i] = make([]byte, 1500)
		rand.Read(packet[i])
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checksum.ChecksumDefault(packet[i%1000], 0)
	}
}
