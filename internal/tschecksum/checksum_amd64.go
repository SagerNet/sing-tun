package tschecksum

import "golang.org/x/sys/cpu"

var (
	useAVX2 = cpu.X86.HasAVX && cpu.X86.HasAVX2 && cpu.X86.HasBMI2
	useSSE2 = cpu.X86.HasSSE2
)

// Checksum computes an IP checksum starting with the provided initial value.
// The length of data should be at least 128 bytes for best performance. Smaller
// buffers will still compute a correct result.
func Checksum(data []byte, initial uint16) uint16 {
	if useAVX2 {
		return checksumAVX2(data, initial)
	}
	if useSSE2 {
		return checksumSSE2(data, initial)
	}
	return checksumAMD64(data, initial)
}
