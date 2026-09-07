//go:build !ios

package tun

import "github.com/sagernet/sing/common/memory"

const (
	goReceiveCapacityBase    = 64 << 10
	goReceiveCapacityMax     = 1 << 20
	goTransmitCapacity       = 512 << 10
	goReceiveBatchMin        = 8
	goReadBatch              = 64
	goDescriptorRingCapacity = 2048
	goReassemblyEntries      = 8
	goSlabPoolLowWater       = 128
	goDescriptorPoolLowWater = 64
)

func goFlowCapacity() int {
	totalMemory := memory.Total()
	if totalMemory == 0 {
		return 16384
	}
	return int(min(max(totalMemory/65536, 4096), 16384))
}
