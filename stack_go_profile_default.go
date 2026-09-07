//go:build !ios

package tun

const (
	goReceiveCapacityBase    = 64 << 10
	goReceiveCapacityMax     = 4 << 20
	goTransmitCapacityMax    = 2 << 20
	goEngineBurstBytes       = 1 << 20
	goFlowCapacity           = 16384
	goReceiveBatchMin        = 8
	goReadBatch              = 64
	goDescriptorRingCapacity = 2048
	goReassemblyEntries      = 8
	goSlabPoolLowWater       = 128
	goDescriptorPoolLowWater = 64
)
