package tun

const (
	goReceiveCapacityBase    = 32 << 10
	goReceiveCapacityMax     = 256 << 10
	goTransmitCapacity       = 512 << 10
	goReceiveBatchMin        = 4
	goReadBatch              = 32
	goDescriptorRingCapacity = 512
	goReassemblyEntries      = 4
	goSlabPoolLowWater       = 8
	goDescriptorPoolLowWater = 16
)

func goFlowCapacity() int {
	return 1024
}
