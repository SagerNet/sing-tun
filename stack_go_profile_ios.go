package tun

const (
	goReceiveCapacityBase    = 32 << 10
	goReceiveCapacityMax     = 256 << 10
	goTransmitCapacityMax    = 512 << 10
	goEngineBurstBytes       = 256 << 10
	goFlowCapacity           = 1024
	goReceiveBatchMin        = 4
	goReadBatch              = 32
	goDescriptorRingCapacity = 512
	goReassemblyEntries      = 4
	goSlabPoolLowWater       = 8
	goDescriptorPoolLowWater = 16
)
