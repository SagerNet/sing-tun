package tun

import "time"

const (
	goDefaultBufferProfile   = BufferProfileCompact
	goEngineBurstBytes       = 256 << 10
	goFlowCapacity           = 1024
	goReceiveBatchMin        = 4
	goReadBatch              = 32
	goReadBufferIdle         = 250 * time.Millisecond
	goDescriptorRingCapacity = 512
	goReassemblyEntries      = 4
	goSlabPoolLowWater       = 8
)
