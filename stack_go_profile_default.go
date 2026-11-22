//go:build !ios

package tun

import "time"

const (
	goDefaultBufferProfile   = BufferProfileFull
	goEngineBurstBytes       = 1 << 20
	goFlowCapacity           = 16384
	goReceiveBatchMin        = 8
	goReadBatch              = 64
	goReadBufferIdle         = time.Second
	goDescriptorRingCapacity = 2048
	goReassemblyEntries      = 8
	goSlabPoolLowWater       = 128
)
