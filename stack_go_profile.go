package tun

import "time"

type goProfile struct {
	receiveBase       uint64
	receiveMax        uint64
	transmitMax       uint64
	engineBurstBytes  int
	flowCapacity      int
	receiveBatchMin   int
	readBatch         int
	readBufferIdle    time.Duration
	descriptorBlocks  uint32
	reassemblyEntries int
	slabPoolLowWater  int
	udpNATMax         uint32
}

var (
	goCompactProfile = goProfile{
		receiveBase:       32 << 10,
		receiveMax:        256 << 10,
		transmitMax:       512 << 10,
		engineBurstBytes:  256 << 10,
		flowCapacity:      1024,
		receiveBatchMin:   4,
		readBatch:         32,
		readBufferIdle:    250 * time.Millisecond,
		descriptorBlocks:  8,
		reassemblyEntries: 4,
		slabPoolLowWater:  8,
		udpNATMax:         4096,
	}
	goFullProfile = goProfile{
		receiveBase:       64 << 10,
		receiveMax:        4 << 20,
		transmitMax:       2 << 20,
		engineBurstBytes:  1 << 20,
		flowCapacity:      16384,
		receiveBatchMin:   8,
		readBatch:         64,
		readBufferIdle:    time.Second,
		descriptorBlocks:  32,
		reassemblyEntries: 8,
		slabPoolLowWater:  128,
		udpNATMax:         16384,
	}
)
