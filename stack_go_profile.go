package tun

type goBufferCapacity struct {
	receiveBase uint64
	receiveMax  uint64
	transmitMax uint64
}

var (
	goCompactBuffers = goBufferCapacity{receiveBase: 32 << 10, receiveMax: 256 << 10, transmitMax: 512 << 10}
	goFullBuffers    = goBufferCapacity{receiveBase: 64 << 10, receiveMax: 4 << 20, transmitMax: 2 << 20}
)
