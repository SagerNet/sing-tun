package tun

import (
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
)

const (
	memoryTunDefaultBatchSize = 128
	memoryTunMaxPacketSize    = 65535
)

type MemoryTunOptions struct {
	MTU       int
	Headroom  int
	RearSpace int
	BatchSize int
	Outbound  func(packets []*buf.Buffer)
	Route     func(packet []byte) *OutboundQueue
}

type MemoryTun struct {
	mtu              atomic.Int32
	headroom         int
	rearSpace        int
	batchSize        int
	route            func(packet []byte) *OutboundQueue
	attached         atomic.Bool
	closed           atomic.Bool
	inboundAccess    sync.Mutex
	inbound          goPacketRing
	inboundHeadroom  atomic.Int32
	inboundRearSpace atomic.Int32
	outbound         *OutboundQueue
	writableAccess   sync.Mutex
	writable         []*OutboundQueue
	writablePending  atomic.Bool
	engineWake       goSignal
	closeSignal      chan struct{}
}

func NewMemoryTun(options MemoryTunOptions) *MemoryTun {
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = memoryTunDefaultBatchSize
	}
	memoryTun := &MemoryTun{
		headroom:    options.Headroom,
		rearSpace:   options.RearSpace,
		batchSize:   batchSize,
		route:       options.Route,
		inbound:     newGoPacketRing(4 * batchSize),
		engineWake:  make(goSignal, 1),
		closeSignal: make(chan struct{}),
	}
	outboundHandler := options.Outbound
	if outboundHandler == nil {
		outboundHandler = buf.ReleaseMulti
	}
	memoryTun.outbound = memoryTun.NewOutboundQueue(outboundHandler)
	memoryTun.mtu.Store(int32(options.MTU))
	return memoryTun
}

func (t *MemoryTun) Name() (string, error) {
	return "memory", nil
}

func (t *MemoryTun) Start() error {
	return nil
}

func (t *MemoryTun) UpdateRouteOptions(tunOptions Options) error {
	return nil
}

func (t *MemoryTun) MTU() int {
	return int(t.mtu.Load())
}

func (t *MemoryTun) UpdateMTU(mtu int) {
	t.mtu.Store(int32(mtu))
}

func (t *MemoryTun) Read(p []byte) (int, error) {
	return 0, os.ErrInvalid
}

func (t *MemoryTun) Write(p []byte) (int, error) {
	packets := [1][]byte{p}
	_, err := t.WritePackets(packets[:])
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *MemoryTun) WritePackets(packets [][]byte) (int, error) {
	t.inboundAccess.Lock()
	if t.closed.Load() {
		t.inboundAccess.Unlock()
		return 0, os.ErrClosed
	}
	if !t.attached.Load() {
		t.inboundAccess.Unlock()
		return 0, nil
	}
	headroom := int(t.inboundHeadroom.Load())
	rearSpace := int(t.inboundRearSpace.Load())
	wasEmpty := t.inbound.empty()
	accepted := 0
	for _, packet := range packets {
		if len(packet) == 0 || len(packet) > memoryTunMaxPacketSize {
			continue
		}
		if t.inbound.full() {
			continue
		}
		buffer := buf.NewSize(headroom + len(packet) + rearSpace)
		buffer.Resize(headroom, 0)
		buffer.Write(packet)
		t.inbound.push(buffer, nil, 0)
		accepted++
	}
	t.inboundAccess.Unlock()
	if wasEmpty && accepted > 0 {
		t.engineWake.notify()
	}
	return accepted, nil
}

func (t *MemoryTun) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	t.inboundAccess.Lock()
	t.inbound.releaseAll()
	t.inboundAccess.Unlock()
	t.outbound.Close()
	close(t.closeSignal)
	return nil
}

func (t *MemoryTun) queueWritable(queue *OutboundQueue) {
	t.writableAccess.Lock()
	if queue.writableQueued {
		t.writableAccess.Unlock()
		return
	}
	queue.writableQueued = true
	t.writable = append(t.writable, queue)
	t.writablePending.Store(true)
	t.writableAccess.Unlock()
	t.engineWake.notify()
}

func (t *MemoryTun) takeWritable(spare []*OutboundQueue) []*OutboundQueue {
	if !t.writablePending.Swap(false) {
		return spare
	}
	t.writableAccess.Lock()
	queues := t.writable
	t.writable = spare
	for _, queue := range queues {
		queue.writableQueued = false
	}
	t.writableAccess.Unlock()
	return queues
}

func (t *MemoryTun) newOutboundPacket(length int) *buf.Buffer {
	packet := buf.NewSize(t.headroom + length + t.rearSpace)
	packet.Resize(t.headroom, 0)
	return packet
}
