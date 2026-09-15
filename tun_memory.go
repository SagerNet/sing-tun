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
	Outbound  func(packets []*buf.Buffer) error
}

type MemoryTun struct {
	mtu              atomic.Int32
	headroom         int
	rearSpace        int
	batchSize        int
	outboundHandler  func(packets []*buf.Buffer) error
	attached         atomic.Bool
	closed           atomic.Bool
	inboundAccess    sync.Mutex
	inbound          goPacketRing
	inboundHeadroom  atomic.Int32
	inboundRearSpace atomic.Int32
	outboundAccess   sync.Mutex
	control          goPacketRing
	datagram         goPacketRing
	data             goPacketRing
	dataTurn         bool
	dataQueued       atomic.Int32
	transmitInterest bool
	transmitWritable bool
	engineWake       goSignal
	readerWake       goSignal
	closeSignal      chan struct{}
}

func NewMemoryTun(options MemoryTunOptions) *MemoryTun {
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = memoryTunDefaultBatchSize
	}
	memoryTun := &MemoryTun{
		headroom:        options.Headroom,
		rearSpace:       options.RearSpace,
		batchSize:       batchSize,
		outboundHandler: options.Outbound,
		inbound:         newGoPacketRing(4 * batchSize),
		control:         newGoPacketRing(4 * batchSize),
		datagram:        newGoPacketRing(4 * batchSize),
		data:            newGoPacketRing(2 * batchSize),
		engineWake:      make(goSignal, 1),
		readerWake:      make(goSignal, 1),
		closeSignal:     make(chan struct{}),
	}
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
	buffers := [1][]byte{p}
	var sizes [1]int
	_, err := t.ReadPackets(buffers[:], sizes[:], 0)
	if err != nil {
		return 0, err
	}
	return sizes[0], nil
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

func (t *MemoryTun) ReadPackets(buffers [][]byte, sizes []int, offset int) (int, error) {
	if len(buffers) == 0 {
		return 0, nil
	}
	if t.outboundHandler != nil {
		return 0, os.ErrInvalid
	}
	for {
		t.outboundAccess.Lock()
		count := 0
		for count < len(buffers) {
			buffer, owner, segmentEnd := t.popOutboundLocked()
			if buffer == nil {
				break
			}
			packet := buffer.Bytes()
			if owner != nil {
				owner.frameDequeued(len(packet), segmentEnd)
			}
			target := buffers[count][offset:]
			if len(packet) > len(target) {
				buffer.Release()
				continue
			}
			sizes[count] = copy(target, packet)
			buffer.Release()
			count++
		}
		wakeEngine := t.takeTransmitWritableLocked()
		t.outboundAccess.Unlock()
		if wakeEngine {
			t.engineWake.notify()
		}
		if count > 0 {
			return count, nil
		}
		if t.closed.Load() {
			return 0, os.ErrClosed
		}
		select {
		case <-t.readerWake:
		case <-t.closeSignal:
		}
	}
}

func (t *MemoryTun) popOutboundLocked() (*buf.Buffer, *GoConn, uint64) {
	if !t.control.empty() {
		return t.control.pop()
	}
	if !t.datagram.empty() && (t.data.empty() || !t.dataTurn) {
		t.dataTurn = true
		return t.datagram.pop()
	}
	if !t.data.empty() {
		t.dataTurn = false
		t.dataQueued.Add(-1)
		return t.data.pop()
	}
	return nil, nil, 0
}

func (t *MemoryTun) takeTransmitWritableLocked() bool {
	if !t.transmitInterest || t.data.full() {
		return false
	}
	t.transmitInterest = false
	t.transmitWritable = true
	return true
}

func (t *MemoryTun) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	t.inboundAccess.Lock()
	t.inbound.releaseAll()
	t.inboundAccess.Unlock()
	t.outboundAccess.Lock()
	t.control.releaseAll()
	t.datagram.releaseAll()
	t.data.releaseAll()
	t.dataQueued.Store(0)
	t.outboundAccess.Unlock()
	close(t.closeSignal)
	return nil
}

func (t *MemoryTun) newOutboundPacket(length int) *buf.Buffer {
	packet := buf.NewSize(t.headroom + length + t.rearSpace)
	packet.Resize(t.headroom, 0)
	return packet
}

type goPacketRing struct {
	packets     []*buf.Buffer
	owners      []*GoConn
	segmentEnds []uint64
	head        int
	count       int
}

func newGoPacketRing(capacity int) goPacketRing {
	return goPacketRing{
		packets:     make([]*buf.Buffer, capacity),
		owners:      make([]*GoConn, capacity),
		segmentEnds: make([]uint64, capacity),
	}
}

func (r *goPacketRing) empty() bool {
	return r.count == 0
}

func (r *goPacketRing) full() bool {
	return r.count == len(r.packets)
}

func (r *goPacketRing) push(packet *buf.Buffer, owner *GoConn, segmentEnd uint64) {
	index := (r.head + r.count) % len(r.packets)
	r.packets[index] = packet
	r.owners[index] = owner
	r.segmentEnds[index] = segmentEnd
	r.count++
}

func (r *goPacketRing) pop() (*buf.Buffer, *GoConn, uint64) {
	packet := r.packets[r.head]
	owner := r.owners[r.head]
	segmentEnd := r.segmentEnds[r.head]
	r.packets[r.head] = nil
	r.owners[r.head] = nil
	r.segmentEnds[r.head] = 0
	r.head = (r.head + 1) % len(r.packets)
	r.count--
	return packet, owner, segmentEnd
}

func (r *goPacketRing) releaseAll() {
	for !r.empty() {
		packet, owner, segmentEnd := r.pop()
		if owner != nil {
			owner.frameDequeued(packet.Len(), segmentEnd)
		}
		packet.Release()
	}
}
