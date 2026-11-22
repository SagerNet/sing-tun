package tun

import (
	"crypto/rand"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
)

const (
	memoryTunDefaultBatchSize = 128
	memoryTunMaxPacketSize    = 65535
)

const (
	memoryTunOffloadChecksum uint32 = 1 << iota
	memoryTunOffloadTCPSegmentation
	memoryTunOffloadUDPSegmentation
)

type MemoryTunOptions struct {
	MTU                    int
	Headroom               int
	RearSpace              int
	BatchSize              int
	Outbound               func(packets []*buf.Buffer)
	Route                  func(packet []byte) *OutboundQueue
	Ethernet               bool
	VirtioNetHeader        bool
	ChecksumOffload        bool
	TCPSegmentationOffload bool
	UDPSegmentationOffload bool
	GatewayMAC             net.HardwareAddr
	PeerMAC                net.HardwareAddr
	Inet6Prefix            []netip.Prefix
}

type MemoryTun struct {
	mtu              atomic.Int32
	headroom         int
	rearSpace        int
	batchSize        int
	route            func(packet []byte) *OutboundQueue
	ethernet         bool
	virtioHeader     bool
	linkHeaderLength int
	offload          atomic.Uint32
	gatewayMAC       [header.EthernetAddressSize]byte
	peerMAC          atomic.Uint64
	peerMACFixed     bool
	inet6Prefix      []netip.Prefix
	platformIO       atomic.Pointer[goMemoryIO]
	attached         atomic.Bool
	closed           atomic.Bool
	inboundAccess    sync.Mutex
	inbound          goPacketRing
	inboundWritable  *sync.Cond
	inboundHeadroom  atomic.Int32
	inboundRearSpace atomic.Int32
	outbound         *OutboundQueue
	writableAccess   sync.Mutex
	writable         []*OutboundQueue
	writablePending  atomic.Bool
}

func NewMemoryTun(options MemoryTunOptions) *MemoryTun {
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = memoryTunDefaultBatchSize
	}
	memoryTun := &MemoryTun{
		headroom:     options.Headroom,
		rearSpace:    options.RearSpace,
		batchSize:    batchSize,
		route:        options.Route,
		ethernet:     options.Ethernet,
		virtioHeader: options.VirtioNetHeader,
		inet6Prefix:  options.Inet6Prefix,
		inbound:      newGoPacketRing(4 * batchSize),
	}
	if options.VirtioNetHeader {
		memoryTun.linkHeaderLength += goVirtioHeaderLength
	}
	if options.Ethernet {
		memoryTun.linkHeaderLength += header.EthernetMinimumSize
		if len(options.GatewayMAC) == header.EthernetAddressSize {
			memoryTun.gatewayMAC = [header.EthernetAddressSize]byte(options.GatewayMAC)
		} else {
			rand.Read(memoryTun.gatewayMAC[:])
			memoryTun.gatewayMAC[0] = memoryTun.gatewayMAC[0]&^1 | 2
		}
		if len(options.PeerMAC) == header.EthernetAddressSize {
			memoryTun.peerMACFixed = true
			memoryTun.peerMAC.Store(goPackMAC(options.PeerMAC))
		}
	}
	outboundHandler := options.Outbound
	if outboundHandler == nil {
		outboundHandler = buf.ReleaseMulti
	}
	memoryTun.SetOffload(options.ChecksumOffload, options.TCPSegmentationOffload, options.UDPSegmentationOffload)
	memoryTun.inboundWritable = sync.NewCond(&memoryTun.inboundAccess)
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

func (t *MemoryTun) SetOffload(checksum bool, tcpSegmentation bool, udpSegmentation bool) {
	var offload uint32
	if t.virtioHeader && checksum {
		offload = memoryTunOffloadChecksum
		if tcpSegmentation {
			offload |= memoryTunOffloadTCPSegmentation
		}
		if udpSegmentation {
			offload |= memoryTunOffloadUDPSegmentation
		}
	}
	t.offload.Store(offload)
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
	return t.writePackets(packets, false)
}

func (t *MemoryTun) WaitWritePackets(packets [][]byte) error {
	_, err := t.writePackets(packets, true)
	return err
}

func (t *MemoryTun) writePackets(packets [][]byte, wait bool) (int, error) {
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
	accepted := 0
	notify := false
	for _, packet := range packets {
		if len(packet) == 0 || len(packet) > t.linkHeaderLength+memoryTunMaxPacketSize {
			continue
		}
		for wait && t.inbound.full() {
			if notify {
				notify = false
				t.inboundAccess.Unlock()
				t.wakeEngine()
				t.inboundAccess.Lock()
			} else {
				t.inboundWritable.Wait()
			}
			if t.closed.Load() {
				t.inboundAccess.Unlock()
				return accepted, os.ErrClosed
			}
			if !t.attached.Load() {
				t.inboundAccess.Unlock()
				return accepted, nil
			}
			headroom = int(t.inboundHeadroom.Load())
			rearSpace = int(t.inboundRearSpace.Load())
		}
		if t.inbound.full() {
			continue
		}
		if t.inbound.empty() {
			notify = true
		}
		buffer := buf.NewSize(headroom + len(packet) + rearSpace)
		buffer.Resize(headroom, 0)
		buffer.Write(packet)
		t.inbound.push(buffer, nil, 0)
		accepted++
	}
	t.inboundAccess.Unlock()
	if notify {
		t.wakeEngine()
	}
	return accepted, nil
}

func (t *MemoryTun) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	t.inboundAccess.Lock()
	t.inbound.releaseAll()
	t.inboundWritable.Broadcast()
	t.inboundAccess.Unlock()
	t.outbound.Close()
	t.wakeEngine()
	return nil
}

func (t *MemoryTun) wakeEngine() {
	platformIO := t.platformIO.Load()
	if platformIO != nil {
		platformIO.wake()
	}
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
	t.wakeEngine()
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
