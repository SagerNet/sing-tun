package tun

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type goMemoryIO struct {
	stack *Go
	tun   *MemoryTun
	goMemoryPoller
	handed               []*buf.Buffer
	blocked              map[*OutboundQueue]*goBlockedWriters
	writableSpare        []*OutboundQueue
	closeSignal          chan struct{}
	advertiser           sync.WaitGroup
	epoch                time.Time
	solicitationDeadline atomic.Int64
}

func (o *goMemoryIO) start() error {
	err := o.goMemoryPoller.open(-1)
	if err != nil {
		return err
	}
	o.epoch = time.Now()
	o.tun.platformIO.Store(o)
	o.tun.attached.Store(true)
	o.closeSignal = make(chan struct{})
	if o.tun.ethernet && len(o.tun.inet6Prefix) > 0 {
		o.advertiser.Go(o.loopRouterAdvertisement)
	}
	return nil
}

func (o *goMemoryIO) inboundReady() (bool, error) {
	if o.tun.closed.Load() {
		return false, os.ErrClosed
	}
	o.tun.inboundAccess.Lock()
	defer o.tun.inboundAccess.Unlock()
	return !o.tun.inbound.empty(), nil
}

func (o *goMemoryIO) wait(timeout time.Duration, events []goSocketEvent) (bool, int, error) {
	ready, err := o.inboundReady()
	if err != nil {
		return false, 0, err
	}
	if ready {
		timeout = 0
	}
	_, socketCount, err := o.goMemoryPoller.wait(timeout, events)
	if err != nil || ready {
		return ready, socketCount, err
	}
	ready, err = o.inboundReady()
	return ready, socketCount, err
}

func (o *goMemoryIO) readBurst(frames []goFrame, options N.ReadWaitOptions) (int, bool, error) {
	o.releaseReadBuffers()
	if o.tun.closed.Load() {
		return 0, false, os.ErrClosed
	}
	o.tun.inboundHeadroom.Store(int32(options.FrontHeadroom))
	o.tun.inboundRearSpace.Store(int32(options.RearHeadroom))
	o.tun.inboundAccess.Lock()
	popped := 0
	for popped < len(frames) && !o.tun.inbound.empty() {
		buffer, _, _ := o.tun.inbound.pop()
		frames[popped] = goFrame{buffer: buffer}
		popped++
	}
	drained := o.tun.inbound.empty()
	for range popped {
		o.tun.inboundWritable.Signal()
	}
	o.tun.inboundAccess.Unlock()
	count := 0
	for index := range popped {
		buffer := frames[index].buffer
		meta, accepted := o.receiveLink(buffer)
		if !accepted {
			buffer.Release()
			continue
		}
		if options.NeedHeadroom() {
			buffer = options.Copy(buffer)
			options.PostReturn(buffer)
		}
		o.handed = append(o.handed, buffer)
		frames[count] = goFrame{buffer: buffer, meta: meta}
		count++
	}
	clear(frames[count:popped])
	return count, drained, nil
}

func (o *goMemoryIO) releaseReadBuffers() {
	buf.ReleaseMulti(o.handed)
	o.handed = o.handed[:0]
}

type goOutboundClass uint8

const (
	goOutboundControl goOutboundClass = iota
	goOutboundDatagram
	goOutboundData
)

func (o *goMemoryIO) enqueue(segments [][]byte, meta ForwardFrameMeta, class goOutboundClass, owner *GoConn, segmentEnd uint64) error {
	if o.tun.closed.Load() || !o.tun.attached.Load() {
		return os.ErrClosed
	}
	length := 0
	for _, segment := range segments {
		length += len(segment)
	}
	frame := o.tun.newOutboundFrame(length)
	for _, segment := range segments {
		common.Must1(frame.Write(segment))
	}
	packet := frame.From(o.tun.linkHeaderLength)
	if o.tun.ethernet {
		_, resolved := o.tun.linkDestination(packet)
		if !resolved {
			o.solicitPeer(packet)
			frame.Release()
			return errGoFrameDropped
		}
	}
	queue := o.tun.outbound
	if o.tun.route != nil {
		routed := o.tun.route(packet)
		if routed != nil {
			queue = routed
		}
	}
	if owner != nil {
		owner.outboundQueue.Store(queue)
	}
	offload := o.tun.offload.Load()
	segmentation := memoryTunOffloadTCPSegmentation
	if meta.gsoType == goUDPGSOType {
		segmentation = memoryTunOffloadUDPSegmentation
	}
	var fragments [][]byte
	mtu := o.tun.MTU()
	switch {
	case meta.gsoType == goGSONone && length > mtu:
		meta.completeChecksum(packet)
		var fragmentsBuilt bool
		fragments, fragmentsBuilt = goFragmentPacket(&o.stack.fragmentIdentification, packet, mtu)
		if !fragmentsBuilt {
			frame.Release()
			return errGoFrameDropped
		}
	case meta.gsoType != goGSONone && offload&segmentation == 0:
		var segmented bool
		fragments, segmented = goSegmentPacket(packet, meta)
		if !segmented {
			frame.Release()
			return errGoFrameDropped
		}
	default:
		if offload&memoryTunOffloadChecksum == 0 {
			meta.completeChecksum(packet)
		}
		o.tun.encodeLinkHeader(frame.Bytes(), meta)
	}
	return queue.enqueue(frame, fragments, class, owner, segmentEnd)
}

func goSegmentPacket(packet []byte, meta ForwardFrameMeta) ([][]byte, bool) {
	headerLength := int(meta.segmentHeaderLength(packet))
	count := max((len(packet)-headerLength+int(meta.gsoSize)-1)/int(meta.gsoSize), 1)
	if count > goGSOMaxSegments {
		return nil, false
	}
	options := GSOOptions{
		GSOType:    GSOUDPL4,
		HdrLen:     uint16(headerLength),
		CsumStart:  meta.checksumStart,
		CsumOffset: meta.checksumOffset,
		GSOSize:    meta.gsoSize,
		NeedsCsum:  meta.needsChecksum,
	}
	switch meta.gsoType {
	case goGSOTypeIPv4:
		options.GSOType = GSOTCPv4
	case goGSOTypeIPv6:
		options.GSOType = GSOTCPv6
	}
	segmentLength := headerLength + int(meta.gsoSize)
	storage := make([]byte, count*segmentLength)
	segments := make([][]byte, count)
	for index := range segments {
		segments[index] = storage[index*segmentLength : (index+1)*segmentLength]
	}
	sizes := make([]int, count)
	count, err := GSOSplit(packet, options, 0, segments, sizes, 0)
	if err != nil {
		return nil, false
	}
	for index := range count {
		segments[index] = segments[index][:sizes[index]]
	}
	return segments[:count], true
}

func (o *goMemoryIO) writeFrame(frame [][]byte, meta ForwardFrameMeta) error {
	return o.enqueue(frame, meta, goOutboundControl, nil, 0)
}

func (o *goMemoryIO) writePacket(packet []byte, meta ForwardFrameMeta) error {
	segments := [1][]byte{packet}
	return o.enqueue(segments[:], meta, goOutboundControl, nil, 0)
}

func (o *goMemoryIO) writeDatagram(packet []byte, meta ForwardFrameMeta) error {
	segments := [1][]byte{packet}
	return o.enqueue(segments[:], meta, goOutboundDatagram, nil, 0)
}

func (o *goMemoryIO) writeData(frame [][]byte, meta ForwardFrameMeta, owner *GoConn, segmentEnd uint64) error {
	return o.enqueue(frame, meta, goOutboundData, owner, segmentEnd)
}

func (o *goMemoryIO) writePacketBatch(frames []goUDPFrame) error {
	udpSegmentation := o.tun.offload.Load()&memoryTunOffloadUDPSegmentation != 0
	var writeErr error
	var segments [goPacketBatchSize + 1][]byte
	for index := 0; index < len(frames); {
		frame := &frames[index]
		end := index + 1
		meta := frame.meta
		if udpSegmentation && frame.meta.needsChecksum {
			var payloadLength int
			end, payloadLength = goUDPSegmentRun(frames, index)
			if end-index > 1 {
				meta = frame.coalesce(payloadLength)
			}
		}
		segments[0] = frame.header[:frame.length]
		for packetIndex := index; packetIndex < end; packetIndex++ {
			segments[packetIndex-index+1] = frames[packetIndex].payload
		}
		writeErr = E.Errors(writeErr, o.enqueue(segments[:end-index+1], meta, goOutboundDatagram, nil, 0))
		index = end
	}
	return writeErr
}

func (o *goMemoryIO) transmitBacklogBelowBatch(conn *GoConn) bool {
	queue := conn.outboundQueue.Load()
	if queue == nil {
		queue = o.tun.outbound
	}
	return int(queue.dataQueued.Load()) < o.tun.batchSize
}

func (o *goMemoryIO) flush() {
}

func (o *goMemoryIO) mtu() int {
	return o.tun.MTU()
}

func (o *goMemoryIO) transmitPrefix() int {
	return 0
}

func (o *goMemoryIO) transmitChecksumOffload() bool {
	return o.tun.offload.Load()&memoryTunOffloadChecksum != 0
}

func (o *goMemoryIO) transmitSegmentOffload() bool {
	return o.tun.offload.Load()&memoryTunOffloadTCPSegmentation != 0
}

func (o *goMemoryIO) armTransmitWritable(conn *GoConn) (*goBlockedWriters, error) {
	queue := o.tun.outbound
	if conn != nil {
		routed := conn.outboundQueue.Load()
		if routed != nil {
			queue = routed
		}
	}
	queue.access.Lock()
	armed := !queue.closed.Load() && queue.data.full()
	if armed {
		queue.transmitInterest = true
	}
	queue.access.Unlock()
	if !armed {
		return nil, nil
	}
	waiters := o.blocked[queue]
	if waiters == nil {
		waiters = new(goBlockedWriters)
		o.blocked[queue] = waiters
	}
	return waiters, nil
}

func (o *goMemoryIO) takeTransmitWritable(writable []*goBlockedWriters) []*goBlockedWriters {
	queues := o.tun.takeWritable(o.writableSpare)
	for _, queue := range queues {
		waiters := o.blocked[queue]
		if waiters == nil {
			continue
		}
		if queue.closed.Load() {
			delete(o.blocked, queue)
		}
		writable = append(writable, waiters)
	}
	clear(queues)
	o.writableSpare = queues[:0]
	return writable
}

func (o *goMemoryIO) close() error {
	close(o.closeSignal)
	o.advertiser.Wait()
	o.releaseReadBuffers()
	o.tun.attached.Store(false)
	o.tun.platformIO.CompareAndSwap(o, nil)
	o.tun.inboundAccess.Lock()
	o.tun.inbound.releaseAll()
	o.tun.inboundWritable.Broadcast()
	o.tun.inboundAccess.Unlock()
	clear(o.blocked)
	return o.goMemoryPoller.close()
}
