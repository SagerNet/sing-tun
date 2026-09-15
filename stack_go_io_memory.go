package tun

import (
	"os"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type goMemoryIO struct {
	stack   *Go
	tun     *MemoryTun
	timer   *time.Timer
	handed  []*buf.Buffer
	dropped goDropCounter
	stop    chan struct{}
}

func (o *goMemoryIO) start() error {
	o.tun.attached.Store(true)
	if o.tun.outboundHandler != nil {
		o.stop = make(chan struct{})
		go o.deliverOutbound()
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
	if ready || err != nil || timeout == 0 {
		return ready, 0, err
	}
	if timeout < 0 {
		select {
		case <-o.tun.engineWake:
		case <-o.tun.closeSignal:
		}
	} else {
		if o.timer == nil {
			o.timer = time.NewTimer(timeout)
		} else {
			o.timer.Reset(timeout)
		}
		select {
		case <-o.tun.engineWake:
			o.timer.Stop()
		case <-o.tun.closeSignal:
			o.timer.Stop()
		case <-o.timer.C:
		}
	}
	ready, err = o.inboundReady()
	return ready, 0, err
}

func (o *goMemoryIO) registerSocket(socket *goSocket, token uint32, interest uint8) error {
	return nil
}

func (o *goMemoryIO) updateSocket(socket *goSocket, interest uint8) error {
	return nil
}

func (o *goMemoryIO) unregisterSocket(socket *goSocket) {
}

func (o *goMemoryIO) readBurst(frames []goFrame, options N.ReadWaitOptions) (int, bool, error) {
	o.releaseReadBuffers()
	if o.tun.closed.Load() {
		return 0, false, os.ErrClosed
	}
	o.tun.inboundHeadroom.Store(int32(options.FrontHeadroom))
	o.tun.inboundRearSpace.Store(int32(options.RearHeadroom))
	o.tun.inboundAccess.Lock()
	defer o.tun.inboundAccess.Unlock()
	count := 0
	for count < len(frames) && !o.tun.inbound.empty() {
		buffer, _, _ := o.tun.inbound.pop()
		if options.NeedHeadroom() {
			buffer = options.Copy(buffer)
			options.PostReturn(buffer)
		}
		o.handed = append(o.handed, buffer)
		frames[count] = goFrame{buffer: buffer}
		count++
	}
	return count, o.tun.inbound.empty(), nil
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

func (o *goMemoryIO) enqueue(segments [][]byte, class goOutboundClass, owner *GoConn, segmentEnd uint64) error {
	length := 0
	for _, segment := range segments {
		length += len(segment)
	}
	o.tun.outboundAccess.Lock()
	defer o.tun.outboundAccess.Unlock()
	if o.tun.closed.Load() || !o.tun.attached.Load() {
		return os.ErrClosed
	}
	ring := &o.tun.control
	switch class {
	case goOutboundDatagram:
		ring = &o.tun.datagram
	case goOutboundData:
		ring = &o.tun.data
	}
	if ring.full() {
		if class == goOutboundData {
			return errGoTransmitBlocked
		}
		return errGoFrameDropped
	}
	if o.tun.control.empty() && o.tun.datagram.empty() && o.tun.data.empty() {
		defer o.tun.readerWake.notify()
	}
	packet := o.tun.newOutboundPacket(length)
	for _, segment := range segments {
		packet.Write(segment)
	}
	mtu := o.tun.MTU()
	if length <= mtu {
		o.pushOutboundLocked(ring, packet, owner, segmentEnd)
		return nil
	}
	defer packet.Release()
	fragments, fragmentsBuilt := goFragmentPacket(&o.stack.fragmentIdentification, packet.Bytes(), mtu)
	if !fragmentsBuilt {
		return errGoFrameDropped
	}
	for _, fragment := range fragments {
		if ring.full() {
			return errGoFrameDropped
		}
		fragmentPacket := o.tun.newOutboundPacket(len(fragment))
		fragmentPacket.Write(fragment)
		o.pushOutboundLocked(ring, fragmentPacket, owner, segmentEnd)
	}
	return nil
}

func (o *goMemoryIO) pushOutboundLocked(ring *goPacketRing, packet *buf.Buffer, owner *GoConn, segmentEnd uint64) {
	if owner != nil {
		owner.frameEnqueued(packet.Len())
		o.tun.dataQueued.Add(1)
	}
	ring.push(packet, owner, segmentEnd)
}

func (o *goMemoryIO) deliverOutbound() {
	batch := make([]*buf.Buffer, o.tun.batchSize)
	for {
		o.tun.outboundAccess.Lock()
		count := 0
		for count < len(batch) {
			buffer, owner, segmentEnd := o.tun.popOutboundLocked()
			if buffer == nil {
				break
			}
			if owner != nil {
				owner.frameDequeued(buffer.Len(), segmentEnd)
			}
			batch[count] = buffer
			count++
		}
		wakeEngine := o.tun.takeTransmitWritableLocked()
		o.tun.outboundAccess.Unlock()
		if wakeEngine {
			o.tun.engineWake.notify()
		}
		if count > 0 {
			err := o.tun.outboundHandler(batch[:count])
			if err != nil {
				for range count {
					o.dropped.record(o.stack.logger, "outbound frames")
				}
			}
			clear(batch[:count])
			continue
		}
		select {
		case <-o.tun.readerWake:
		case <-o.tun.closeSignal:
			return
		case <-o.stop:
			return
		}
	}
}

func (o *goMemoryIO) writeFrame(frame [][]byte, meta ForwardFrameMeta) error {
	return o.enqueue(frame, goOutboundControl, nil, 0)
}

func (o *goMemoryIO) writePacket(packet []byte, meta ForwardFrameMeta) error {
	segments := [1][]byte{packet}
	return o.enqueue(segments[:], goOutboundControl, nil, 0)
}

func (o *goMemoryIO) writeDatagram(packet []byte, meta ForwardFrameMeta) error {
	segments := [1][]byte{packet}
	return o.enqueue(segments[:], goOutboundDatagram, nil, 0)
}

func (o *goMemoryIO) writeData(frame [][]byte, meta ForwardFrameMeta, owner *GoConn, segmentEnd uint64) error {
	return o.enqueue(frame, goOutboundData, owner, segmentEnd)
}

func (o *goMemoryIO) writePacketBatch(frames []goUDPFrame) error {
	var writeErr error
	for index := range frames {
		frame := &frames[index]
		segments := [2][]byte{frame.header[:frame.length], frame.payload}
		writeErr = E.Errors(writeErr, o.enqueue(segments[:], goOutboundDatagram, nil, 0))
	}
	return writeErr
}

func (o *goMemoryIO) transmitBacklogBelowBatch() bool {
	return int(o.tun.dataQueued.Load()) < o.tun.batchSize
}

func (o *goMemoryIO) flush() {
}

func (o *goMemoryIO) mtu() int {
	return o.tun.MTU()
}

func (o *goMemoryIO) supportsSockets() bool {
	return false
}

func (o *goMemoryIO) transmitPrefix() int {
	return 0
}

func (o *goMemoryIO) transmitChecksumOffload() bool {
	return false
}

func (o *goMemoryIO) transmitSegmentOffload() bool {
	return false
}

func (o *goMemoryIO) armTransmitWritable() (bool, error) {
	o.tun.outboundAccess.Lock()
	defer o.tun.outboundAccess.Unlock()
	if !o.tun.data.full() {
		return false, nil
	}
	o.tun.transmitInterest = true
	return true, nil
}

func (o *goMemoryIO) takeTransmitWritable() bool {
	o.tun.outboundAccess.Lock()
	defer o.tun.outboundAccess.Unlock()
	writable := o.tun.transmitWritable
	o.tun.transmitWritable = false
	return writable
}

func (o *goMemoryIO) wake() {
	o.tun.engineWake.notify()
}

func (o *goMemoryIO) close() error {
	o.releaseReadBuffers()
	o.tun.attached.Store(false)
	if o.stop != nil {
		close(o.stop)
	}
	o.tun.inboundAccess.Lock()
	o.tun.inbound.releaseAll()
	o.tun.inboundAccess.Unlock()
	if o.timer != nil {
		o.timer.Stop()
	}
	return nil
}
