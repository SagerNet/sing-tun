package tun

import (
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

const goEngineTransmits = false

var goEmptyVirtioHeader [virtioNetHdrLen]byte

type goLinuxDevice struct {
	stack               *Go
	vnetHeader          bool
	offloadProbePending atomic.Bool
	transmitOffload     atomic.Bool
	udpTransmitDisabled atomic.Bool
	droppedEngineFrames goDropCounter
	droppedDataFrames   goDropCounter
	closing             atomic.Bool
}

type goLinuxIO struct {
	device *goLinuxDevice
	tun    *NativeTun
	tunFd  int
	ownsFd bool
	goPoller
	fdAccess     sync.RWMutex
	receiveSlots goReadSlots
}

func newGoPlatformQueues(stack *Go) ([]goPlatformIO, error) {
	nativeTun, isNative := stack.tun.(*NativeTun)
	if !isNative {
		return nil, E.New("go: unsupported TUN implementation")
	}
	err := nativeTun.detachRuntimePoller()
	if err != nil {
		return nil, E.Cause(err, "go: detach tun from runtime poller")
	}
	device := &goLinuxDevice{stack: stack}
	vnetHeader, err := nativeTun.vnetHeaderEnabled()
	if err != nil {
		stack.logger.Warn(E.Cause(err, "go: check IFF_VNET_HDR"))
		vnetHeader = false
	}
	device.vnetHeader = vnetHeader
	if vnetHeader {
		offloadErr := setUDPOffload(nativeTun.rawFileDescriptor())
		if offloadErr != nil {
			offloadErr = setTCPOffload(nativeTun.rawFileDescriptor())
		}
		if offloadErr != nil {
			stack.logger.Warn(E.Cause(offloadErr, "go: set TSO offload"))
		} else {
			device.offloadProbePending.Store(true)
		}
	}
	queueCount := 1
	if nativeTun.multiQueue {
		queueCount = runtime.GOMAXPROCS(0)
	} else if nativeTun.options.MultiQueue {
		stack.logger.Warn("go: multi-queue requested but the tun device is single-queue")
	}
	queues := make([]goPlatformIO, queueCount)
	queues[0] = &goLinuxIO{device: device, tun: nativeTun, tunFd: nativeTun.rawFileDescriptor()}
	for index := 1; index < len(queues); index++ {
		queues[index] = &goLinuxIO{device: device, tun: nativeTun, tunFd: -1}
	}
	return queues, nil
}

func (o *goLinuxIO) start() error {
	if o.tunFd < 0 {
		queueFd, err := o.tun.openQueue()
		if err != nil {
			o.device.stack.logger.Warn(E.Cause(err, "go: attach tun queue"))
			return errGoQueueUnavailable
		}
		o.tunFd = queueFd
		o.ownsFd = true
	}
	err := o.goPoller.open(o.tunFd)
	if err != nil && o.ownsFd {
		err = E.Errors(err, unix.Close(o.tunFd))
	}
	return err
}

func (o *goLinuxIO) probeTransmitOffload() error {
	probeAddr := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	fingerprint := []byte("sing-tun-probe-tun-gro")
	segmentSize := len(fingerprint)
	const ipHeaderLength = 20
	const tcpHeaderLength = 20
	totalLength := ipHeaderLength + tcpHeaderLength + 2*segmentSize
	packet := make([]byte, totalLength)
	probeIPv4 := header.IPv4(packet)
	probeIPv4.Encode(&header.IPv4Fields{
		SrcAddr:     probeAddr,
		DstAddr:     probeAddr,
		Protocol:    unix.IPPROTO_TCP,
		TTL:         0,
		TotalLength: uint16(totalLength),
	})
	probeTCP := header.TCP(packet[ipHeaderLength:])
	probeTCP.Encode(&header.TCPFields{
		SrcPort:    0,
		DstPort:    0,
		SeqNum:     1,
		AckNum:     1,
		DataOffset: tcpHeaderLength,
		Flags:      header.TCPFlagAck,
		WindowSize: 3000,
	})
	copy(packet[ipHeaderLength+tcpHeaderLength:], fingerprint)
	copy(packet[ipHeaderLength+tcpHeaderLength+segmentSize:], fingerprint)
	probeIPv4.SetChecksum(^probeIPv4.CalculateChecksum())
	pseudoSum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, probeIPv4.SourceAddressSlice(), probeIPv4.DestinationAddressSlice(), uint16(tcpHeaderLength+2*segmentSize))
	probeTCP.SetChecksum(pseudoSum)
	errno := o.transmitFrame([][]byte{packet}, ForwardFrameMeta{
		needsChecksum:  true,
		checksumStart:  ipHeaderLength,
		checksumOffset: header.TCPChecksumOffset,
		gsoType:        unix.VIRTIO_NET_HDR_GSO_TCPV4,
		gsoSize:        uint16(segmentSize),
	})
	if errno != 0 {
		return E.Cause(errno, "go: tso probe write")
	}
	return nil
}

func (o *goLinuxIO) wait(timeout time.Duration, events []goSocketEvent) (bool, int, error) {
	deviceReady, socketCount, err := o.goPoller.wait(timeout, events)
	return deviceReady&goInterestRead != 0, socketCount, err
}

func (o *goLinuxIO) readBurst(frames []goFrame, options N.ReadWaitOptions) (int, bool, error) {
	// Linux hands pre-segmentation TSO aggregates to the TUN fd even with IFF_VNET_HDR off
	// (observed on 6.x kernels).
	o.receiveSlots.configure(goPacketBatchSize, virtioNetHdrLen+gsoMaxSize+options.FrontHeadroom+options.RearHeadroom)
	limit := min(len(frames), goPacketBatchSize)
	o.receiveSlots.wake(limit)
	count := 0
	for count < limit {
		buffer := o.receiveSlots.slot(count)
		buffer.Reset()
		buffer.Resize(options.FrontHeadroom, 0)
		buffer.Reserve(options.RearHeadroom)
		scratch := buffer.FreeBytes()
		//nolint:staticcheck
		n, _, errno := unix.RawSyscall(unix.SYS_READ, uintptr(o.tunFd), uintptr(unsafe.Pointer(&scratch[0])), uintptr(len(scratch)))
		if errno != 0 {
			if errno == unix.EAGAIN {
				return count, true, nil
			}
			if errno == unix.EINTR {
				continue
			}
			return 0, false, E.Cause(errno, "go: read tun")
		}
		if n == 0 {
			return 0, false, os.ErrClosed
		}
		// The kernel rejects writes with EIO while the device is not up (tun_get_user).
		if o.device.offloadProbePending.CompareAndSwap(true, false) {
			probeErr := o.probeTransmitOffload()
			if probeErr != nil {
				o.device.stack.logger.Warn(E.Cause(probeErr, "go: TSO write probe"))
			} else {
				o.device.transmitOffload.Store(true)
			}
		}
		packet := scratch[:n]
		if !o.device.vnetHeader {
			buffer.Truncate(int(n))
			options.PostReturn(buffer)
			frames[count] = goFrame{buffer: buffer}
			count++
			continue
		}
		payload, virtioOptions, parseErr := parseVirtioRead(packet)
		if parseErr != nil {
			continue
		}
		meta := goFrameMeta(virtioOptions)
		buffer.Resize(options.FrontHeadroom+len(packet)-len(payload), len(payload))
		options.PostReturn(buffer)
		frames[count] = goFrame{buffer: buffer, meta: meta}
		count++
	}
	return count, false, nil
}

func (o *goLinuxIO) releaseReadBuffers() {
	o.receiveSlots.sleep()
}

func (o *goLinuxIO) writeFrame(frame [][]byte, meta ForwardFrameMeta) error {
	for {
		errno := o.transmitFrame(frame, meta)
		switch errno {
		case 0:
			return nil
		case unix.EINTR:
			if o.device.closing.Load() {
				return os.ErrClosed
			}
		case unix.EAGAIN, unix.ENOBUFS, unix.ENOMEM:
			o.device.droppedEngineFrames.record(o.device.stack.logger, "engine frames")
			return errGoFrameDropped
		default:
			if errno == unix.EBADF && o.device.closing.Load() {
				return os.ErrClosed
			}
			return E.Cause(errno, "go: write tun")
		}
	}
}

func (o *goLinuxIO) writePacket(packet []byte, meta ForwardFrameMeta) error {
	frame := [1][]byte{packet}
	return o.writeFrame(frame[:], meta)
}

func (o *goLinuxIO) writeData(frame [][]byte, meta ForwardFrameMeta, owner *GoConn, segmentEnd uint64) error {
	delay := goTransmitBackoffMin
	waited := time.Duration(0)
	for {
		errno := o.transmitFrame(frame, meta)
		switch errno {
		case 0:
			return nil
		case unix.EINTR:
			if o.device.closing.Load() {
				return os.ErrClosed
			}
		case unix.ENOBUFS, unix.ENOMEM:
			// Before Linux 6.6, tun_alloc_skb places the whole frame in the skb head unless the
			// virtio header carries a header length, so a large frame needs a high-order
			// allocation, which fails with ENOBUFS under memory fragmentation.
			o.device.droppedDataFrames.record(o.device.stack.logger, "data frames")
			return errGoFrameDropped
		case unix.EAGAIN:
			// tun chardev writes complete into netif_rx, which drops on backlog overflow
			// instead of reporting EAGAIN, and tun_chr_poll reports the fd always writable.
			if o.device.closing.Load() {
				return os.ErrClosed
			}
			if waited >= goTransmitBackoffBudget {
				o.device.droppedDataFrames.record(o.device.stack.logger, "data frames")
				return errGoFrameDropped
			}
			time.Sleep(delay)
			if o.device.closing.Load() {
				return os.ErrClosed
			}
			waited += delay
			delay = min(2*delay, goTransmitBackoffMax)
		default:
			if errno == unix.EBADF && o.device.closing.Load() {
				return os.ErrClosed
			}
			return errno
		}
	}
}

func (o *goLinuxIO) transmitFrame(frame [][]byte, meta ForwardFrameMeta) unix.Errno {
	o.fdAccess.RLock()
	defer o.fdAccess.RUnlock()
	if o.device.closing.Load() {
		return unix.EBADF
	}
	var headerStorage [virtioNetHdrLen]byte
	var iovecStorage [goPacketBatchSize + 2]unix.Iovec
	iovecs := iovecStorage[:]
	iovecCapacity := len(frame)
	if o.device.vnetHeader {
		iovecCapacity++
	}
	if iovecCapacity > len(iovecs) {
		iovecs = make([]unix.Iovec, iovecCapacity)
	}
	iovecCount := 0
	if o.device.vnetHeader {
		prefix := goEmptyVirtioHeader[:]
		if meta != (ForwardFrameMeta{}) {
			virtioHeader := virtioNetHdr{gsoType: meta.gsoType, gsoSize: meta.gsoSize, hdrLen: meta.segmentHeaderLength(frame[0])}
			if meta.needsChecksum {
				virtioHeader.flags = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
				virtioHeader.csumStart = meta.checksumStart
				virtioHeader.csumOffset = meta.checksumOffset
			}
			common.Must(virtioHeader.encode(headerStorage[:]))
			prefix = headerStorage[:]
		}
		vector := unix.Iovec{Base: &prefix[0]}
		vector.SetLen(len(prefix))
		iovecs[iovecCount] = vector
		iovecCount++
	}
	for _, segment := range frame {
		if len(segment) == 0 {
			continue
		}
		vector := unix.Iovec{Base: &segment[0]}
		vector.SetLen(len(segment))
		iovecs[iovecCount] = vector
		iovecCount++
	}
	//nolint:staticcheck
	_, _, errno := unix.RawSyscall(unix.SYS_WRITEV, uintptr(o.tunFd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(iovecCount))
	return errno
}

func (o *goLinuxIO) mtu() int {
	return o.device.stack.mtu
}

func (o *goLinuxIO) supportsSockets() bool {
	return true
}

func (o *goLinuxIO) transmitPrefix() int {
	if o.device.vnetHeader {
		return virtioNetHdrLen
	}
	return 0
}

func (o *goLinuxIO) transmitChecksumOffload() bool {
	return o.device.vnetHeader
}

func (o *goLinuxIO) transmitSegmentOffload() bool {
	return o.device.transmitOffload.Load()
}

func (o *goLinuxIO) armTransmitWritable(conn *GoConn) (*goBlockedWriters, error) {
	return nil, nil
}

func (o *goLinuxIO) takeTransmitWritable(writable []*goBlockedWriters) []*goBlockedWriters {
	return writable
}

func (o *goLinuxIO) close() error {
	o.device.closing.Store(true)
	o.fdAccess.Lock()
	defer o.fdAccess.Unlock()
	o.receiveSlots.release()
	err := o.goPoller.close()
	if o.ownsFd {
		err = E.Errors(err, unix.Close(o.tunFd))
	}
	return err
}

func (o *goLinuxIO) writeDatagram(packet []byte, meta ForwardFrameMeta) error {
	return o.writePacket(packet, meta)
}

func (o *goLinuxIO) transmitBacklogBelowBatch(conn *GoConn) bool {
	return true
}

func (o *goLinuxIO) flush() {
}

func (o *goLinuxIO) writePacketBatch(frames []goUDPFrame) error {
	if o.device.closing.Load() {
		return os.ErrClosed
	}
	var writeError error
	var segments [goPacketBatchSize + 1][]byte
	for index := 0; index < len(frames); {
		frame := &frames[index]
		end := index + 1
		payloadLength := len(frame.payload)
		if o.device.vnetHeader && !o.device.udpTransmitDisabled.Load() {
			end, payloadLength = goUDPSegmentRun(frames, index)
		}
		packetHeader := frame.header
		meta := frame.meta
		if end-index > 1 {
			meta = frame.coalesce(payloadLength)
		}
		segments[0] = frame.header[:frame.length]
		for packetIndex := index; packetIndex < end; packetIndex++ {
			segments[packetIndex-index+1] = frames[packetIndex].payload
		}
		errno := o.transmitFrame(segments[:end-index+1], meta)
		if errno == unix.EINTR {
			frame.header = packetHeader
			continue
		}
		if errno == unix.EBADF && o.device.closing.Load() {
			return os.ErrClosed
		}
		if errno != 0 && end-index > 1 {
			switch errno {
			case unix.EINVAL, unix.EIO, unix.EOPNOTSUPP:
				o.device.udpTransmitDisabled.Store(true)
				frame.header = packetHeader
				continue
			}
		}
		if errno == unix.EAGAIN || errno == unix.ENOBUFS || errno == unix.ENOMEM {
			o.device.droppedEngineFrames.record(o.device.stack.logger, "UDP frames")
			writeError = E.Errors(writeError, errGoFrameDropped)
		} else if errno != 0 {
			writeError = E.Errors(writeError, E.Cause(errno, "go: write UDP batch"))
		}
		index = end
	}
	return writeError
}
