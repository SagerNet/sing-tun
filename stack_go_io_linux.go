package tun

import (
	"encoding/binary"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

const goEngineInlineTransmit = false

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
	device          *goLinuxDevice
	tun             *NativeTun
	tunFd           int
	ownsFd          bool
	epollFd         int
	eventFd         int
	receiveBuffers  []*buf.Buffer
	readWaitOptions N.ReadWaitOptions
	events          [goSocketEventBatch + 2]unix.EpollEvent
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
	err := o.startPoller()
	if err != nil && o.ownsFd {
		err = E.Errors(err, unix.Close(o.tunFd))
	}
	return err
}

func (o *goLinuxIO) startPoller() error {
	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return E.Cause(err, "go: create epoll")
	}
	eventFd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		unix.Close(epollFd)
		return E.Cause(err, "go: create eventfd")
	}
	err = unix.EpollCtl(epollFd, unix.EPOLL_CTL_ADD, o.tunFd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: goEpollDataTun})
	if err == nil {
		err = unix.EpollCtl(epollFd, unix.EPOLL_CTL_ADD, eventFd, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: goEpollDataWake})
	}
	if err != nil {
		return E.Errors(E.Cause(err, "go: register epoll events"), unix.Close(epollFd), unix.Close(eventFd))
	}
	o.epollFd = epollFd
	o.eventFd = eventFd
	return nil
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

const (
	goEpollDataTun  int32 = -1
	goEpollDataWake int32 = -2
)

func (o *goLinuxIO) wait(timeout time.Duration, events []goSocketEvent) (bool, int, error) {
	milliseconds := -1
	if timeout >= 0 {
		milliseconds = int((timeout + time.Millisecond - 1) / time.Millisecond)
	}
	var eventCount int
	var err error
	if timeout == 0 {
		//nolint:staticcheck
		count, _, errno := unix.RawSyscall6(unix.SYS_EPOLL_PWAIT, uintptr(o.epollFd), uintptr(unsafe.Pointer(&o.events[0])), uintptr(len(o.events)), 0, 0, 0)
		eventCount = int(count)
		if errno != 0 {
			err = errno
		}
	} else {
		eventCount, err = unix.EpollWait(o.epollFd, o.events[:], milliseconds)
	}
	if err != nil {
		if err == unix.EINTR {
			return false, 0, nil
		}
		return false, 0, E.Cause(err, "go: epoll wait")
	}
	tunReadable := false
	socketCount := 0
	for index := range eventCount {
		event := &o.events[index]
		switch event.Fd {
		case goEpollDataWake:
			var value [8]byte
			_, _ = unix.Read(o.eventFd, value[:])
		case goEpollDataTun:
			if event.Events&(unix.EPOLLERR|unix.EPOLLHUP) != 0 {
				return false, 0, unix.ECONNRESET
			}
			tunReadable = true
		default:
			if socketCount == len(events) {
				continue
			}
			events[socketCount] = goSocketEvent{
				token:    uint32(event.Fd),
				readable: event.Events&(unix.EPOLLIN|unix.EPOLLERR|unix.EPOLLHUP|unix.EPOLLRDHUP) != 0,
				writable: event.Events&unix.EPOLLOUT != 0,
			}
			socketCount++
		}
	}
	return tunReadable, socketCount, nil
}

func (o *goLinuxIO) registerSocket(socket *goSocket, token uint32, interest uint8) error {
	socket.token = token
	err := unix.EpollCtl(o.epollFd, unix.EPOLL_CTL_ADD, socket.fd, &unix.EpollEvent{Events: goEpollEvents(interest), Fd: int32(token)})
	if err != nil {
		return E.Cause(err, "go: register socket")
	}
	socket.registered = true
	return nil
}

func (o *goLinuxIO) updateSocket(socket *goSocket, interest uint8) error {
	operation := unix.EPOLL_CTL_MOD
	if interest == 0 {
		operation = unix.EPOLL_CTL_DEL
	} else if !socket.registered {
		operation = unix.EPOLL_CTL_ADD
	}
	err := unix.EpollCtl(o.epollFd, operation, socket.fd, &unix.EpollEvent{Events: goEpollEvents(interest), Fd: int32(socket.token)})
	if err != nil {
		return E.Cause(err, "go: update socket interest")
	}
	socket.registered = interest != 0
	return nil
}

func (o *goLinuxIO) unregisterSocket(socket *goSocket) {
	if !socket.registered {
		return
	}
	unix.EpollCtl(o.epollFd, unix.EPOLL_CTL_DEL, socket.fd, nil)
	socket.registered = false
}

func goEpollEvents(interest uint8) uint32 {
	var events uint32
	if interest&goInterestRead != 0 {
		events |= unix.EPOLLIN | unix.EPOLLRDHUP
	}
	if interest&goInterestWrite != 0 {
		events |= unix.EPOLLOUT
	}
	return events
}

func (o *goLinuxIO) readBurst(frames []goFrame, options N.ReadWaitOptions) (int, bool, error) {
	if o.receiveBuffers == nil || o.readWaitOptions != options {
		o.releaseReadBuffers()
		if o.receiveBuffers == nil {
			o.receiveBuffers = make([]*buf.Buffer, goPacketBatchSize)
		}
		o.readWaitOptions = options
	}
	count := 0
	for count < min(len(frames), len(o.receiveBuffers)) {
		buffer := o.receiveBuffers[count]
		if buffer == nil {
			// Linux hands pre-segmentation TSO aggregates to the TUN fd even with IFF_VNET_HDR off
			// (observed on 6.x kernels).
			buffer = options.NewBufferSize(virtioNetHdrLen + gsoMaxSize)
			o.receiveBuffers[count] = buffer
		}
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
		var meta ForwardFrameMeta
		switch virtioOptions.GSOType {
		case GSONone:
		case GSOTCPv4:
			meta.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV4
			meta.gsoSize = virtioOptions.GSOSize
		case GSOTCPv6:
			meta.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV6
			meta.gsoSize = virtioOptions.GSOSize
		case GSOUDPL4:
			meta.gsoType = goUDPGSOType
			meta.gsoSize = virtioOptions.GSOSize
		}
		meta.needsChecksum = virtioOptions.NeedsCsum
		meta.checksumStart = virtioOptions.CsumStart
		meta.checksumOffset = virtioOptions.CsumOffset
		buffer.Resize(options.FrontHeadroom+len(packet)-len(payload), len(payload))
		options.PostReturn(buffer)
		frames[count] = goFrame{buffer: buffer, meta: meta}
		count++
	}
	return count, false, nil
}

func (o *goLinuxIO) releaseReadBuffers() {
	buf.ReleaseMulti(o.receiveBuffers)
	clear(o.receiveBuffers)
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
		case unix.EAGAIN:
			o.device.droppedEngineFrames.record(o.device.stack.logger, "engine frames")
			return errGoFrameDropped
		default:
			return E.Cause(errno, "go: write tun")
		}
	}
}

func (o *goLinuxIO) writeData(frame [][]byte, meta ForwardFrameMeta) error {
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
			return E.Cause(errno, "go: write tun")
		}
	}
}

func (o *goLinuxIO) transmitFrame(frame [][]byte, meta ForwardFrameMeta) unix.Errno {
	var headerStorage [virtioNetHdrLen]byte
	var iovecStorage [goPacketBatchSize + 2]unix.Iovec
	iovecs := iovecStorage[:0]
	if o.device.vnetHeader {
		prefix := goEmptyVirtioHeader[:]
		if meta != (ForwardFrameMeta{}) {
			virtioHeader := virtioNetHdr{gsoType: meta.gsoType, gsoSize: meta.gsoSize}
			if meta.needsChecksum {
				virtioHeader.flags = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
				virtioHeader.csumStart = meta.checksumStart
				virtioHeader.csumOffset = meta.checksumOffset
			}
			if meta.gsoType == goUDPGSOType {
				virtioHeader.hdrLen = meta.checksumStart + header.UDPMinimumSize
			} else if meta.gsoType != unix.VIRTIO_NET_HDR_GSO_NONE {
				virtioHeader.hdrLen = meta.checksumStart + uint16(header.TCP(frame[0][meta.checksumStart:]).DataOffset())
			}
			common.Must(virtioHeader.encode(headerStorage[:]))
			prefix = headerStorage[:]
		}
		vector := unix.Iovec{Base: &prefix[0]}
		vector.SetLen(len(prefix))
		iovecs = append(iovecs, vector)
	}
	for _, segment := range frame {
		if len(segment) == 0 {
			continue
		}
		vector := unix.Iovec{Base: &segment[0]}
		vector.SetLen(len(segment))
		iovecs = append(iovecs, vector)
	}
	//nolint:staticcheck
	_, _, errno := unix.RawSyscall(unix.SYS_WRITEV, uintptr(o.tunFd), uintptr(unsafe.Pointer(&iovecs[0])), uintptr(len(iovecs)))
	return errno
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

func (o *goLinuxIO) armTransmitWritable() (bool, error) {
	return false, nil
}

func (o *goLinuxIO) takeTransmitWritable() bool {
	return false
}

func (o *goLinuxIO) wake() {
	var value [8]byte
	binary.NativeEndian.PutUint64(value[:], 1)
	_, _ = unix.Write(o.eventFd, value[:])
}

func (o *goLinuxIO) close() error {
	o.device.closing.Store(true)
	err := E.Errors(unix.Close(o.epollFd), unix.Close(o.eventFd))
	if o.ownsFd {
		err = E.Errors(err, unix.Close(o.tunFd))
	}
	return err
}

func (o *goLinuxIO) flush() {
}

func (o *goLinuxIO) writePacketBatch(frames []goUDPFrame) error {
	var writeError error
	var segments [goPacketBatchSize + 1][]byte
	for index := 0; index < len(frames); {
		frame := &frames[index]
		end := index + 1
		payloadLength := len(frame.payload)
		if o.device.vnetHeader && !o.device.udpTransmitDisabled.Load() && payloadLength > 0 {
			for end < len(frames) {
				next := &frames[end]
				if next.length != frame.length || len(next.payload) == 0 || len(next.payload) > len(frame.payload) || frame.length+payloadLength+len(next.payload) > 65535 {
					break
				}
				udpOffset := frame.length - header.UDPMinimumSize
				if binary.BigEndian.Uint32(next.header[udpOffset:]) != binary.BigEndian.Uint32(frame.header[udpOffset:]) {
					break
				}
				if frame.length == header.IPv4MinimumSize+header.UDPMinimumSize {
					if [8]byte(next.header[12:20]) != [8]byte(frame.header[12:20]) {
						break
					}
				} else if [32]byte(next.header[8:40]) != [32]byte(frame.header[8:40]) {
					break
				}
				payloadLength += len(next.payload)
				end++
				if len(next.payload) < len(frame.payload) {
					break
				}
			}
		}
		packetHeader := frame.header
		meta := frame.meta
		if end-index > 1 {
			udpLength := uint16(header.UDPMinimumSize + payloadLength)
			var sourceAddress, destinationAddress []byte
			if frame.length == header.IPv4MinimumSize+header.UDPMinimumSize {
				ipHdr := header.IPv4(packetHeader[:header.IPv4MinimumSize])
				ipHdr.SetTotalLength(uint16(frame.length + payloadLength))
				ipHdr.SetChecksum(0)
				ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
				sourceAddress = ipHdr.SourceAddressSlice()
				destinationAddress = ipHdr.DestinationAddressSlice()
			} else {
				ipHdr := header.IPv6(packetHeader[:header.IPv6MinimumSize])
				ipHdr.SetPayloadLength(udpLength)
				sourceAddress = ipHdr.SourceAddressSlice()
				destinationAddress = ipHdr.DestinationAddressSlice()
			}
			udpHdr := header.UDP(packetHeader[frame.length-header.UDPMinimumSize : frame.length])
			udpHdr.SetLength(udpLength)
			udpHdr.SetChecksum(header.PseudoHeaderChecksum(header.UDPProtocolNumber, sourceAddress, destinationAddress, udpLength))
			meta.gsoType = goUDPGSOType
			meta.gsoSize = uint16(len(frame.payload))
		}
		segments[0] = packetHeader[:frame.length]
		for packetIndex := index; packetIndex < end; packetIndex++ {
			segments[packetIndex-index+1] = frames[packetIndex].payload
		}
		errno := o.transmitFrame(segments[:end-index+1], meta)
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 && end-index > 1 {
			switch errno {
			case unix.EINVAL, unix.EIO, unix.EOPNOTSUPP:
				o.device.udpTransmitDisabled.Store(true)
				continue
			}
		}
		if errno == unix.EAGAIN {
			o.device.droppedEngineFrames.record(o.device.stack.logger, "UDP frames")
			writeError = E.Errors(writeError, errGoFrameDropped)
		} else if errno != 0 {
			writeError = E.Errors(writeError, E.Cause(errno, "go: write UDP batch"))
		}
		index = end
	}
	return writeError
}
