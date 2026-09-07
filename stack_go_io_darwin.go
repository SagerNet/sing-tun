package tun

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sagernet/sing-tun/gtcpip/header"
	rawfile "github.com/sagernet/sing-tun/internal/rawfile_darwin"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

const (
	goWakeIdent            = 0
	goEngineInlineTransmit = true

	goDarwinTransmitBatch = 64
	goDarwinBatchHeader   = 128
	goDarwinBatchIovecs   = 8
	// sendit_x builds every packet of the batch before sending any of it, and mbuf_allocpacket
	// takes a 16 KB cluster for a packet above MBIGCLBYTES (4096 bytes, prefix included) from a
	// pool of a few hundred; a batch of large frames exhausts it and fails with ENOBUFS, so only
	// frames that fit a 4 KB cluster are batched and larger ones keep the per-frame writev.
	goDarwinBatchFrameLimit = 4096 - PacketOffset

	// utun_pkt_input in netif mode returns ENOSPC once utun_input_chain_count exceeds
	// net.utun.max_pending_input (512) and does not free the mbuf, and neither does ctl_send:
	// every ENOSPC leaks one mbuf cluster until reboot. The chain only drains when the host side
	// syncs the rx ring, which kern_channel_notify triggers per successful input, so the gate keeps
	// the estimated chain depth well under the limit and, when nothing moves, submits a small probe
	// to trigger a sync rather than wait forever.
	goDarwinGateLimit      = 512
	goDarwinGateHighWater  = 384
	goDarwinGateProbe      = 8
	goDarwinGatePoll       = 100 * time.Microsecond
	goDarwinGateSample     = time.Millisecond
	goDarwinGateProbeAfter = 16
	goDarwinGateRIBSize    = 4096
	goDarwinGateRIBSizeMax = 1 << 20

	sysprotoControl       = 2
	utunOptionEnableNetif = 20
)

type goDarwinIO struct {
	stack                 *Go
	tunFd                 int
	kqueueFd              int
	transmitAccess        *sync.Mutex
	receiveBuffers        []*buf.Buffer
	readWaitOptions       N.ReadWaitOptions
	receiveIovecs         []unix.Iovec
	messageHeaders        []rawfile.MsgHdrX
	events                [goSocketEventBatch + 3]unix.Kevent_t
	changes               [2]unix.Kevent_t
	wakeEvent             [1]unix.Kevent_t
	transmitWritableEvent [1]unix.Kevent_t
	transmitWritable      atomic.Bool
	receiveBatch          int
	transmitIovecs        []unix.Iovec
	socketTokens          []uint32
	socketInterests       []uint8
	droppedEngineFrames   goDropCounter
	droppedBatchFrames    goDropCounter
	leakedClusters        goDropCounter
	closing               atomic.Bool

	batchHeaders   []byte
	batchIovecs    []unix.Iovec
	batchMessages  []rawfile.MsgHdrX
	batchSpill     []byte
	batchSpilled   []bool
	batchStart     int
	batchCount     int
	packetIovecs   [goPacketBatchSize * 3]unix.Iovec
	packetMessages [goPacketBatchSize]rawfile.MsgHdrX

	netif              bool
	interfaceIndex     int
	epoch              time.Time
	gateRIB            []byte
	gateSubmitted      int64
	gateSampledAt      int64
	gateSampledTime    atomic.Int64
	gateInflightSample int64
	gateConsumedBase   int64
	gateBlocked        atomic.Bool
	gateIdlePolls      int
	gateLastConsumed   int64
	gateProbeEnd       int64
}

func newGoPlatformQueues(stack *Go) ([]goPlatformIO, error) {
	return []goPlatformIO{&goDarwinIO{stack: stack, epoch: time.Now()}}, nil
}

func (o *goDarwinIO) start() error {
	nativeTun, isNative := o.stack.tun.(*NativeTun)
	if !isNative {
		return E.New("go: unsupported TUN implementation")
	}
	err := nativeTun.detachRuntimePoller()
	if err != nil {
		return E.Cause(err, "go: detach tun from runtime poller")
	}
	o.tunFd = nativeTun.rawFileDescriptor()
	o.transmitAccess = nativeTun.transmitAccess()
	err = nativeTun.enableMaxPendingPackets()
	if err != nil {
		return E.Cause(err, "go: set UTUN_OPT_MAX_PENDING_PACKETS")
	}
	kqueueFd, err := unix.Kqueue()
	if err != nil {
		return E.Cause(err, "go: create kqueue")
	}
	registrations := []unix.Kevent_t{
		{Ident: uint64(o.tunFd), Filter: unix.EVFILT_READ, Flags: unix.EV_ADD | unix.EV_ENABLE},
		{Ident: goWakeIdent, Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_ENABLE | unix.EV_CLEAR},
	}
	_, err = unix.Kevent(kqueueFd, registrations, nil, nil)
	if err != nil {
		unix.Close(kqueueFd)
		return E.Cause(err, "go: register kqueue events")
	}
	o.kqueueFd = kqueueFd
	o.wakeEvent[0] = unix.Kevent_t{Ident: goWakeIdent, Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER}
	o.transmitWritableEvent[0] = unix.Kevent_t{Ident: uint64(o.tunFd), Filter: unix.EVFILT_WRITE, Flags: unix.EV_ADD | unix.EV_ENABLE | unix.EV_ONESHOT}
	o.receiveIovecs = make([]unix.Iovec, goReadBatch)
	o.messageHeaders = make([]rawfile.MsgHdrX, goReadBatch)
	o.transmitIovecs = make([]unix.Iovec, 0, 8)
	o.receiveBatch = goReceiveBatchMin
	o.batchHeaders = make([]byte, goDarwinTransmitBatch*goDarwinBatchHeader)
	o.batchIovecs = make([]unix.Iovec, goDarwinTransmitBatch*goDarwinBatchIovecs)
	o.batchMessages = make([]rawfile.MsgHdrX, goDarwinTransmitBatch)
	o.batchSpilled = make([]bool, goDarwinTransmitBatch)
	netif, err := unix.GetsockoptInt(o.tunFd, sysprotoControl, utunOptionEnableNetif)
	if err == nil && netif != 0 {
		name, nameErr := nativeTun.Name()
		if nameErr != nil {
			unix.Close(kqueueFd)
			return E.Cause(nameErr, "go: utun name")
		}
		netInterface, lookupErr := net.InterfaceByName(name)
		if lookupErr != nil {
			unix.Close(kqueueFd)
			return E.Cause(lookupErr, "go: utun interface")
		}
		o.netif = true
		o.interfaceIndex = netInterface.Index
		consumed, sampleErr := o.readInterfacePackets()
		if sampleErr != nil {
			unix.Close(kqueueFd)
			return E.Cause(sampleErr, "go: utun statistics")
		}
		o.gateConsumedBase = consumed
	}
	return nil
}

// The NET_RT_IFLIST2 route sysctl takes the interface index as its last name component and
// sysctl_iflist2 skips every other interface, so one interface costs a single small transfer.
func (o *goDarwinIO) readInterfacePackets() (int64, error) {
	mib := [6]int32{unix.CTL_NET, unix.AF_ROUTE, 0, unix.AF_UNSPEC, unix.NET_RT_IFLIST2, int32(o.interfaceIndex)}
	if o.gateRIB == nil {
		o.gateRIB = make([]byte, goDarwinGateRIBSize)
	}
	var rib []byte
	for {
		length := uintptr(len(o.gateRIB))
		_, _, errno := unix.Syscall6(unix.SYS___SYSCTL, uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)), uintptr(unsafe.Pointer(&o.gateRIB[0])), uintptr(unsafe.Pointer(&length)), 0, 0)
		if errno == unix.ENOMEM && len(o.gateRIB) < goDarwinGateRIBSizeMax {
			o.gateRIB = make([]byte, 2*len(o.gateRIB))
			continue
		}
		if errno != 0 {
			return 0, errno
		}
		rib = o.gateRIB[:length]
		break
	}
	for len(rib) >= int(unsafe.Sizeof(unix.IfMsghdr2{})) {
		message := (*unix.IfMsghdr2)(unsafe.Pointer(&rib[0]))
		if message.Type == unix.RTM_IFINFO2 && int(message.Index) == o.interfaceIndex {
			return int64(message.Data.Ipackets), nil
		}
		if message.Msglen == 0 {
			break
		}
		rib = rib[message.Msglen:]
	}
	return 0, unix.ENOENT
}

func (o *goDarwinIO) wait(timeout time.Duration, events []goSocketEvent) (bool, int, error) {
	if o.gateBlocked.Load() {
		poll := goDarwinGatePoll
		if o.netif {
			poll = max(goDarwinGateSample-(time.Since(o.epoch)-time.Duration(o.gateSampledTime.Load())), 0)
		}
		if timeout < 0 || timeout > poll {
			timeout = poll
		}
	}
	var timeoutSpec *unix.Timespec
	if timeout >= 0 {
		spec := unix.NsecToTimespec(timeout.Nanoseconds())
		timeoutSpec = &spec
	}
	var eventCount int
	var err error
	if timeout == 0 {
		//nolint:staticcheck
		count, _, errno := unix.RawSyscall6(unix.SYS_KEVENT, uintptr(o.kqueueFd), 0, 0, uintptr(unsafe.Pointer(&o.events[0])), uintptr(len(o.events)), uintptr(unsafe.Pointer(timeoutSpec)))
		eventCount = int(count)
		if errno != 0 {
			err = errno
		}
	} else {
		eventCount, err = unix.Kevent(o.kqueueFd, nil, o.events[:], timeoutSpec)
	}
	if o.gateBlocked.Load() {
		o.gatePoll()
	}
	if err != nil {
		if err == unix.EINTR {
			return false, 0, nil
		}
		return false, 0, E.Cause(err, "go: kevent wait")
	}
	tunReadable := false
	socketCount := 0
	for index := range eventCount {
		event := &o.events[index]
		if event.Filter == unix.EVFILT_USER {
			continue
		}
		if int(event.Ident) == o.tunFd {
			if event.Filter == unix.EVFILT_WRITE {
				o.transmitWritable.Store(true)
				continue
			}
			if event.Flags&unix.EV_ERROR != 0 && event.Data != 0 {
				return false, 0, unix.Errno(event.Data)
			}
			if event.Flags&unix.EV_EOF != 0 {
				return false, 0, unix.ECONNRESET
			}
			tunReadable = true
			continue
		}
		if int(event.Ident) >= len(o.socketTokens) || socketCount == len(events) {
			continue
		}
		events[socketCount] = goSocketEvent{
			token:    o.socketTokens[event.Ident],
			readable: event.Filter == unix.EVFILT_READ,
			writable: event.Filter == unix.EVFILT_WRITE,
		}
		socketCount++
	}
	return tunReadable, socketCount, nil
}

func (o *goDarwinIO) registerSocket(socket *goSocket, token uint32, interest uint8) error {
	if socket.fd >= len(o.socketTokens) {
		grown := max(socket.fd+1, 2*len(o.socketTokens), 64)
		o.socketTokens = append(o.socketTokens, make([]uint32, grown-len(o.socketTokens))...)
		o.socketInterests = append(o.socketInterests, make([]uint8, grown-len(o.socketInterests))...)
	}
	o.socketTokens[socket.fd] = token
	o.socketInterests[socket.fd] = 0
	return o.updateSocket(socket, interest)
}

func (o *goDarwinIO) updateSocket(socket *goSocket, interest uint8) error {
	current := o.socketInterests[socket.fd]
	if current == interest {
		return nil
	}
	changes := o.changes[:0]
	if current&goInterestRead != interest&goInterestRead {
		changes = append(changes, unix.Kevent_t{Ident: uint64(socket.fd), Filter: unix.EVFILT_READ, Flags: goKqueueFlags(interest&goInterestRead != 0)})
	}
	if current&goInterestWrite != interest&goInterestWrite {
		changes = append(changes, unix.Kevent_t{Ident: uint64(socket.fd), Filter: unix.EVFILT_WRITE, Flags: goKqueueFlags(interest&goInterestWrite != 0)})
	}
	o.socketInterests[socket.fd] = interest
	_, err := unix.Kevent(o.kqueueFd, changes, nil, nil)
	if err != nil {
		return E.Cause(err, "go: update socket interest")
	}
	return nil
}

func goKqueueFlags(enable bool) uint16 {
	if enable {
		return unix.EV_ADD | unix.EV_ENABLE
	}
	return unix.EV_DELETE
}

func (o *goDarwinIO) unregisterSocket(socket *goSocket) {
	o.updateSocket(socket, 0)
	o.socketTokens[socket.fd] = 0
}

func (o *goDarwinIO) readBurst(frames []goFrame, options N.ReadWaitOptions) (int, bool, error) {
	if o.receiveBuffers == nil || o.readWaitOptions != options {
		o.releaseReadBuffers()
		if o.receiveBuffers == nil {
			o.receiveBuffers = make([]*buf.Buffer, goReadBatch)
		}
		o.readWaitOptions = options
	}
	// recvmsg_x walks every submitted msghdr slot, whether or not a packet is pending for it.
	count := min(o.receiveBatch, len(frames))
	for index := range count {
		buffer := o.receiveBuffers[index]
		if buffer == nil {
			buffer = options.NewBufferSize(o.stack.mtu + PacketOffset)
			o.receiveBuffers[index] = buffer
		}
		buffer.Reset()
		buffer.Resize(options.FrontHeadroom, 0)
		buffer.Reserve(options.RearHeadroom)
		o.receiveIovecs[index] = rawfile.IovecFromBytes(buffer.FreeBytes())
		// Cannot clear only the length field. Older versions of the darwin kernel will check whether other data is empty.
		// https://github.com/Darm64/XNU/blob/xnu-2782.40.9/bsd/kern/uipc_syscalls.c#L2026-L2048
		o.messageHeaders[index] = rawfile.MsgHdrX{}
		o.messageHeaders[index].Msg.Iov = &o.receiveIovecs[index]
		o.messageHeaders[index].Msg.Iovlen = 1
	}
	received, errno := receiveMessageBatch(o.tunFd, o.messageHeaders[:count])
	if errno != 0 {
		if errno == unix.EWOULDBLOCK || errno == unix.EINTR {
			return 0, true, nil
		}
		return 0, false, E.Cause(errno, "go: recvmsg_x")
	}
	if received >= count {
		o.receiveBatch = min(count*2, len(o.messageHeaders))
	} else if received*2 < count {
		o.receiveBatch = max(count/2, goReceiveBatchMin)
	}
	frameCount := 0
	for index := range received {
		dataLen := int(o.messageHeaders[index].DataLen)
		if dataLen <= PacketOffset || dataLen > o.receiveBuffers[index].FreeLen() || o.messageHeaders[index].Msg.Flags&unix.MSG_TRUNC != 0 {
			continue
		}
		buffer := o.receiveBuffers[index]
		buffer.Reset()
		buffer.Resize(options.FrontHeadroom+PacketOffset, dataLen-PacketOffset)
		frames[frameCount] = goFrame{buffer: buffer}
		frameCount++
	}
	return frameCount, received == 0, nil
}

func (o *goDarwinIO) releaseReadBuffers() {
	clear(o.receiveIovecs)
	clear(o.messageHeaders)
	buf.ReleaseMulti(o.receiveBuffers)
	clear(o.receiveBuffers)
	o.transmitAccess.Lock()
	clear(o.transmitIovecs)
	if o.batchCount == 0 {
		clear(o.batchIovecs)
		clear(o.batchMessages)
		o.batchSpill = nil
	}
	o.transmitAccess.Unlock()
}

func receiveMessageBatch(fd int, headers []rawfile.MsgHdrX) (int, unix.Errno) {
	//nolint:staticcheck
	n, _, errno := unix.RawSyscall6(unix.SYS_RECVMSG_X, uintptr(fd), uintptr(unsafe.Pointer(&headers[0])), uintptr(len(headers)), unix.MSG_DONTWAIT, 0, 0)
	return int(n), errno
}

func (o *goDarwinIO) writeFrame(frame [][]byte, meta ForwardFrameMeta) error {
	err := o.writePacket(frame)
	if err == errGoTransmitBlocked {
		o.droppedEngineFrames.record(o.stack.logger, "engine frames")
		return errGoFrameDropped
	}
	return err
}

func (o *goDarwinIO) writeData(frame [][]byte, meta ForwardFrameMeta) error {
	o.transmitAccess.Lock()
	defer o.transmitAccess.Unlock()
	frameLength := 0
	for _, segment := range frame {
		frameLength += len(segment)
	}
	if frameLength > goDarwinBatchFrameLimit {
		return o.writeUnbatchedLocked(frame)
	}
	if o.batchCount == goDarwinTransmitBatch {
		o.flushLocked()
		if o.batchCount == goDarwinTransmitBatch {
			if o.batchStart == 0 {
				return errGoTransmitBlocked
			}
			o.compactBatch()
		}
	}
	slot := o.batchCount
	iovecs := o.batchIovecs[slot*goDarwinBatchIovecs : slot*goDarwinBatchIovecs : (slot+1)*goDarwinBatchIovecs]
	if header.IPVersion(frame[0]) == header.IPv4Version {
		iovecs = append(iovecs, packetHeaderVec4)
	} else {
		iovecs = append(iovecs, packetHeaderVec6)
	}
	for index, segment := range frame {
		if len(segment) == 0 {
			continue
		}
		if index == 0 && len(frame) > 1 {
			if len(segment) > goDarwinBatchHeader {
				return o.writeUnbatchedLocked(frame)
			}
			headerCopy := o.batchHeaders[slot*goDarwinBatchHeader : slot*goDarwinBatchHeader+len(segment)]
			copy(headerCopy, segment)
			segment = headerCopy
		}
		if len(iovecs) == cap(iovecs) {
			return o.writeUnbatchedLocked(frame)
		}
		iovecs = append(iovecs, rawfile.IovecFromBytes(segment))
	}
	o.batchMessages[slot] = rawfile.MsgHdrX{}
	o.batchMessages[slot].Msg.Iov = &iovecs[0]
	o.batchMessages[slot].Msg.Iovlen = int32(len(iovecs))
	o.batchSpilled[slot] = false
	o.batchCount++
	return nil
}

func (o *goDarwinIO) writeUnbatchedLocked(frame [][]byte) error {
	o.flushLocked()
	if o.batchCount > o.batchStart {
		return errGoTransmitBlocked
	}
	return o.writePacketLocked(frame)
}

func (o *goDarwinIO) flush() {
	o.transmitAccess.Lock()
	o.flushLocked()
	o.transmitAccess.Unlock()
}

func (o *goDarwinIO) gateEstimate() int64 {
	return o.gateInflightSample + (o.gateSubmitted - o.gateSampledAt)
}

func (o *goDarwinIO) gateSample() (int64, bool, bool) {
	if !o.netif {
		return o.gateEstimate(), false, false
	}
	now := int64(time.Since(o.epoch))
	if now-o.gateSampledTime.Load() < int64(goDarwinGateSample) {
		return o.gateEstimate(), false, false
	}
	o.gateSampledTime.Store(now)
	consumed, err := o.readInterfacePackets()
	if err != nil {
		return o.gateEstimate(), false, true
	}
	progressed := consumed != o.gateLastConsumed
	if progressed {
		o.gateProbeEnd = 0
	}
	o.gateLastConsumed = consumed
	o.gateInflightSample = max(o.gateSubmitted-(consumed-o.gateConsumedBase), 0)
	o.gateSampledAt = o.gateSubmitted
	return o.gateInflightSample, progressed, true
}

func (o *goDarwinIO) gateRoom(pending int) int {
	if !o.netif {
		return pending
	}
	estimate := o.gateEstimate()
	if estimate+int64(pending) > goDarwinGateHighWater {
		estimate, _, _ = o.gateSample()
	}
	room := goDarwinGateHighWater - estimate
	room = max(room, min(o.gateProbeEnd-o.gateSubmitted, goDarwinGateLimit-1-estimate))
	return int(max(min(room, int64(pending)), 0))
}

// flushLocked submits the queued frames. sendmsg_x reports no count on failure. ENOBUFS comes from
// sendit_x failing to build the packets before anything is sent, so the batch is kept and retried.
// For the other errors ctl_send_list frees whatever follows the failing packet, so the call
// consumed every frame handed to it: the ones before the failure were delivered, the failing one
// is charged to the kernel (an ENOSPC leaks it), the rest are dropped and left to retransmission.
func (o *goDarwinIO) flushLocked() {
	pending := o.batchCount - o.batchStart
	if pending == 0 {
		o.gateReleaseLocked()
		return
	}
	room := o.gateRoom(pending)
	for room > 0 {
		messages := o.batchMessages[o.batchStart : o.batchStart+room]
		n, errno := rawfile.NonBlockingSendMMsg(o.tunFd, messages)
		if errno == unix.EINTR {
			continue
		}
		if errno == unix.ENOBUFS || errno == unix.EAGAIN {
			break
		}
		if errno != 0 {
			o.batchStart += room
			o.gateSubmitted += int64(room)
			o.recordWriteError(errno)
			break
		}
		o.batchStart += n
		o.gateSubmitted += int64(n)
		room -= n
	}
	if o.batchStart == o.batchCount {
		o.batchStart = 0
		o.batchCount = 0
		o.gateReleaseLocked()
		return
	}
	o.gateBlockLocked()
	o.spillHeld()
}

func (o *goDarwinIO) gateBlockLocked() {
	if !o.gateBlocked.Swap(true) {
		o.wake()
	}
}

func (o *goDarwinIO) gateReleaseLocked() {
	if !o.gateBlocked.Load() {
		return
	}
	if o.gateRoom(1) == 0 {
		return
	}
	o.gateBlocked.Store(false)
	o.gateIdlePolls = 0
	o.transmitWritable.Store(true)
	o.wake()
}

// recordWriteError realigns the estimate after ENOSPC: the chain held more than the limit when
// the kernel refused, and the frames the kernel freed behind the refused one never reach the
// interface counter, so the counter baseline is moved to make the estimate read the limit now.
func (o *goDarwinIO) recordWriteError(errno unix.Errno) {
	if errno == unix.ENOSPC {
		o.leakedClusters.record(o.stack.logger, "frames into a full utun input queue, each leaking one kernel mbuf")
		if !o.netif {
			return
		}
		consumed, err := o.readInterfacePackets()
		if err == nil {
			o.gateLastConsumed = consumed
			o.gateConsumedBase = consumed - (o.gateSubmitted - (goDarwinGateLimit + 1))
		}
		o.gateSampledTime.Store(int64(time.Since(o.epoch)))
		o.gateInflightSample = goDarwinGateLimit + 1
		o.gateSampledAt = o.gateSubmitted
		o.gateProbeEnd = 0
		return
	}
	o.droppedBatchFrames.record(o.stack.logger, "batched frames")
}

func (o *goDarwinIO) gatePoll() {
	o.transmitAccess.Lock()
	defer o.transmitAccess.Unlock()
	if !o.gateBlocked.Load() {
		return
	}
	_, progressed, sampled := o.gateSample()
	if !sampled {
		o.flushLocked()
		return
	}
	if progressed {
		o.gateIdlePolls = 0
	} else {
		o.gateIdlePolls++
	}
	if o.gateIdlePolls >= goDarwinGateProbeAfter {
		o.gateProbeEnd = o.gateSubmitted + goDarwinGateProbe
		o.gateIdlePolls = 0
	}
	o.flushLocked()
}

func (o *goDarwinIO) spillHeld() {
	slotSize := o.stack.mtu + PacketOffset
	if o.batchSpill == nil {
		o.batchSpill = make([]byte, goDarwinTransmitBatch*slotSize)
	}
	for slot := o.batchStart; slot < o.batchCount; slot++ {
		if o.batchSpilled[slot] {
			continue
		}
		message := &o.batchMessages[slot]
		iovecs := unsafe.Slice(message.Msg.Iov, int(message.Msg.Iovlen))
		spill := o.batchSpill[slot*slotSize : (slot+1)*slotSize]
		length := 0
		for _, iovec := range iovecs[1:] {
			length += copy(spill[length:], bytesFromIovec(iovec))
		}
		iovecs[1] = rawfile.IovecFromBytes(spill[:length])
		message.Msg.Iovlen = 2
		o.batchSpilled[slot] = true
	}
}

func bytesFromIovec(iovec unix.Iovec) []byte {
	return unsafe.Slice(iovec.Base, int(iovec.Len))
}

func (o *goDarwinIO) compactBatch() {
	slotSize := o.stack.mtu + PacketOffset
	for slot := o.batchStart; slot < o.batchCount; slot++ {
		target := slot - o.batchStart
		source := &o.batchMessages[slot]
		sourceIovecs := unsafe.Slice(source.Msg.Iov, int(source.Msg.Iovlen))
		targetIovecs := o.batchIovecs[target*goDarwinBatchIovecs : target*goDarwinBatchIovecs+len(sourceIovecs)]
		copy(targetIovecs, sourceIovecs)
		for index := range targetIovecs {
			base := uintptr(unsafe.Pointer(targetIovecs[index].Base))
			headerStart := uintptr(unsafe.Pointer(&o.batchHeaders[slot*goDarwinBatchHeader]))
			if base >= headerStart && base < headerStart+goDarwinBatchHeader {
				copy(o.batchHeaders[target*goDarwinBatchHeader:(target+1)*goDarwinBatchHeader], o.batchHeaders[slot*goDarwinBatchHeader:(slot+1)*goDarwinBatchHeader])
				targetIovecs[index].Base = &o.batchHeaders[target*goDarwinBatchHeader+int(base-headerStart)]
				continue
			}
			if o.batchSpilled[slot] {
				spillStart := uintptr(unsafe.Pointer(&o.batchSpill[slot*slotSize]))
				if base >= spillStart && base < spillStart+uintptr(slotSize) {
					copy(o.batchSpill[target*slotSize:(target+1)*slotSize], o.batchSpill[slot*slotSize:(slot+1)*slotSize])
					targetIovecs[index].Base = &o.batchSpill[target*slotSize+int(base-spillStart)]
				}
			}
		}
		o.batchMessages[target] = rawfile.MsgHdrX{}
		o.batchMessages[target].Msg.Iov = &targetIovecs[0]
		o.batchMessages[target].Msg.Iovlen = int32(len(targetIovecs))
		o.batchSpilled[target] = o.batchSpilled[slot]
	}
	o.batchCount -= o.batchStart
	o.batchStart = 0
}

func (o *goDarwinIO) writePacket(frame [][]byte) error {
	o.transmitAccess.Lock()
	defer o.transmitAccess.Unlock()
	return o.writePacketLocked(frame)
}

func (o *goDarwinIO) writePacketLocked(frame [][]byte) error {
	defer func() { clear(o.transmitIovecs) }()
	if o.gateRoom(1) == 0 {
		o.gateBlockLocked()
		return errGoTransmitBlocked
	}
	headerVec := packetHeaderVec6
	if header.IPVersion(frame[0]) == header.IPv4Version {
		headerVec = packetHeaderVec4
	}
	iovecs := append(o.transmitIovecs[:0], headerVec)
	for _, segment := range frame {
		if len(segment) == 0 {
			continue
		}
		iovecs = append(iovecs, rawfile.IovecFromBytes(segment))
	}
	o.transmitIovecs = iovecs
	for {
		errno := rawfile.NonBlockingWriteIovec(o.tunFd, iovecs)
		if errno == 0 {
			o.gateSubmitted++
			return nil
		}
		if errno == unix.EINTR {
			if o.closing.Load() {
				return os.ErrClosed
			}
			continue
		}
		if errno == unix.ENOSPC {
			o.gateSubmitted++
			o.recordWriteError(errno)
			o.gateBlockLocked()
			return errGoTransmitBlocked
		}
		if errno == unix.ENOBUFS || errno == unix.EAGAIN {
			if o.closing.Load() {
				return os.ErrClosed
			}
			o.gateBlockLocked()
			return errGoTransmitBlocked
		}
		return errno
	}
}

func (o *goDarwinIO) transmitPrefix() int {
	return PacketOffset
}

func (o *goDarwinIO) transmitChecksumOffload() bool {
	return false
}

func (o *goDarwinIO) transmitSegmentOffload() bool {
	return false
}

func (o *goDarwinIO) armTransmitWritable() (bool, error) {
	if o.gateBlocked.Load() {
		return true, nil
	}
	_, err := unix.Kevent(o.kqueueFd, o.transmitWritableEvent[:], nil, nil)
	if err != nil {
		return false, E.Cause(err, "go: arm EVFILT_WRITE")
	}
	return true, nil
}

func (o *goDarwinIO) takeTransmitWritable() bool {
	return o.transmitWritable.Swap(false)
}

func (o *goDarwinIO) wake() {
	_, _ = unix.Kevent(o.kqueueFd, o.wakeEvent[:], nil, nil)
}

func (o *goDarwinIO) close() error {
	o.closing.Store(true)
	return unix.Close(o.kqueueFd)
}

func (o *goDarwinIO) writePacketBatch(frames []goUDPFrame) error {
	o.transmitAccess.Lock()
	defer o.transmitAccess.Unlock()
	defer func() {
		clear(o.packetMessages[:])
		clear(o.packetIovecs[:])
	}()
	o.flushLocked()
	limit := len(frames)
	for index := 0; index < len(frames); {
		room := o.gateRoom(min(len(frames)-index, limit))
		if room == 0 || o.batchCount > o.batchStart {
			o.gateBlockLocked()
			o.droppedEngineFrames.record(o.stack.logger, "UDP frames")
			return errGoFrameDropped
		}
		frame := &frames[index]
		if frame.length+len(frame.payload) > goDarwinBatchFrameLimit {
			segments := [2][]byte{frame.header[:frame.length], frame.payload}
			err := o.writePacketLocked(segments[:])
			if err == errGoTransmitBlocked {
				o.droppedEngineFrames.record(o.stack.logger, "UDP frames")
				return errGoFrameDropped
			} else if err != nil {
				return err
			}
			index++
			continue
		}
		count := 0
		for count < room {
			next := &frames[index+count]
			if next.length+len(next.payload) > goDarwinBatchFrameLimit {
				break
			}
			iovecs := o.packetIovecs[count*3 : (count+1)*3]
			iovecs[0] = packetHeaderVec6
			if next.length == header.IPv4MinimumSize+header.UDPMinimumSize {
				iovecs[0] = packetHeaderVec4
			}
			iovecs[1] = rawfile.IovecFromBytes(next.header[:next.length])
			iovecCount := 2
			if len(next.payload) > 0 {
				iovecs[2] = rawfile.IovecFromBytes(next.payload)
				iovecCount++
			}
			o.packetMessages[count] = rawfile.MsgHdrX{}
			o.packetMessages[count].Msg.Iov = &iovecs[0]
			o.packetMessages[count].Msg.Iovlen = int32(iovecCount)
			count++
		}
		written, errno := rawfile.NonBlockingSendMMsg(o.tunFd, o.packetMessages[:count])
		if errno == unix.EINTR {
			continue
		}
		if (errno == unix.EMSGSIZE || errno == unix.ENOBUFS) && count > 1 {
			limit = (count + 1) / 2
			continue
		}
		if errno == unix.ENOBUFS || errno == unix.EAGAIN {
			o.gateBlockLocked()
			o.droppedEngineFrames.record(o.stack.logger, "UDP frames")
			return errGoFrameDropped
		}
		if errno != 0 {
			o.gateSubmitted += int64(count)
			o.recordWriteError(errno)
			return errGoFrameDropped
		}
		if written == 0 {
			return unix.EIO
		}
		o.gateSubmitted += int64(written)
		index += written
	}
	return nil
}
