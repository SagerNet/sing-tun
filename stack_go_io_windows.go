package tun

import (
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sagernet/sing-tun/internal/afd"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

const goEngineInlineTransmit = false

const goSessionRingCapacity = 0x800000

const (
	goCompletionKeyTun uintptr = iota + 1
	goCompletionKeyWake
	goCompletionKeySocket
)

const goAFDReadEvents = afd.POLL_RECEIVE | afd.POLL_DISCONNECT | afd.POLL_ABORT | afd.POLL_LOCAL_CLOSE | afd.POLL_CONNECT_FAIL

type goWindowsIO struct {
	stack        *Go
	tun          *NativeTun
	iocp         windows.Handle
	afd          *afd.Device
	waitPacket   *afd.WaitCompletionPacket
	waitArmed    bool
	bridgeArm    windows.Handle
	bridgeClose  windows.Handle
	bridgeDone   chan struct{}
	entries      map[*goAFDEntry]struct{}
	completions  [goSocketEventBatch + 2]afd.OverlappedEntry
	receiveSlots [][]byte
	// wintun's read-wait event is auto-reset and only set by the driver when it appends to
	// the ring; WintunReceivePacket neither re-signals nor resets it (wintun api/session.c:
	// CreateEventW(&SecurityAttributes, FALSE, FALSE, NULL)).
	ringDrained         bool
	droppedEngineFrames goDropCounter
	closing             atomic.Bool
	droppedDataFrames   goDropCounter
}

func newGoPlatformIO(stack *Go) (goPlatformIO, error) {
	return &goWindowsIO{stack: stack}, nil
}

func (o *goWindowsIO) start() error {
	nativeTun, isNative := o.stack.tun.(*NativeTun)
	if !isNative {
		return E.New("go: unsupported TUN implementation")
	}
	o.tun = nativeTun
	err := nativeTun.resizeSessionRing(goSessionRingCapacity)
	if err != nil {
		return E.Cause(err, "go: resize wintun session ring")
	}
	iocp, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return E.Cause(err, "go: create completion port")
	}
	o.iocp = iocp
	device, err := afd.Open(iocp, "sing-tun")
	if err != nil {
		windows.CloseHandle(iocp)
		return E.Cause(err, "go: open afd device")
	}
	o.afd = device
	if afd.WaitCompletionPacketSupported() {
		waitPacket, packetErr := afd.NewWaitCompletionPacket()
		if packetErr != nil {
			device.Close()
			windows.CloseHandle(iocp)
			return E.Cause(packetErr, "go: create wait completion packet")
		}
		o.waitPacket = waitPacket
	} else {
		armEvent, eventErr := windows.CreateEvent(nil, 0, 0, nil)
		if eventErr != nil {
			device.Close()
			windows.CloseHandle(iocp)
			return E.Cause(eventErr, "go: create read wait event")
		}
		closeEvent, eventErr := windows.CreateEvent(nil, 1, 0, nil)
		if eventErr != nil {
			windows.CloseHandle(armEvent)
			device.Close()
			windows.CloseHandle(iocp)
			return E.Cause(eventErr, "go: create read wait close event")
		}
		o.bridgeArm = armEvent
		o.bridgeClose = closeEvent
		o.bridgeDone = make(chan struct{})
		go o.bridgeReadWait()
	}
	o.entries = make(map[*goAFDEntry]struct{})
	slotSize := o.stack.mtu
	storage := make([]byte, goReadBatch*slotSize)
	o.receiveSlots = make([][]byte, goReadBatch)
	for index := range goReadBatch {
		o.receiveSlots[index] = storage[index*slotSize : (index+1)*slotSize]
	}
	o.ringDrained = true
	return nil
}

func (o *goWindowsIO) bridgeReadWait() {
	defer close(o.bridgeDone)
	armHandles := []windows.Handle{o.bridgeArm, o.bridgeClose}
	readHandles := []windows.Handle{o.tun.readWaitHandle(), o.bridgeClose}
	for {
		signaled, err := windows.WaitForMultipleObjects(armHandles, false, windows.INFINITE)
		if err != nil || signaled != windows.WAIT_OBJECT_0 {
			return
		}
		signaled, err = windows.WaitForMultipleObjects(readHandles, false, windows.INFINITE)
		if err != nil || signaled != windows.WAIT_OBJECT_0 {
			return
		}
		windows.PostQueuedCompletionStatus(o.iocp, 0, goCompletionKeyTun, nil)
	}
}

func (o *goWindowsIO) armReadWait() (bool, error) {
	if o.waitArmed {
		return false, nil
	}
	o.waitArmed = true
	if o.waitPacket == nil {
		windows.SetEvent(o.bridgeArm)
		return false, nil
	}
	alreadySignaled, err := o.waitPacket.Associate(o.iocp, o.tun.readWaitHandle(), goCompletionKeyTun)
	if err != nil {
		o.waitArmed = false
		return false, E.Cause(err, "go: associate wintun read event")
	}
	if alreadySignaled {
		o.waitArmed = false
		return true, nil
	}
	return false, nil
}

func (o *goWindowsIO) wait(timeout time.Duration, events []goSocketEvent) (bool, int, error) {
	tunReadable := !o.ringDrained
	if o.ringDrained {
		signaled, err := o.armReadWait()
		if err != nil {
			return false, 0, err
		}
		if signaled {
			tunReadable = true
			o.waitPacket.Cancel()
		}
	}
	var waitMillis uint32
	if tunReadable || timeout == 0 {
		waitMillis = 0
	} else if timeout < 0 {
		waitMillis = windows.INFINITE
	} else {
		waitMillis = uint32((timeout + time.Millisecond - 1) / time.Millisecond)
	}
	var removed uint32
	err := afd.GetQueuedCompletionStatusEx(o.iocp, &o.completions[0], uint32(len(o.completions)), &removed, waitMillis, false)
	if err != nil {
		if err == windows.WAIT_TIMEOUT {
			return tunReadable, 0, nil
		}
		return false, 0, E.Cause(err, "go: wait for completion")
	}
	socketCount := 0
	for index := range removed {
		completion := &o.completions[index]
		switch completion.CompletionKey {
		case goCompletionKeyTun:
			o.waitArmed = false
			tunReadable = true
		case goCompletionKeyWake:
		default:
			entry := (*goAFDEntry)(unsafe.Pointer(completion.Overlapped))
			entry.armed = false
			if entry.cancelled {
				o.releaseEntry(entry)
				continue
			}
			var pollEvents uint32
			if entry.pollInfo.NumberOfHandles > 0 {
				pollEvents = entry.pollInfo.Handles[0].Events
			}
			if uint32(entry.ioStatusBlock.Status) != afd.STATUS_CANCELLED && socketCount < len(events) {
				readable := pollEvents&goAFDReadEvents != 0 || entry.ioStatusBlock.Status != 0
				writable := pollEvents&afd.POLL_SEND != 0
				if readable || writable {
					events[socketCount] = goSocketEvent{token: entry.token, readable: readable, writable: writable}
					socketCount++
				}
			}
			if entry.interest != 0 {
				armErr := o.armEntry(entry)
				if armErr != nil && socketCount < len(events) {
					events[socketCount] = goSocketEvent{token: entry.token, readable: true}
					socketCount++
				}
			}
		}
	}
	return tunReadable, socketCount, nil
}

func (o *goWindowsIO) armEntry(entry *goAFDEntry) error {
	var pollEvents uint32
	if entry.interest&goInterestRead != 0 {
		pollEvents |= goAFDReadEvents
	}
	if entry.interest&goInterestWrite != 0 {
		pollEvents |= afd.POLL_SEND
	}
	err := o.afd.Poll(entry.baseHandle, pollEvents, &entry.ioStatusBlock, &entry.pollInfo)
	if err != nil {
		return err
	}
	entry.armed = true
	return nil
}

func (o *goWindowsIO) registerSocket(socket *goSocket, token uint32, interest uint8) error {
	baseHandle, err := afd.BaseSocket(socket.handle)
	if err != nil {
		return E.Cause(err, "go: query base socket")
	}
	entry := &goAFDEntry{baseHandle: baseHandle, token: token, interest: interest}
	entry.pinner.Pin(entry)
	if o.entries == nil {
		o.entries = make(map[*goAFDEntry]struct{})
	}
	o.entries[entry] = struct{}{}
	socket.entry = entry
	if interest == 0 {
		return nil
	}
	err = o.armEntry(entry)
	if err != nil {
		o.releaseEntry(entry)
		socket.entry = nil
		return E.Cause(err, "go: poll socket")
	}
	return nil
}

func (o *goWindowsIO) releaseEntry(entry *goAFDEntry) {
	delete(o.entries, entry)
	entry.pinner.Unpin()
}

func (o *goWindowsIO) updateSocket(socket *goSocket, interest uint8) error {
	entry := socket.entry
	if entry == nil || entry.interest == interest {
		return nil
	}
	entry.interest = interest
	if entry.armed {
		return o.afd.Cancel(&entry.ioStatusBlock)
	}
	if interest == 0 {
		return nil
	}
	err := o.armEntry(entry)
	if err != nil {
		return E.Cause(err, "go: poll socket")
	}
	return nil
}

func (o *goWindowsIO) unregisterSocket(socket *goSocket) {
	entry := socket.entry
	if entry == nil {
		return
	}
	socket.entry = nil
	entry.interest = 0
	entry.cancelled = true
	if !entry.armed {
		o.releaseEntry(entry)
		return
	}
	o.afd.Cancel(&entry.ioStatusBlock)
}

func (o *goWindowsIO) readBurst(frames []goFrame) (int, bool, error) {
	limit := min(len(frames), len(o.receiveSlots))
	count := 0
	for count < limit {
		n, err := o.tun.receiveInto(o.receiveSlots[count])
		if err != nil {
			return 0, false, err
		}
		if n == 0 {
			o.ringDrained = true
			return count, true, nil
		}
		frames[count] = goFrame{data: o.receiveSlots[count][:n]}
		count++
	}
	o.ringDrained = false
	return count, false, nil
}

func goFatalReadError(err error) bool {
	return true
}

func (o *goWindowsIO) writeFrame(frame [][]byte, meta ForwardFrameMeta) error {
	err := o.transmitFrame(frame)
	if err == windows.ERROR_BUFFER_OVERFLOW {
		o.droppedEngineFrames.record(o.stack.logger, "engine frames")
		return errGoFrameDropped
	}
	return err
}

func (o *goWindowsIO) writeData(frame [][]byte, meta ForwardFrameMeta) error {
	backoff := goTransmitBackoffMin
	waited := time.Duration(0)
	for {
		err := o.transmitFrame(frame)
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return err
		}
		if o.closing.Load() {
			return os.ErrClosed
		}
		if waited >= goTransmitBackoffBudget {
			o.droppedDataFrames.record(o.stack.logger, "data frames")
			return errGoFrameDropped
		}
		time.Sleep(backoff)
		waited += backoff
		backoff = min(backoff*2, goTransmitBackoffMax)
	}
}

func (o *goWindowsIO) transmitFrame(frame [][]byte) error {
	err := o.tun.transmitGather(frame)
	if err == nil || err == windows.ERROR_BUFFER_OVERFLOW || err == os.ErrClosed {
		return err
	}
	return E.Cause(err, "go: wintun send")
}

func (o *goWindowsIO) transmitPrefix() int {
	return 0
}

func (o *goWindowsIO) transmitChecksumOffload() bool {
	return false
}

func (o *goWindowsIO) transmitSegmentOffload() bool {
	return false
}

func (o *goWindowsIO) armTransmitWritable() (bool, error) {
	return false, nil
}

func (o *goWindowsIO) takeTransmitWritable() bool {
	return false
}

func (o *goWindowsIO) wake() {
	_ = windows.PostQueuedCompletionStatus(o.iocp, 0, goCompletionKeyWake, nil)
}

func (o *goWindowsIO) drainWake() {
}

func (o *goWindowsIO) close() error {
	o.closing.Store(true)
	var err error
	if o.waitPacket != nil {
		err = E.Errors(o.waitPacket.Cancel(), o.waitPacket.Close())
	} else {
		windows.SetEvent(o.bridgeClose)
		<-o.bridgeDone
		err = E.Errors(windows.CloseHandle(o.bridgeArm), windows.CloseHandle(o.bridgeClose))
	}
	err = E.Errors(err, o.afd.Close(), windows.CloseHandle(o.iocp))
	for entry := range o.entries {
		entry.pinner.Unpin()
	}
	clear(o.entries)
	return err
}

func (o *goWindowsIO) flush() {
}
