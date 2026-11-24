package tun

import (
	"os"
	"sync"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const goWakeIdentifier = 0

type goPoller struct {
	kqueueDescriptor int
	deviceDescriptor int
	registrations    int
	access           sync.RWMutex
	closed           bool
	events           [goSocketEventBatch + 3]unix.Kevent_t
	changes          [2]unix.Kevent_t
	wakeEvent        [1]unix.Kevent_t
	writableEvent    [1]unix.Kevent_t
	socketTokens     []uint32
	socketInterests  []uint8
}

func (p *goPoller) open(deviceDescriptor int) error {
	kqueueDescriptor, err := unix.Kqueue()
	if err != nil {
		return E.Cause(err, "go: create kqueue")
	}
	changes := append(p.changes[:0], unix.Kevent_t{Ident: goWakeIdentifier, Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_ENABLE | unix.EV_CLEAR})
	if deviceDescriptor >= 0 {
		changes = append(changes, unix.Kevent_t{Ident: uint64(deviceDescriptor), Filter: unix.EVFILT_READ, Flags: unix.EV_ADD | unix.EV_ENABLE})
		p.registrations = 1
	}
	_, err = unix.Kevent(kqueueDescriptor, changes, nil, nil)
	if err != nil {
		unix.Close(kqueueDescriptor)
		return E.Cause(err, "go: register kqueue events")
	}
	p.kqueueDescriptor = kqueueDescriptor
	p.deviceDescriptor = deviceDescriptor
	p.wakeEvent[0] = unix.Kevent_t{Ident: goWakeIdentifier, Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER}
	p.writableEvent[0] = unix.Kevent_t{Ident: uint64(deviceDescriptor), Filter: unix.EVFILT_WRITE, Flags: unix.EV_ADD | unix.EV_ENABLE | unix.EV_ONESHOT}
	return nil
}

func (p *goPoller) wait(timeout time.Duration, events []goSocketEvent) (uint8, int, error) {
	if timeout == 0 && p.registrations == 0 {
		return 0, 0, nil
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
		count, _, errno := unix.RawSyscall6(unix.SYS_KEVENT, uintptr(p.kqueueDescriptor), 0, 0, uintptr(unsafe.Pointer(&p.events[0])), uintptr(len(p.events)), uintptr(unsafe.Pointer(timeoutSpec)))
		eventCount = int(count)
		if errno != 0 {
			err = errno
		}
	} else {
		eventCount, err = unix.Kevent(p.kqueueDescriptor, nil, p.events[:], timeoutSpec)
	}
	if err != nil {
		if err == unix.EINTR {
			return 0, 0, nil
		}
		return 0, 0, E.Cause(err, "go: kevent wait")
	}
	var deviceReady uint8
	socketCount := 0
	for index := range eventCount {
		event := &p.events[index]
		if event.Filter == unix.EVFILT_USER {
			continue
		}
		if int(event.Ident) == p.deviceDescriptor {
			if event.Filter == unix.EVFILT_WRITE {
				deviceReady |= goInterestWrite
				continue
			}
			if event.Flags&unix.EV_ERROR != 0 && event.Data != 0 {
				return 0, 0, unix.Errno(event.Data)
			}
			if event.Flags&unix.EV_EOF != 0 {
				return 0, 0, unix.ECONNRESET
			}
			deviceReady |= goInterestRead
			continue
		}
		if int(event.Ident) >= len(p.socketTokens) || socketCount == len(events) {
			continue
		}
		events[socketCount] = goSocketEvent{
			token:    p.socketTokens[event.Ident],
			readable: event.Filter == unix.EVFILT_READ,
			writable: event.Filter == unix.EVFILT_WRITE,
		}
		socketCount++
	}
	return deviceReady, socketCount, nil
}

func (p *goPoller) registerSocket(socket *goSocket, token uint32, interest uint8) error {
	if socket.fd >= len(p.socketTokens) {
		grown := max(socket.fd+1, 2*len(p.socketTokens), 64)
		p.socketTokens = append(p.socketTokens, make([]uint32, grown-len(p.socketTokens))...)
		p.socketInterests = append(p.socketInterests, make([]uint8, grown-len(p.socketInterests))...)
	}
	p.socketTokens[socket.fd] = token
	p.socketInterests[socket.fd] = 0
	err := p.updateSocket(socket, interest)
	if err != nil {
		return err
	}
	p.registrations++
	return nil
}

func (p *goPoller) updateSocket(socket *goSocket, interest uint8) error {
	current := p.socketInterests[socket.fd]
	if current == interest {
		return nil
	}
	changes := p.changes[:0]
	if current&goInterestRead != interest&goInterestRead {
		changes = append(changes, unix.Kevent_t{Ident: uint64(socket.fd), Filter: unix.EVFILT_READ, Flags: goKqueueFlags(interest&goInterestRead != 0)})
	}
	if current&goInterestWrite != interest&goInterestWrite {
		changes = append(changes, unix.Kevent_t{Ident: uint64(socket.fd), Filter: unix.EVFILT_WRITE, Flags: goKqueueFlags(interest&goInterestWrite != 0)})
	}
	p.socketInterests[socket.fd] = interest
	_, err := unix.Kevent(p.kqueueDescriptor, changes, nil, nil)
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

func (p *goPoller) unregisterSocket(socket *goSocket) {
	p.updateSocket(socket, 0)
	p.socketTokens[socket.fd] = 0
	p.registrations--
}

func (p *goPoller) setDeviceReadEnabled(enabled bool) error {
	if p.deviceDescriptor < 0 {
		return nil
	}
	flags := uint16(unix.EV_DISABLE)
	if enabled {
		flags = unix.EV_ENABLE
	}
	changes := p.changes[:1]
	changes[0] = unix.Kevent_t{Ident: uint64(p.deviceDescriptor), Filter: unix.EVFILT_READ, Flags: flags}
	_, err := unix.Kevent(p.kqueueDescriptor, changes, nil, nil)
	if err != nil {
		return E.Cause(err, "go: update device read")
	}
	return nil
}

func (p *goPoller) armDeviceWritable() error {
	p.access.RLock()
	defer p.access.RUnlock()
	if p.closed {
		return os.ErrClosed
	}
	_, err := unix.Kevent(p.kqueueDescriptor, p.writableEvent[:], nil, nil)
	if err != nil {
		return E.Cause(err, "go: arm EVFILT_WRITE")
	}
	return nil
}

func (p *goPoller) wake() {
	p.access.RLock()
	defer p.access.RUnlock()
	if p.closed {
		return
	}
	_, _ = unix.Kevent(p.kqueueDescriptor, p.wakeEvent[:], nil, nil)
}

func (p *goPoller) close() error {
	p.access.Lock()
	defer p.access.Unlock()
	p.closed = true
	return unix.Close(p.kqueueDescriptor)
}
