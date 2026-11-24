package tun

import (
	"encoding/binary"
	"sync"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	goEpollDataDevice int32 = -1
	goEpollDataWake   int32 = -2
)

type goPoller struct {
	epollDescriptor  int
	eventDescriptor  int
	deviceDescriptor int
	registrations    int
	access           sync.RWMutex
	closed           bool
	events           [goSocketEventBatch + 2]unix.EpollEvent
}

func (p *goPoller) open(deviceDescriptor int) error {
	epollDescriptor, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return E.Cause(err, "go: create epoll")
	}
	eventDescriptor, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		unix.Close(epollDescriptor)
		return E.Cause(err, "go: create eventfd")
	}
	if deviceDescriptor >= 0 {
		err = unix.EpollCtl(epollDescriptor, unix.EPOLL_CTL_ADD, deviceDescriptor, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: goEpollDataDevice})
		p.registrations = 1
	}
	if err == nil {
		err = unix.EpollCtl(epollDescriptor, unix.EPOLL_CTL_ADD, eventDescriptor, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: goEpollDataWake})
	}
	if err != nil {
		return E.Errors(E.Cause(err, "go: register epoll events"), unix.Close(epollDescriptor), unix.Close(eventDescriptor))
	}
	p.epollDescriptor = epollDescriptor
	p.eventDescriptor = eventDescriptor
	p.deviceDescriptor = deviceDescriptor
	return nil
}

func (p *goPoller) setDeviceReadEnabled(enabled bool) error {
	if p.deviceDescriptor < 0 {
		return nil
	}
	if enabled {
		err := unix.EpollCtl(p.epollDescriptor, unix.EPOLL_CTL_ADD, p.deviceDescriptor, &unix.EpollEvent{Events: unix.EPOLLIN, Fd: goEpollDataDevice})
		if err != nil {
			return E.Cause(err, "go: enable device read")
		}
		p.registrations++
		return nil
	}
	err := unix.EpollCtl(p.epollDescriptor, unix.EPOLL_CTL_DEL, p.deviceDescriptor, nil)
	if err != nil {
		return E.Cause(err, "go: disable device read")
	}
	p.registrations--
	return nil
}

func (p *goPoller) wait(timeout time.Duration, events []goSocketEvent) (uint8, int, error) {
	if timeout == 0 && p.registrations == 0 {
		return 0, 0, nil
	}
	milliseconds := -1
	if timeout >= 0 {
		milliseconds = int((timeout + time.Millisecond - 1) / time.Millisecond)
	}
	var eventCount int
	var err error
	if timeout == 0 {
		//nolint:staticcheck
		count, _, errno := unix.RawSyscall6(unix.SYS_EPOLL_PWAIT, uintptr(p.epollDescriptor), uintptr(unsafe.Pointer(&p.events[0])), uintptr(len(p.events)), 0, 0, 0)
		eventCount = int(count)
		if errno != 0 {
			err = errno
		}
	} else {
		eventCount, err = unix.EpollWait(p.epollDescriptor, p.events[:], milliseconds)
	}
	if err != nil {
		if err == unix.EINTR {
			return 0, 0, nil
		}
		return 0, 0, E.Cause(err, "go: epoll wait")
	}
	var deviceReady uint8
	socketCount := 0
	for index := range eventCount {
		event := &p.events[index]
		switch event.Fd {
		case goEpollDataWake:
			var value [8]byte
			_, _ = unix.Read(p.eventDescriptor, value[:])
		case goEpollDataDevice:
			if event.Events&(unix.EPOLLERR|unix.EPOLLHUP) != 0 {
				return 0, 0, unix.ECONNRESET
			}
			deviceReady |= goInterestRead
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
	return deviceReady, socketCount, nil
}

func (p *goPoller) registerSocket(socket *goSocket, token uint32, interest uint8) error {
	socket.token = token
	err := unix.EpollCtl(p.epollDescriptor, unix.EPOLL_CTL_ADD, socket.fd, &unix.EpollEvent{Events: goEpollEvents(interest), Fd: int32(token)})
	if err != nil {
		return E.Cause(err, "go: register socket")
	}
	socket.registered = true
	p.registrations++
	return nil
}

func (p *goPoller) updateSocket(socket *goSocket, interest uint8) error {
	operation := unix.EPOLL_CTL_MOD
	if interest == 0 {
		operation = unix.EPOLL_CTL_DEL
	} else if !socket.registered {
		operation = unix.EPOLL_CTL_ADD
	}
	err := unix.EpollCtl(p.epollDescriptor, operation, socket.fd, &unix.EpollEvent{Events: goEpollEvents(interest), Fd: int32(socket.token)})
	if err != nil {
		return E.Cause(err, "go: update socket interest")
	}
	socket.registered = interest != 0
	return nil
}

func (p *goPoller) unregisterSocket(socket *goSocket) {
	p.registrations--
	if !socket.registered {
		return
	}
	unix.EpollCtl(p.epollDescriptor, unix.EPOLL_CTL_DEL, socket.fd, nil)
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

func (p *goPoller) wake() {
	p.access.RLock()
	defer p.access.RUnlock()
	if p.closed {
		return
	}
	var value [8]byte
	binary.NativeEndian.PutUint64(value[:], 1)
	_, _ = unix.Write(p.eventDescriptor, value[:])
}

func (p *goPoller) close() error {
	p.access.Lock()
	defer p.access.Unlock()
	p.closed = true
	return E.Errors(unix.Close(p.epollDescriptor), unix.Close(p.eventDescriptor))
}
