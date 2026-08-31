package tun

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/unix"
)

type networkUpdateMonitor struct {
	routeUpdate   chan netlink.RouteUpdate
	linkUpdate    chan netlink.LinkUpdate
	addressUpdate chan netlink.AddrUpdate
	close         chan struct{}

	dirty atomic.Bool

	access    sync.Mutex
	callbacks list.List[NetworkUpdateCallback]
	logger    logger.Logger
}

var ErrNetlinkBanned = E.New(
	"netlink socket in Android is banned by Google, " +
		"use the root or system (ADB) user to run sing-box, " +
		"or switch to the sing-box Android graphical interface client",
)

const (
	routeUpdateBufferSize = 8192
	linkUpdateBufferSize  = 32
	addrUpdateBufferSize  = 32
)

func NewNetworkUpdateMonitor(logger logger.Logger) (NetworkUpdateMonitor, error) {
	monitor := &networkUpdateMonitor{
		routeUpdate:   make(chan netlink.RouteUpdate, routeUpdateBufferSize),
		linkUpdate:    make(chan netlink.LinkUpdate, linkUpdateBufferSize),
		addressUpdate: make(chan netlink.AddrUpdate, addrUpdateBufferSize),
		close:         make(chan struct{}),
		logger:        logger,
	}
	// check is netlink banned by google
	if runtime.GOOS == "android" {
		netlinkSocket, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_ROUTE)
		if err != nil {
			return nil, ErrNetlinkBanned
		}
		err = unix.Bind(netlinkSocket, &unix.SockaddrNetlink{
			Family: unix.AF_NETLINK,
		})
		unix.Close(netlinkSocket)
		if err != nil {
			return nil, ErrNetlinkBanned
		}
	}
	return monitor, nil
}

func (m *networkUpdateMonitor) Start() error {
	err := netlink.RouteSubscribe(m.routeUpdate, m.close)
	if err != nil {
		return E.Cause(err, "subscribe route updates")
	}
	err = netlink.LinkSubscribe(m.linkUpdate, m.close)
	if err != nil {
		return E.Cause(err, "subscribe link updates")
	}
	err = netlink.AddrSubscribe(m.addressUpdate, m.close)
	if err != nil {
		return E.Cause(err, "subscribe address updates")
	}
	go m.readRouteLoop()
	go m.readLinkLoop()
	go m.readAddrLoop()
	go m.emitLoop(time.Second)
	return nil
}

func (m *networkUpdateMonitor) readRouteLoop() {
	for {
		select {
		case <-m.close:
			return
		case <-m.routeUpdate:
			m.dirty.Store(true)
		}
	}
}

func (m *networkUpdateMonitor) readLinkLoop() {
	for {
		select {
		case <-m.close:
			return
		case <-m.linkUpdate:
			m.dirty.Store(true)
		}
	}
}

func (m *networkUpdateMonitor) readAddrLoop() {
	for {
		select {
		case <-m.close:
			return
		case <-m.addressUpdate:
			m.dirty.Store(true)
		}
	}
}

func (m *networkUpdateMonitor) emitLoop(minDuration time.Duration) {
	ticker := time.NewTicker(minDuration)
	defer ticker.Stop()
	for {
		select {
		case <-m.close:
			return
		case <-ticker.C:
			if m.dirty.CompareAndSwap(true, false) {
				m.emit()
			}
		}
	}
}

func (m *networkUpdateMonitor) Close() error {
	select {
	case <-m.close:
		return os.ErrClosed
	default:
	}
	close(m.close)
	return nil
}
