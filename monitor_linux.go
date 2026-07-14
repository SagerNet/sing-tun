package tun

import (
	"os"
	"runtime"
	"sync"
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

	access    sync.Mutex
	callbacks list.List[NetworkUpdateCallback]
	logger    logger.Logger
}

var ErrNetlinkBanned = E.New(
	"netlink socket in Android is banned by Google, " +
		"use the root or system (ADB) user to run sing-box, " +
		"or switch to the sing-box Android graphical interface client",
)

func NewNetworkUpdateMonitor(logger logger.Logger) (NetworkUpdateMonitor, error) {
	monitor := &networkUpdateMonitor{
		routeUpdate:   make(chan netlink.RouteUpdate, 2),
		linkUpdate:    make(chan netlink.LinkUpdate, 2),
		addressUpdate: make(chan netlink.AddrUpdate, 2),
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
	go m.loopUpdate(time.Second)
	return nil
}

func (m *networkUpdateMonitor) loopUpdate(minDuration time.Duration) {
	timer := time.NewTimer(minDuration)
	timer.Stop()
	defer timer.Stop()
	var (
		timerC  <-chan time.Time
		pending bool
	)
	for {
		select {
		case <-m.close:
			return
		case <-m.routeUpdate:
		case <-m.linkUpdate:
		case <-m.addressUpdate:
		case <-timerC:
			if pending {
				m.emit()
				pending = false
				timer.Reset(minDuration)
				continue
			}
			timerC = nil
			continue
		}
		if timerC != nil {
			pending = true
			continue
		}
		m.emit()
		timer.Reset(minDuration)
		timerC = timer.C
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
