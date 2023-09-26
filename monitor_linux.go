package tun

import (
	"os"
	"runtime"
	"sync"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/unix"
)

type networkUpdateMonitor struct {
	routeUpdate chan netlink.RouteUpdate
	linkUpdate  chan netlink.LinkUpdate
	close       chan struct{}

	access    sync.Mutex
	callbacks list.List[NetworkUpdateCallback]
	logger    logger.Logger
}

func NewNetworkUpdateMonitor(logger logger.Logger) (NetworkUpdateMonitor, error) {
	monitor := &networkUpdateMonitor{
		routeUpdate: make(chan netlink.RouteUpdate, 2),
		linkUpdate:  make(chan netlink.LinkUpdate, 2),
		close:       make(chan struct{}),
		logger:      logger,
	}
	// check is netlink banned by google
	if runtime.GOOS == "android" {
		netlinkSocket, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_ROUTE)
		if err != nil {
			return nil, os.ErrInvalid
		}
		err = unix.Bind(netlinkSocket, &unix.SockaddrNetlink{
			Family: unix.AF_NETLINK,
		})
		unix.Close(netlinkSocket)
		if err != nil {
			return nil, os.ErrInvalid
		}
	}
	return monitor, nil
}

func (m *networkUpdateMonitor) Start() error {
	err := netlink.RouteSubscribe(m.routeUpdate, m.close)
	if err != nil {
		return err
	}
	err = netlink.LinkSubscribe(m.linkUpdate, m.close)
	if err != nil {
		return err
	}
	go m.loopUpdate()
	return nil
}

func (m *networkUpdateMonitor) loopUpdate() {
	for {
		select {
		case <-m.close:
			return
		case <-m.routeUpdate:
		case <-m.linkUpdate:
		}
		m.emit()
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
