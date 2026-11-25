package tun

import (
	"errors"
	"os"
	"runtime"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/netlink/nl"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/unix"
)

const (
	netlinkGroups = unix.RTMGRP_LINK |
		unix.RTMGRP_IPV4_IFADDR |
		unix.RTMGRP_IPV6_IFADDR |
		unix.RTMGRP_IPV4_ROUTE |
		unix.RTMGRP_IPV6_ROUTE
	netlinkReceiveBufferSize = 1 << 20
)

type networkUpdateMonitor struct {
	socket *os.File
	update chan struct{}
	close  chan struct{}

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
		update: make(chan struct{}, 1),
		close:  make(chan struct{}),
		logger: logger,
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
	netlinkSocket, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return E.Cause(err, "create netlink socket")
	}
	groups := uint32(netlinkGroups)
	if runtime.GOOS == "android" {
		groups |= unix.RTMGRP_IPV4_RULE | 1<<(unix.RTNLGRP_IPV6_RULE-1)
	}
	err = unix.Bind(netlinkSocket, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: groups,
	})
	if err != nil {
		unix.Close(netlinkSocket)
		// gVisor rejects these netlink groups with EOPNOTSUPP, or EACCES in releases before 2025-11
		if E.IsMulti(err, unix.EOPNOTSUPP, unix.EACCES) {
			return nil
		}
		return E.Cause(err, "subscribe netlink groups")
	}
	err = unix.SetsockoptInt(netlinkSocket, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, netlinkReceiveBufferSize)
	if err != nil {
		unix.SetsockoptInt(netlinkSocket, unix.SOL_SOCKET, unix.SO_RCVBUF, netlinkReceiveBufferSize)
	}
	m.socket = os.NewFile(uintptr(netlinkSocket), "netlink")
	go m.loopRead()
	go m.loopUpdate(time.Second)
	return nil
}

func (m *networkUpdateMonitor) loopRead() {
	buffer := make([]byte, unix.Getpagesize())
	for {
		n, err := m.socket.Read(buffer)
		if err != nil && !errors.Is(err, unix.ENOBUFS) {
			select {
			case <-m.close:
			default:
				m.logger.Error("read netlink socket: ", err)
			}
			return
		}
		if err == nil && runtime.GOOS != "android" && !isNetworkUpdate(buffer[:n]) {
			continue
		}
		select {
		case m.update <- struct{}{}:
		default:
		}
	}
}

func isNetworkUpdate(buffer []byte) bool {
	messages, err := syscall.ParseNetlinkMessage(buffer)
	if err != nil {
		return true
	}
	return slices.ContainsFunc(messages, func(message syscall.NetlinkMessage) bool {
		if message.Header.Type != unix.RTM_NEWROUTE && message.Header.Type != unix.RTM_DELROUTE {
			return true
		}
		if nl.DeserializeRtMsg(message.Data).Dst_len == 0 {
			return true
		}
		attributes, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return true
		}
		var hasInterface, hasNextHop bool
		for _, attribute := range attributes {
			switch attribute.Attr.Type {
			case unix.RTA_OIF:
				hasInterface = true
			case unix.RTA_GATEWAY, unix.RTA_VIA:
				hasNextHop = true
			}
		}
		return hasInterface && !hasNextHop
	})
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
		case <-m.update:
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
	if m.socket != nil {
		return m.socket.Close()
	}
	return nil
}
