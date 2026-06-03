package tun

import (
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

var _ NetworkUpdateMonitor = (*networkUpdateMonitor)(nil)

type networkUpdateMonitor struct {
	access          sync.Mutex
	callbacks       list.List[NetworkUpdateCallback]
	routeSocketFile *os.File
	closeOnce       sync.Once
	done            chan struct{}
	logger          logger.Logger
}

func NewNetworkUpdateMonitor(logger logger.Logger) (NetworkUpdateMonitor, error) {

	return &networkUpdateMonitor{
		logger: logger,
		done:   make(chan struct{}),
	}, nil
}

// Close implements NetworkUpdateMonitor.
func (m *networkUpdateMonitor) Close() error {
	m.closeOnce.Do(func() {
		close(m.done)
	})
	return nil
}

// Start implements NetworkUpdateMonitor.
func (m *networkUpdateMonitor) Start() error {
	go m.loopUpdate()
	return nil
}

func (m *networkUpdateMonitor) loopUpdate() {
	for {
		select {
		case <-m.done:
			return
		default:
		}
		err := m.loopUpdate0()
		if err != nil {
			m.logger.Error("listen network update: ", err)
			return
		}
	}
}

func (m *networkUpdateMonitor) loopUpdate0() error {
	routeSocket, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, 0)
	if err != nil {
		return err
	}
	err = unix.SetNonblock(routeSocket, true)
	if err != nil {
		unix.Close(routeSocket)
		return err
	}
	routeSocketFile := os.NewFile(uintptr(routeSocket), "route")
	defer routeSocketFile.Close()
	m.routeSocketFile = routeSocketFile
	m.loopUpdate1(routeSocketFile)
	return nil
}

func (m *networkUpdateMonitor) loopUpdate1(routeSocketFile *os.File) {
	buffer := buf.NewPacket()
	defer buffer.Release()

	done := make(chan struct{})
	go func() {
		select {
		case <-m.done:
			routeSocketFile.Close()
		case <-done:
		}
	}()
	n, err := routeSocketFile.Read(buffer.FreeBytes())
	close(done)
	if err != nil {
		return
	}
	buffer.Truncate(n)

	messages, err := route.ParseRIB(route.RIBTypeRoute, buffer.Bytes())
	if err != nil {
		return
	}

	for _, message := range messages {
		if _, isRouteMessage := message.(*route.RouteMessage); isRouteMessage {
			m.emit()
			return
		}
	}
}

// checkUpdate finds the first IPv4 default gateway and emits an update event.
func (m *defaultInterfaceMonitor) checkUpdate() error {
	var defaultInterface *control.Interface
	ribMessage, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return err
	}
	routeMessages, err := route.ParseRIB(route.RIBTypeRoute, ribMessage)
	if err != nil {
		return err
	}

	for _, rawRouteMessage := range routeMessages {
		routeMessage := rawRouteMessage.(*route.RouteMessage)
		if len(routeMessage.Addrs) <= unix.RTAX_NETMASK {
			continue
		}
		destination, isIPv4Destination := routeMessage.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !isIPv4Destination || destination.IP != netip.IPv4Unspecified().As4() {
			continue
		}
		mask, isIPv4Mask := routeMessage.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr)
		if !isIPv4Mask {
			continue
		}
		if ones, _ := net.IPMask(mask.IP[:]).Size(); ones != 0 {
			continue
		}
		flag := unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC
		if routeMessage.Flags&(flag) != flag {
			continue
		}
		routeInterface, err := m.interfaceFinder.ByIndex(routeMessage.Index)
		if err != nil {
			return err
		}
		if routeInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		defaultInterface = routeInterface
		break
	}

	if defaultInterface == nil {
		if m.underNetworkExtension {
			m.logger.Warn("Not implemented: UnderNetworkExtension")
		}
		return ErrNoRoute
	}
	newInterface, err := m.interfaceFinder.ByIndex(defaultInterface.Index)
	if err != nil {
		return E.Cause(err, "find updated interface: ", defaultInterface.Name)
	}
	oldInterface := m.defaultInterface.Swap(newInterface)
	if oldInterface != nil && oldInterface.Equals(*newInterface) {
		return nil
	}
	m.emit(newInterface, 0)
	return nil
}
