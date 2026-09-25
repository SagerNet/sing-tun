package tun

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type Go struct {
	ctx                    context.Context
	tun                    Tun
	mtu                    int
	handler                Handler
	logger                 logger.Logger
	broadcastAddr          netip.Addr
	inet4LoopbackAddress   []netip.Addr
	inet6LoopbackAddress   []netip.Addr
	udpTimeout             time.Duration
	icmpTimeout            time.Duration
	udpNATOptions          UDPNatOptions
	memoryPressure         func() MemoryPressure
	udpNats                []*UDPNat
	fragmentIdentification atomic.Uint32
	dispatcher             *ForwardDispatcher
	directory              goFlowDirectory
	congestion             *goCongestionOps
	queueFactory           func(stack *Go) ([]goPlatformIO, error)
	access                 sync.Mutex
	engines                []*goEngine
	closed                 atomic.Bool
	validateChecksum       bool
}

func NewGo(options StackOptions) (*Go, error) {
	congestion, err := goLookupCongestionControl(options.TCPCongestionControl)
	if err != nil {
		return nil, err
	}
	stack := &Go{
		congestion:           congestion,
		queueFactory:         newGoPlatformQueues,
		ctx:                  options.Context,
		tun:                  options.Tun,
		mtu:                  int(options.TunOptions.MTU),
		handler:              options.Handler,
		logger:               options.Logger,
		broadcastAddr:        BroadcastAddr(options.TunOptions.Inet4Address),
		inet4LoopbackAddress: options.TunOptions.Inet4LoopbackAddress,
		inet6LoopbackAddress: options.TunOptions.Inet6LoopbackAddress,
		udpTimeout:           options.UDPTimeout,
		icmpTimeout:          options.ICMPTimeout,
		udpNATOptions: UDPNatOptions{
			Timeout:         options.UDPTimeout,
			Mapping:         options.UDPMapping,
			Filtering:       options.UDPFiltering,
			MaxSize:         options.UDPNATMax,
			InterfaceFinder: options.InterfaceFinder,
		},
		memoryPressure: options.MemoryPressure,
		directory: goFlowDirectory{
			flows:      make(map[flowKey]*GoConn),
			udpSockets: make(map[netip.AddrPort]*GoUDPConn),
			listeners:  make(map[netip.AddrPort]*GoListener),
		},
	}
	memoryTun, isMemoryTun := options.Tun.(*MemoryTun)
	if isMemoryTun {
		stack.validateChecksum = true
		stack.queueFactory = func(current *Go) ([]goPlatformIO, error) {
			return []goPlatformIO{&goMemoryIO{stack: current, tun: memoryTun, handed: make([]*buf.Buffer, 0, goReadBatch), blocked: make(map[*OutboundQueue]*goBlockedWriters)}}, nil
		}
	}
	return stack, nil
}

func (s *Go) Start() error {
	s.access.Lock()
	defer s.access.Unlock()
	queues, err := s.queueFactory(s)
	if err != nil {
		return err
	}
	for index, queue := range queues {
		err = queue.start()
		if err == nil {
			continue
		}
		if index > 0 && errors.Is(err, errGoQueueUnavailable) {
			queues = queues[:index]
			break
		}
		return E.Errors(err, goCloseQueues(queues[:index]))
	}
	natCount := uint32(1)
	var udpNats []*UDPNat
	if s.handler != nil {
		udpNATOptions := s.udpNATOptions
		udpNATOptions.Handler = s.handler
		udpNATOptions.Prepare = s.prepareUDPConnection
		maxSize := udpNATOptions.MaxSize
		if maxSize == 0 {
			if runtime.GOOS == "ios" {
				maxSize = 4096
			} else {
				maxSize = 16384
			}
		}
		if udpNATOptions.Mapping == NATMappingAddressAndPortDependent {
			natCount = min(uint32(len(queues)), maxSize)
		}
		udpNats = make([]*UDPNat, natCount)
		for index := range udpNats {
			udpNATOptions.Shared = index+int(natCount) < len(queues)
			udpNATOptions.MaxSize = maxSize / natCount
			if uint32(index) < maxSize%natCount {
				udpNATOptions.MaxSize++
			}
			udpNat := NewUDPNat(udpNATOptions)
			err = udpNat.Start()
			if err != nil {
				udpNat.Close()
				for _, started := range udpNats[:index] {
					started.Close()
				}
				return E.Errors(err, goCloseQueues(queues))
			}
			udpNats[index] = udpNat
		}
		s.dispatcher = NewForwardDispatcher(s.handler, &goWriteback{platformIO: queues[0]}, s.logger, s.udpTimeout, s.icmpTimeout)
	}
	s.udpNats = udpNats
	if natCount > 1 {
		s.directory.udpFlows = make(map[udpNatSessionKey]*GoPacketConn)
	}
	s.engines = make([]*goEngine, len(queues))
	for index, queue := range queues {
		s.engines[index] = newGoEngine(s, queue, len(queues))
		if udpNats != nil {
			s.engines[index].udpNat = udpNats[index%int(natCount)]
		}
	}
	for _, engine := range s.engines {
		go engine.run()
	}
	return nil
}

func goCloseQueues(queues []goPlatformIO) error {
	var err error
	for _, queue := range queues {
		err = E.Errors(err, queue.close())
	}
	return err
}

func (s *Go) HasEndpoint(protocol uint8, local, remote netip.AddrPort) bool {
	if s.closed.Load() || !local.IsValid() || !remote.IsValid() {
		return false
	}
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	if local.Addr().Is4() != remote.Addr().Is4() {
		return false
	}
	s.directory.access.RLock()
	defer s.directory.access.RUnlock()
	switch protocol {
	case uint8(header.TCPProtocolNumber):
		return s.directory.flows[flowKey{protocol: protocol, source: remote, destination: local}] != nil || s.directory.listeners[local] != nil
	case uint8(header.UDPProtocolNumber):
		socket := s.directory.udpSockets[local]
		return socket != nil && (!socket.connected || socket.remote == remote)
	default:
		return false
	}
}

type goFlowDirectory struct {
	access     sync.RWMutex
	flows      map[flowKey]*GoConn
	udpFlows   map[udpNatSessionKey]*GoPacketConn
	udpSockets map[netip.AddrPort]*GoUDPConn
	listeners  map[netip.AddrPort]*GoListener
}

func (d *goFlowDirectory) insertListener(listener *GoListener) {
	d.access.Lock()
	if len(listener.engine.stack.engines) > 1 {
		listener.engine.tcpListeners[listener.local] = listener
	}
	d.listeners[listener.local] = listener
	d.access.Unlock()
}

func (d *goFlowDirectory) removeListener(listener *GoListener) {
	d.access.Lock()
	if len(listener.engine.stack.engines) > 1 && listener.engine.tcpListeners[listener.local] == listener {
		delete(listener.engine.tcpListeners, listener.local)
	}
	if d.listeners[listener.local] == listener {
		delete(d.listeners, listener.local)
	}
	d.access.Unlock()
}

func (d *goFlowDirectory) lookupListener(local netip.AddrPort) *GoListener {
	d.access.RLock()
	listener := d.listeners[local]
	d.access.RUnlock()
	return listener
}

func (d *goFlowDirectory) insertUDPSocket(socket *GoUDPConn) {
	d.access.Lock()
	if len(socket.engine.stack.engines) > 1 {
		socket.engine.udpSockets[socket.local] = socket
	}
	d.udpSockets[socket.local] = socket
	d.access.Unlock()
}

func (d *goFlowDirectory) removeUDPSocket(socket *GoUDPConn) {
	d.access.Lock()
	if len(socket.engine.stack.engines) > 1 && socket.engine.udpSockets[socket.local] == socket {
		delete(socket.engine.udpSockets, socket.local)
	}
	if d.udpSockets[socket.local] == socket {
		delete(d.udpSockets, socket.local)
	}
	d.access.Unlock()
}

func (d *goFlowDirectory) lookupUDPSocket(local netip.AddrPort) *GoUDPConn {
	d.access.RLock()
	socket := d.udpSockets[local]
	d.access.RUnlock()
	return socket
}

func (d *goFlowDirectory) insert(key flowKey, conn *GoConn) {
	d.access.Lock()
	if len(conn.engine.stack.engines) > 1 {
		conn.engine.flows[key] = conn
	}
	d.flows[key] = conn
	d.access.Unlock()
}

func (d *goFlowDirectory) remove(key flowKey, conn *GoConn) {
	d.access.Lock()
	if len(conn.engine.stack.engines) > 1 && conn.engine.flows[key] == conn {
		delete(conn.engine.flows, key)
	}
	if d.flows[key] == conn {
		delete(d.flows, key)
	}
	d.access.Unlock()
}

func (d *goFlowDirectory) lookup(key flowKey) *GoConn {
	d.access.RLock()
	conn := d.flows[key]
	d.access.RUnlock()
	return conn
}

func (s *Go) ResetNetwork() {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed.Load() {
		return
	}
	for _, udpNat := range s.udpNats {
		udpNat.Purge()
	}
	s.dispatcher.ResetNetwork()
	for _, engine := range s.engines {
		engine.postMessage(&engine.resetMessage)
	}
}

func (s *Go) Close() error {
	s.access.Lock()
	if !s.closed.CompareAndSwap(false, true) {
		s.access.Unlock()
		return nil
	}
	for _, engine := range s.engines {
		engine.postMessage(&engine.closeMessage)
	}
	s.access.Unlock()
	for _, engine := range s.engines {
		<-engine.exitSignal
	}
	if s.dispatcher != nil {
		s.dispatcher.Close()
	}
	for _, udpNat := range s.udpNats {
		udpNat.Close()
	}
	var err error
	for _, engine := range s.engines {
		err = E.Errors(err, engine.platformIO.close())
	}
	return err
}
