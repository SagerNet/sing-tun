package tun

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type Go struct {
	ctx                  context.Context
	tun                  Tun
	mtu                  int
	handler              Handler
	logger               logger.Logger
	broadcastAddr        netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
	udpTimeout           time.Duration
	icmpTimeout          time.Duration
	udpNATOptions        UDPNatOptions
	memoryPressure       func() MemoryPressure
	udpNats              []*UDPNat
	udpIdentification    atomic.Uint32
	dispatcher           *ForwardDispatcher
	directory            goFlowDirectory
	access               sync.Mutex
	engines              []*goEngine
	closed               atomic.Bool
}

func NewGo(options StackOptions) *Go {
	return &Go{
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
			Timeout:          options.UDPTimeout,
			Mapping:          options.UDPMapping,
			Filtering:        options.UDPFiltering,
			MaxSize:          options.UDPNATMax,
			InterfaceFinder:  options.InterfaceFinder,
			ExcludeInterface: []string{options.TunOptions.Name},
		},
		memoryPressure: options.MemoryPressure,
	}
}

func (s *Go) Start() error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed.Load() {
		return E.New("stack is closed")
	}
	queues, err := newGoPlatformQueues(s)
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
	natCount := uint32(1)
	if udpNATOptions.Mapping == NATMappingAddressAndPortDependent {
		natCount = min(uint32(len(queues)), maxSize)
	}
	udpNats := make([]*UDPNat, natCount)
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
	s.udpNats = udpNats
	s.dispatcher = NewForwardDispatcher(s.handler, &goWriteback{platformIO: queues[0]}, s.logger, s.udpTimeout, s.icmpTimeout)
	if len(queues) > 1 {
		s.directory.flows = make(map[flowKey]*GoConn)
		if natCount > 1 {
			s.directory.udpFlows = make(map[udpNatSessionKey]*GoPacketConn)
		}
	}
	s.engines = make([]*goEngine, len(queues))
	for index, queue := range queues {
		s.engines[index] = newGoEngine(s, queue, len(queues))
		s.engines[index].udpNat = udpNats[index%int(natCount)]
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

type goFlowDirectory struct {
	access   sync.RWMutex
	flows    map[flowKey]*GoConn
	udpFlows map[udpNatSessionKey]*GoPacketConn
}

func (d *goFlowDirectory) insert(key flowKey, conn *GoConn) {
	if d.flows == nil {
		return
	}
	d.access.Lock()
	d.flows[key] = conn
	d.access.Unlock()
}

func (d *goFlowDirectory) remove(key flowKey, conn *GoConn) {
	if d.flows == nil {
		return
	}
	d.access.Lock()
	if d.flows[key] == conn {
		delete(d.flows, key)
	}
	d.access.Unlock()
}

func (d *goFlowDirectory) lookup(key flowKey) *GoConn {
	if d.flows == nil {
		return nil
	}
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
