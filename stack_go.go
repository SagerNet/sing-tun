package tun

import (
	"context"
	"errors"
	"net/netip"
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
	udpNat               *UDPNat
	dispatcher           *ForwardDispatcher
	directory            goFlowDirectory
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
	udpNat := NewUDPNat(udpNATOptions)
	err = udpNat.Start()
	if err != nil {
		return E.Errors(err, goCloseQueues(queues))
	}
	s.udpNat = udpNat
	s.dispatcher = NewForwardDispatcher(s.handler, &goWriteback{platformIO: queues[0]}, s.logger, s.udpTimeout, s.icmpTimeout)
	if len(queues) > 1 {
		s.directory.flows = make(map[flowKey]*GoConn)
	}
	s.engines = make([]*goEngine, len(queues))
	for index, queue := range queues {
		s.engines[index] = newGoEngine(s, queue, len(queues))
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

type goWriteback struct {
	platformIO goPlatformIO
}

func (w *goWriteback) ReturnHeadroom() int {
	return w.platformIO.transmitPrefix()
}

func (w *goWriteback) WriteReturnPackets(packets [][]byte) error {
	prefix := w.platformIO.transmitPrefix()
	var writeErr error
	for _, packet := range packets {
		writeErr = E.Errors(writeErr, goIgnoreDropped(w.platformIO.writeFrame([][]byte{packet[prefix:]}, ForwardFrameMeta{})))
	}
	return writeErr
}

type goFlowDirectory struct {
	access sync.RWMutex
	flows  map[flowKey]*GoConn
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
	if s.udpNat != nil {
		s.udpNat.Purge()
	}
	for _, engine := range s.engines {
		engine.postMessage(&engine.resetMessage)
	}
}

func (s *Go) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	for _, engine := range s.engines {
		engine.postMessage(&engine.closeMessage)
	}
	for _, engine := range s.engines {
		<-engine.exitSignal
	}
	s.dispatcher.Close()
	if s.udpNat != nil {
		s.udpNat.Close()
	}
	var err error
	for _, engine := range s.engines {
		err = E.Errors(err, engine.platformIO.close())
	}
	return err
}
