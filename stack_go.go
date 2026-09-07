package tun

import (
	"context"
	"net/netip"
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
	engine               *goEngine
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
	platformIO, err := newGoPlatformIO(s)
	if err != nil {
		return err
	}
	err = platformIO.start()
	if err != nil {
		return err
	}
	udpNATOptions := s.udpNATOptions
	udpNATOptions.Handler = s.handler
	udpNATOptions.Prepare = s.prepareUDPConnection
	udpNat := NewUDPNat(udpNATOptions)
	err = udpNat.Start()
	if err != nil {
		return E.Errors(err, platformIO.close())
	}
	s.udpNat = udpNat
	s.dispatcher = NewForwardDispatcher(s.handler, &goWriteback{platformIO: platformIO}, s.logger, s.udpTimeout, s.icmpTimeout)
	s.engine = newGoEngine(s, platformIO)
	go s.engine.run()
	return nil
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

func (s *Go) ResetNetwork() {
	if s.udpNat != nil {
		s.udpNat.Purge()
	}
	if s.engine != nil {
		s.engine.postMessage(&s.engine.resetMessage)
	}
}

func (s *Go) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	if s.engine != nil {
		s.engine.postMessage(&s.engine.closeMessage)
		<-s.engine.exitSignal
	}
	s.dispatcher.Close()
	if s.udpNat != nil {
		s.udpNat.Close()
	}
	if s.engine != nil {
		return s.engine.platformIO.close()
	}
	return nil
}
