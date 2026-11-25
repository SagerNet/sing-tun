package ping

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const flowEvictionSample = 16

type Port struct {
	ctx         context.Context
	logger      logger.ContextLogger
	controlFunc func(destination netip.Addr) control.Func
	timeout     time.Duration
	maxSize     int

	returnAccess sync.Mutex
	returnPaths  []tun.Return

	flowAccess sync.Mutex
	flows      map[flowKey]*Destination
	lastSweep  time.Time
}

type flowKey struct {
	source      netip.Addr
	destination netip.Addr
	identifier  uint16
}

func NewPort(ctx context.Context, logger logger.ContextLogger, controlFunc func(destination netip.Addr) control.Func, timeout time.Duration, maxSize int) *Port {
	if timeout <= 0 {
		panic("invalid timeout")
	}
	if maxSize <= 0 {
		panic("invalid max size")
	}
	return &Port{
		ctx:         ctx,
		logger:      logger,
		controlFunc: controlFunc,
		timeout:     timeout,
		maxSize:     maxSize,
		flows:       make(map[flowKey]*Destination),
	}
}

func (p *Port) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.IPv4Unspecified(), netip.IPv6Unspecified()
}

func (p *Port) PortMTU() uint32 {
	return 0
}

func (p *Port) AttachReturn(returnPath tun.Return) error {
	p.returnAccess.Lock()
	defer p.returnAccess.Unlock()
	if slices.Contains(p.returnPaths, returnPath) {
		return nil
	}
	p.returnPaths = append(slices.Clip(p.returnPaths), returnPath)
	return nil
}

func (p *Port) DetachReturn(returnPath tun.Return) error {
	p.returnAccess.Lock()
	defer p.returnAccess.Unlock()
	returnPaths := make([]tun.Return, 0, len(p.returnPaths))
	for _, existing := range p.returnPaths {
		if existing != returnPath {
			returnPaths = append(returnPaths, existing)
		}
	}
	p.returnPaths = returnPaths
	return nil
}

func (p *Port) WritePackets(packets [][]byte) error {
	var errs []error
	for _, packet := range packets {
		err := p.writePacket(packet)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}

func (p *Port) writePacket(packet []byte) error {
	var (
		source      netip.Addr
		destination netip.Addr
		identifier  uint16
	)
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.TransportProtocol() != header.ICMPv4ProtocolNumber || ipHdr.PayloadLength() < header.ICMPv4MinimumSize {
			return nil
		}
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
			return nil
		}
		source = ipHdr.SourceAddr()
		destination = ipHdr.DestinationAddr()
		identifier = icmpHdr.Ident()
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.TransportProtocol() != header.ICMPv6ProtocolNumber || ipHdr.PayloadLength() < header.ICMPv6MinimumSize {
			return nil
		}
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
			return nil
		}
		source = ipHdr.SourceAddr()
		destination = ipHdr.DestinationAddr()
		identifier = icmpHdr.Ident()
	default:
		return nil
	}
	flow, err := p.flowFor(source, destination, identifier)
	if err != nil {
		return E.Cause(err, "connect ICMP flow to ", destination)
	}
	err = flow.WritePacket(buf.As(packet))
	if err != nil {
		flow.Close()
		return err
	}
	return nil
}

func (p *Port) flowFor(source netip.Addr, destination netip.Addr, identifier uint16) (*Destination, error) {
	key := flowKey{source: source, destination: destination, identifier: identifier}
	p.flowAccess.Lock()
	defer p.flowAccess.Unlock()
	now := time.Now()
	if now.Sub(p.lastSweep) >= p.timeout {
		p.lastSweep = now
		for oldKey, oldFlow := range p.flows {
			if oldFlow.IsClosed() {
				delete(p.flows, oldKey)
			}
		}
	}
	flow, loaded := p.flows[key]
	if loaded && !flow.IsClosed() {
		return flow, nil
	}
	if !loaded && len(p.flows) >= p.maxSize {
		p.evictFlowLocked()
	}
	var controlFunc control.Func
	if p.controlFunc != nil {
		controlFunc = p.controlFunc(destination)
	}
	flow, err := ConnectDestination(p.ctx, p.logger, controlFunc, destination, portWriter{p}, p.timeout)
	if err != nil {
		return nil, err
	}
	p.flows[key] = flow
	return flow, nil
}

func (p *Port) evictFlowLocked() {
	var (
		visited      int
		oldestKey    flowKey
		oldestFlow   *Destination
		oldestActive time.Time
	)
	for key, flow := range p.flows {
		if flow.IsClosed() {
			delete(p.flows, key)
		} else if lastActive := flow.lastActive.Load(); oldestFlow == nil || lastActive.Before(oldestActive) {
			oldestKey = key
			oldestFlow = flow
			oldestActive = lastActive
		}
		visited++
		if visited >= flowEvictionSample {
			break
		}
	}
	if len(p.flows) >= p.maxSize {
		oldestFlow.Close()
		delete(p.flows, oldestKey)
	}
}

type portWriter struct {
	port *Port
}

func (w portWriter) WritePacket(packet []byte) error {
	w.port.returnAccess.Lock()
	returnPaths := w.port.returnPaths
	w.port.returnAccess.Unlock()
	for _, returnPath := range returnPaths {
		headroom := returnPath.ReturnHeadroom()
		buffer := make([]byte, headroom+len(packet))
		copy(buffer[headroom:], packet)
		unconsumed := returnPath.ReturnPackets([][]byte{buffer})
		if len(unconsumed) == 0 {
			return nil
		}
	}
	return nil
}

func (p *Port) Close() error {
	p.flowAccess.Lock()
	defer p.flowAccess.Unlock()
	var errs []error
	for key, flow := range p.flows {
		errs = append(errs, flow.Close())
		delete(p.flows, key)
	}
	return E.Errors(errs...)
}
