//go:build with_gvisor

package tun

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/header/parse"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

type ICMPForwarder struct {
	stack   *stack.Stack
	handler Handler
	logger  logger.Logger

	returnPath icmpForwarderReturn

	flowAccess    sync.Mutex
	flows         map[icmpFlowKey]time.Time
	lastSweep     time.Time
	attachedPorts map[Port]bool
}

type icmpFlowKey struct {
	v6          bool
	source      netip.Addr
	destination netip.Addr
	identifier  uint16
}

func NewICMPForwarder(stack *stack.Stack, handler Handler, logger logger.Logger) *ICMPForwarder {
	forwarder := &ICMPForwarder{
		stack:         stack,
		handler:       handler,
		logger:        logger,
		flows:         make(map[icmpFlowKey]time.Time),
		attachedPorts: make(map[Port]bool),
	}
	forwarder.returnPath.forwarder = forwarder
	return forwarder
}

func (f *ICMPForwarder) Close() error {
	f.returnPath.closed.Store(true)
	f.flowAccess.Lock()
	defer f.flowAccess.Unlock()
	for port := range f.attachedPorts {
		port.DetachReturn(&f.returnPath)
		delete(f.attachedPorts, port)
	}
	return nil
}

func (f *ICMPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
		icmpHdr := header.ICMPv4(pkt.TransportHeader().Slice())
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
			return false
		}
		identifier := icmpHdr.Ident()
		verdict := f.handler.JudgeFlow(
			uint8(header.ICMPv4ProtocolNumber),
			netip.AddrPortFrom(AddrFromAddress(ipHdr.SourceAddress()), identifier),
			netip.AddrPortFrom(AddrFromAddress(ipHdr.DestinationAddress()), identifier),
		)
		switch verdict.Action {
		case ActionReject, ActionDrop:
			return true
		case ActionFlow:
			if f.forwardFlow(verdict.Port, false, AddrFromAddress(ipHdr.SourceAddress()), AddrFromAddress(ipHdr.DestinationAddress()), identifier, pkt) {
				return true
			}
		}
		icmpHdr.SetType(header.ICMPv4EchoReply)
		sourceAddress := ipHdr.SourceAddress()
		ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
		ipHdr.SetDestinationAddress(sourceAddress)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], pkt.Data().Checksum()))
		ipHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		outgoingEP, gErr := f.stack.GetNetworkEndpoint(DefaultNIC, header.IPv4ProtocolNumber)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "get IPv4 network endpoint"))
			return true
		}
		route, gErr := f.stack.FindRoute(
			DefaultNIC,
			id.LocalAddress,
			id.RemoteAddress,
			header.IPv6ProtocolNumber,
			false,
		)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "find IPv4 route"))
			return true
		}
		defer route.Release()
		outgoingEP.(ipv4.ExportedEndpoint).WritePacketDirect(route, pkt)
		return true
	} else {
		ipHdr := header.IPv6(pkt.NetworkHeader().Slice())
		icmpHdr := header.ICMPv6(pkt.TransportHeader().Slice())
		if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
			return false
		}
		identifier := icmpHdr.Ident()
		verdict := f.handler.JudgeFlow(
			uint8(header.ICMPv6ProtocolNumber),
			netip.AddrPortFrom(AddrFromAddress(ipHdr.SourceAddress()), identifier),
			netip.AddrPortFrom(AddrFromAddress(ipHdr.DestinationAddress()), identifier),
		)
		switch verdict.Action {
		case ActionReject, ActionDrop:
			return true
		case ActionFlow:
			if f.forwardFlow(verdict.Port, true, AddrFromAddress(ipHdr.SourceAddress()), AddrFromAddress(ipHdr.DestinationAddress()), identifier, pkt) {
				return true
			}
		}
		icmpHdr.SetType(header.ICMPv6EchoReply)
		sourceAddress := ipHdr.SourceAddress()
		ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
		ipHdr.SetDestinationAddress(sourceAddress)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      icmpHdr,
			Src:         ipHdr.SourceAddress(),
			Dst:         ipHdr.DestinationAddress(),
			PayloadCsum: pkt.Data().Checksum(),
			PayloadLen:  pkt.Data().Size(),
		}))
		outgoingEP, gErr := f.stack.GetNetworkEndpoint(DefaultNIC, header.IPv4ProtocolNumber)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "get IPv6 network endpoint"))
			return true
		}
		route, gErr := f.stack.FindRoute(
			DefaultNIC,
			id.LocalAddress,
			id.RemoteAddress,
			header.IPv6ProtocolNumber,
			false,
		)
		if gErr != nil {
			f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "find IPv6 route"))
			return true
		}
		defer route.Release()
		outgoingEP.(ipv6.ExportedEndpoint).WritePacketDirect(route, pkt)
		return true
	}
}

func (f *ICMPForwarder) forwardFlow(port Port, v6 bool, source netip.Addr, destination netip.Addr, identifier uint16, pkt *stack.PacketBuffer) bool {
	if port == nil {
		return false
	}
	inet4Address, inet6Address := port.PortAddresses()
	portAddress := inet4Address
	if v6 {
		portAddress = inet6Address
	}
	if !portAddress.IsValid() || !portAddress.IsUnspecified() {
		return false
	}
	f.flowAccess.Lock()
	if !f.attachedPorts[port] {
		err := port.AttachReturn(&f.returnPath)
		if err != nil {
			f.flowAccess.Unlock()
			f.logger.Trace(E.Cause(err, "attach ICMP return path"))
			return false
		}
		f.attachedPorts[port] = true
	}
	now := time.Now()
	if now.Sub(f.lastSweep) >= defaultICMPTimeout {
		f.lastSweep = now
		for key, deadline := range f.flows {
			if now.After(deadline) {
				delete(f.flows, key)
			}
		}
	}
	f.flows[icmpFlowKey{v6: v6, source: source, destination: destination, identifier: identifier}] = now.Add(defaultICMPTimeout)
	f.flowAccess.Unlock()
	networkSlice := pkt.NetworkHeader().Slice()
	transportSlice := pkt.TransportHeader().Slice()
	dataSlice := pkt.Data().AsRange().ToSlice()
	packetSlice := make([]byte, 0, len(networkSlice)+len(transportSlice)+len(dataSlice))
	packetSlice = append(packetSlice, networkSlice...)
	packetSlice = append(packetSlice, transportSlice...)
	packetSlice = append(packetSlice, dataSlice...)
	err := port.WritePackets([][]byte{packetSlice})
	if err != nil {
		f.logger.Trace(E.Cause(err, "forward ICMP packet"))
	}
	return true
}

func (f *ICMPForwarder) lookupFlow(key icmpFlowKey) bool {
	f.flowAccess.Lock()
	defer f.flowAccess.Unlock()
	deadline, loaded := f.flows[key]
	if !loaded {
		return false
	}
	now := time.Now()
	if now.After(deadline) {
		delete(f.flows, key)
		return false
	}
	f.flows[key] = now.Add(defaultICMPTimeout)
	return true
}

type icmpForwarderReturn struct {
	forwarder *ICMPForwarder
	closed    atomic.Bool
}

func (r *icmpForwarderReturn) ReturnHeadroom() int {
	return 0
}

func (r *icmpForwarderReturn) ReturnPackets(packets [][]byte) [][]byte {
	if r.closed.Load() {
		return packets
	}
	unconsumed := packets[:0]
	for _, packet := range packets {
		if !r.forwarder.returnPacket(packet) {
			unconsumed = append(unconsumed, packet)
		}
	}
	return unconsumed
}

func (f *ICMPForwarder) returnPacket(packet []byte) bool {
	if len(packet) == 0 {
		return false
	}
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.TransportProtocol() != header.ICMPv4ProtocolNumber || len(ipHdr.Payload()) < header.ICMPv4MinimumSize {
			return false
		}
		icmpHdr := header.ICMPv4(ipHdr.Payload())
		var key icmpFlowKey
		switch icmpHdr.Type() {
		case header.ICMPv4EchoReply:
			key = icmpFlowKey{
				source:      AddrFromAddress(ipHdr.DestinationAddress()),
				destination: AddrFromAddress(ipHdr.SourceAddress()),
				identifier:  icmpHdr.Ident(),
			}
		case header.ICMPv4TimeExceeded, header.ICMPv4DstUnreachable:
			inner := icmpHdr.Payload()
			if len(inner) < header.IPv4MinimumSize {
				return false
			}
			innerIPHdr := header.IPv4(inner)
			innerHeaderLength := int(innerIPHdr.HeaderLength())
			if innerHeaderLength < header.IPv4MinimumSize || len(inner) < innerHeaderLength+header.ICMPv4MinimumSize {
				return false
			}
			if innerIPHdr.TransportProtocol() != header.ICMPv4ProtocolNumber {
				return false
			}
			innerICMPHdr := header.ICMPv4(inner[innerHeaderLength:])
			key = icmpFlowKey{
				source:      AddrFromAddress(innerIPHdr.SourceAddress()),
				destination: AddrFromAddress(innerIPHdr.DestinationAddress()),
				identifier:  innerICMPHdr.Ident(),
			}
		default:
			return false
		}
		if !f.lookupFlow(key) {
			return false
		}
		return f.writeBack(packet, header.IPv4ProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress())
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.TransportProtocol() != header.ICMPv6ProtocolNumber || len(ipHdr.Payload()) < header.ICMPv6MinimumSize {
			return false
		}
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		if icmpHdr.Type() != header.ICMPv6EchoReply {
			return false
		}
		key := icmpFlowKey{
			v6:          true,
			source:      AddrFromAddress(ipHdr.DestinationAddress()),
			destination: AddrFromAddress(ipHdr.SourceAddress()),
			identifier:  icmpHdr.Ident(),
		}
		if !f.lookupFlow(key) {
			return false
		}
		return f.writeBack(packet, header.IPv6ProtocolNumber, ipHdr.SourceAddress(), ipHdr.DestinationAddress())
	default:
		return false
	}
}

func (f *ICMPForwarder) writeBack(packet []byte, protocol tcpip.NetworkProtocolNumber, localAddress tcpip.Address, remoteAddress tcpip.Address) bool {
	route, gErr := f.stack.FindRoute(DefaultNIC, localAddress, remoteAddress, protocol, false)
	if gErr != nil {
		f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "find route for ICMP reply"))
		return true
	}
	defer route.Release()
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	defer packetBuffer.DecRef()
	if protocol == header.IPv4ProtocolNumber {
		parse.IPv4(packetBuffer)
	} else {
		parse.IPv6(packetBuffer)
	}
	gErr = route.WritePacketDirect(packetBuffer)
	if gErr != nil {
		f.logger.Error(E.Cause(gonet.TranslateNetstackError(gErr), "write ICMP reply"))
	}
	return true
}
