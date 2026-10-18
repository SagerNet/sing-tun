//go:build with_gvisor

package tun

import (
	"net/netip"
	"sync"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

type LinkEndpointFilter struct {
	stack.LinkEndpoint
	BroadcastAddress     netip.Addr
	Writer               GVisorTun
	Dispatcher           *ForwardDispatcher
	Inet4Address         netip.Addr
	Inet6Address         netip.Addr
	Inet4LoopbackAddress []netip.Addr
	Inet6LoopbackAddress []netip.Addr
}

func (w *LinkEndpointFilter) Attach(dispatcher stack.NetworkDispatcher) {
	if dispatcher == nil {
		w.LinkEndpoint.Attach(nil)
		return
	}
	filter := &networkDispatcherFilter{
		NetworkDispatcher:    dispatcher,
		broadcastAddress:     w.BroadcastAddress,
		writer:               w.Writer,
		inet4Address:         w.Inet4Address,
		inet6Address:         w.Inet6Address,
		inet4LoopbackAddress: w.Inet4LoopbackAddress,
		inet6LoopbackAddress: w.Inet6LoopbackAddress,
	}
	filter.dispatchStage = w.Dispatcher.NewStage(nil, filter.resumeJudged)
	w.LinkEndpoint.Attach(filter)
}

type networkDispatcherFilter struct {
	stack.NetworkDispatcher
	broadcastAddress     netip.Addr
	writer               GVisorTun
	dispatchAccess       sync.Mutex
	dispatchStage        *ForwardStage
	inet4Address         netip.Addr
	inet6Address         netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
}

func (w *networkDispatcherFilter) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	var network header.Network
	if protocol == header.IPv4ProtocolNumber {
		if headerPackets, loaded := pkt.Data().PullUp(header.IPv4MinimumSize); loaded {
			network = header.IPv4(headerPackets)
		}
	} else {
		if headerPackets, loaded := pkt.Data().PullUp(header.IPv6MinimumSize); loaded {
			network = header.IPv6(headerPackets)
		}
	}
	if network == nil {
		w.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
		return
	}
	destination := AddrFromAddress(network.DestinationAddress())
	if destination == w.broadcastAddress || !destination.IsGlobalUnicast() {
		w.writer.WritePacket(pkt)
		return
	}
	if w.dispatchStage != nil && pkt.GSOOptions.Type == stack.GSONone && !pkt.GSOOptions.NeedsCsum {
		if view, loaded := pkt.Data().PullUp(pkt.Data().Size()); loaded {
			w.dispatchAccess.Lock()
			consumed := w.dispatch(protocol, destination, view)
			w.dispatchStage.Flush()
			w.dispatchAccess.Unlock()
			if consumed {
				return
			}
		}
	}
	w.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
}

func (w *networkDispatcherFilter) resumeJudged() {
	w.dispatchAccess.Lock()
	defer w.dispatchAccess.Unlock()
	w.dispatchStage.ResumeJudged(func(packet []byte, _ ForwardFrameMeta) {
		var protocol tcpip.NetworkProtocolNumber
		if header.IPVersion(packet) == header.IPv4Version {
			protocol = header.IPv4ProtocolNumber
		} else {
			protocol = header.IPv6ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           buffer.MakeWithData(packet),
			IsForwardedPacket: true,
		})
		w.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
		pkt.DecRef()
	})
	w.dispatchStage.Flush()
}

func (w *networkDispatcherFilter) dispatch(protocol tcpip.NetworkProtocolNumber, destination netip.Addr, view []byte) bool {
	if protocol == header.IPv4ProtocolNumber {
		switch header.IPv4(view).TransportProtocol() {
		case header.TCPProtocolNumber:
			for _, inet4LoopbackAddress := range w.inet4LoopbackAddress {
				if destination == inet4LoopbackAddress {
					return false
				}
			}
		case header.ICMPv4ProtocolNumber:
			if destination == w.inet4Address {
				return false
			}
		}
	} else {
		switch header.IPv6(view).TransportProtocol() {
		case header.TCPProtocolNumber:
			for _, inet6LoopbackAddress := range w.inet6LoopbackAddress {
				if destination == inet6LoopbackAddress {
					return false
				}
			}
		case header.ICMPv6ProtocolNumber:
			if destination == w.inet6Address {
				return false
			}
		}
	}
	return w.dispatchStage.Dispatch(view)
}
