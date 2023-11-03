//go:build with_gvisor

package tun

import (
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

var _ stack.LinkEndpoint = (*LinkEndpointFilter)(nil)

type LinkEndpointFilter struct {
	stack.LinkEndpoint
	Writer N.VectorisedWriter
}

func (w *LinkEndpointFilter) Attach(dispatcher stack.NetworkDispatcher) {
	w.LinkEndpoint.Attach(&networkDispatcherFilter{dispatcher, w.Writer})
}

var _ stack.NetworkDispatcher = (*networkDispatcherFilter)(nil)

type networkDispatcherFilter struct {
	stack.NetworkDispatcher
	writer N.VectorisedWriter
}

func (w *networkDispatcherFilter) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr) {
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
	if destination.IsGlobalUnicast() {
		w.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
		return
	}
	_, _ = bufio.WriteVectorised(w.writer, pkt.AsSlices())
}
