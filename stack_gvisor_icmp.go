//go:build with_gvisor

package tun

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ICMPForwarder struct {
	ctx       context.Context
	stack     *stack.Stack
	handler   Handler
	directNat *RouteMapping
}

func NewICMPForwarder(ctx context.Context, stack *stack.Stack, handler Handler, timeout time.Duration) *ICMPForwarder {
	return &ICMPForwarder{
		ctx:       ctx,
		stack:     stack,
		handler:   handler,
		directNat: NewRouteMapping(timeout),
	}
}

func (f *ICMPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
		icmpHdr := header.ICMPv4(pkt.TransportHeader().Slice())
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
			return false
		}
		sourceAddr := M.AddrFromIP(ipHdr.SourceAddressSlice())
		destinationAddr := M.AddrFromIP(ipHdr.DestinationAddressSlice())
		rawAction := f.directNat.Lookup(DirectRouteSession{Source: sourceAddr, Destination: destinationAddr}, func() DirectRouteAction {
			destination, pErr := f.handler.PrepareConnection(
				N.NetworkICMPv4,
				M.SocksaddrFrom(sourceAddr, 0),
				M.SocksaddrFrom(destinationAddr, 0),
				&ICMPBackWriter{
					stack:         f.stack,
					packet:        pkt,
					source:        ipHdr.SourceAddress(),
					sourceNetwork: header.IPv4ProtocolNumber,
				},
			)
			if pErr != nil {
				return &DirectRouteReject{
					Drop: pErr == ErrDrop,
				}
			}
			return destination
		})
		switch action := rawAction.(type) {
		case *DirectRouteReject:
			if action.Drop {
				return true
			}
		case DirectRouteDestination:
			// TODO: handle error
			pkt.IncRef()
			_ = action.WritePacketBuffer(pkt)
			return true
		}
		icmpHdr.SetType(header.ICMPv4EchoReply)
		sourceAddress := ipHdr.SourceAddress()
		ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
		ipHdr.SetDestinationAddress(sourceAddress)
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], pkt.Data().Checksum()))
		ipHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		outgoingEP, err := f.stack.GetNetworkEndpoint(DefaultNIC, header.IPv4ProtocolNumber)
		if err != nil {
			// TODO: log error
			return true
		}
		route, err := f.stack.FindRoute(
			DefaultNIC,
			id.LocalAddress,
			id.RemoteAddress,
			header.IPv6ProtocolNumber,
			false,
		)
		if err != nil {
			// TODO: log error
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
		sourceAddr := M.AddrFromIP(ipHdr.SourceAddressSlice())
		destinationAddr := M.AddrFromIP(ipHdr.DestinationAddressSlice())
		rawAction := f.directNat.Lookup(DirectRouteSession{Source: sourceAddr, Destination: destinationAddr}, func() DirectRouteAction {
			destination, pErr := f.handler.PrepareConnection(
				N.NetworkICMPv6,
				M.SocksaddrFrom(sourceAddr, 0),
				M.SocksaddrFrom(destinationAddr, 0),
				&ICMPBackWriter{
					stack:         f.stack,
					packet:        pkt,
					source:        ipHdr.SourceAddress(),
					sourceNetwork: header.IPv6ProtocolNumber,
				},
			)
			if pErr != nil {
				return &DirectRouteReject{
					Drop: pErr == ErrDrop,
				}
			}
			return destination
		})
		switch action := rawAction.(type) {
		case *DirectRouteReject:
			if action.Drop {
				return true
			}
		case DirectRouteDestination:
			pkt.IncRef()
			_ = action.WritePacketBuffer(pkt)
			return true
		}
		icmpHdr.SetType(header.ICMPv6EchoReply)
		sourceAddress := ipHdr.SourceAddress()
		ipHdr.SetSourceAddress(ipHdr.DestinationAddress())
		ipHdr.SetDestinationAddress(sourceAddress)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmpHdr,
			Src:    ipHdr.SourceAddress(),
			Dst:    ipHdr.DestinationAddress(),
		}))
		outgoingEP, err := f.stack.GetNetworkEndpoint(DefaultNIC, header.IPv4ProtocolNumber)
		if err != nil {
			// TODO: log error
			return true
		}
		route, err := f.stack.FindRoute(
			DefaultNIC,
			id.LocalAddress,
			id.RemoteAddress,
			header.IPv6ProtocolNumber,
			false,
		)
		if err != nil {
			// TODO: log error
			return true
		}
		defer route.Release()
		outgoingEP.(ipv6.ExportedEndpoint).WritePacketDirect(route, pkt)
		return true
	}
}

type ICMPBackWriter struct {
	access        sync.Mutex
	stack         *stack.Stack
	packet        *stack.PacketBuffer
	source        tcpip.Address
	sourceNetwork tcpip.NetworkProtocolNumber
}

func (w *ICMPBackWriter) WritePacket(p []byte) error {
	if w.sourceNetwork == header.IPv4ProtocolNumber {
		route, err := w.stack.FindRoute(
			DefaultNIC,
			header.IPv4(p).SourceAddress(),
			w.source,
			w.sourceNetwork,
			false,
		)
		if err != nil {
			return gonet.TranslateNetstackError(err)
		}
		defer route.Release()
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(p),
		})
		defer packet.DecRef()
		err = route.WriteHeaderIncludedPacket(packet)
		if err != nil {
			return gonet.TranslateNetstackError(err)
		}
	} else {
		route, err := w.stack.FindRoute(
			DefaultNIC,
			header.IPv6(p).SourceAddress(),
			w.source,
			w.sourceNetwork,
			false,
		)
		if err != nil {
			return gonet.TranslateNetstackError(err)
		}
		defer route.Release()
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(p),
		})
		defer packet.DecRef()
		err = route.WriteHeaderIncludedPacket(packet)
		if err != nil {
			return gonet.TranslateNetstackError(err)
		}
	}
	return nil
}
