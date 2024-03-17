//go:build with_gvisor

package tun

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat"
)

type UDPForwarder struct {
	ctx    context.Context
	stack  *stack.Stack
	udpNat *udpnat.Service[netip.AddrPort]

	// cache
	cacheProto tcpip.NetworkProtocolNumber
	cacheID    stack.TransportEndpointID
}

func NewUDPForwarder(ctx context.Context, stack *stack.Stack, handler Handler, udpTimeout int64) *UDPForwarder {
	return &UDPForwarder{
		ctx:    ctx,
		stack:  stack,
		udpNat: udpnat.New[netip.AddrPort](udpTimeout, handler),
	}
}

func (f *UDPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	var upstreamMetadata M.Metadata
	upstreamMetadata.Source = M.SocksaddrFrom(AddrFromAddress(id.RemoteAddress), id.RemotePort)
	upstreamMetadata.Destination = M.SocksaddrFrom(AddrFromAddress(id.LocalAddress), id.LocalPort)
	if upstreamMetadata.Source.IsIPv4() {
		f.cacheProto = header.IPv4ProtocolNumber
	} else {
		f.cacheProto = header.IPv6ProtocolNumber
	}
	gBuffer := pkt.Data().ToBuffer()
	sBuffer := buf.NewSize(int(gBuffer.Size()))
	gBuffer.Apply(func(view *buffer.View) {
		sBuffer.Write(view.AsSlice())
	})
	f.cacheID = id
	f.udpNat.NewPacket(
		f.ctx,
		upstreamMetadata.Source.AddrPort(),
		sBuffer,
		upstreamMetadata,
		f.newUDPConn,
	)
	return true
}

func (f *UDPForwarder) newUDPConn(natConn N.PacketConn) N.PacketWriter {
	return &UDPBackWriter{
		stack:         f.stack,
		source:        f.cacheID.RemoteAddress,
		sourcePort:    f.cacheID.RemotePort,
		sourceNetwork: f.cacheProto,
	}
}

type UDPBackWriter struct {
	access        sync.Mutex
	stack         *stack.Stack
	source        tcpip.Address
	sourcePort    uint16
	sourceNetwork tcpip.NetworkProtocolNumber
}

func (w *UDPBackWriter) WritePacket(packetBuffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.IsIP() {
		return E.Cause(os.ErrInvalid, "invalid destination")
	} else if destination.IsIPv4() && w.sourceNetwork == header.IPv6ProtocolNumber {
		destination = M.SocksaddrFrom(netip.AddrFrom16(destination.Addr.As16()), destination.Port)
	} else if destination.IsIPv6() && (w.sourceNetwork == header.IPv4ProtocolNumber) {
		return E.New("send IPv6 packet to IPv4 connection")
	}

	defer packetBuffer.Release()

	route, err := w.stack.FindRoute(
		defaultNIC,
		AddressFromAddr(destination.Addr),
		w.source,
		w.sourceNetwork,
		false,
	)
	if err != nil {
		return wrapStackError(err)
	}
	defer route.Release()

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(packetBuffer.Bytes()),
	})
	defer packet.DecRef()

	packet.TransportProtocolNumber = header.UDPProtocolNumber
	udpHdr := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	pLen := uint16(packet.Size())
	udpHdr.Encode(&header.UDPFields{
		SrcPort: destination.Port,
		DstPort: w.sourcePort,
		Length:  pLen,
	})

	if route.RequiresTXTransportChecksum() && w.sourceNetwork == header.IPv6ProtocolNumber {
		xsum := udpHdr.CalculateChecksum(checksum.Combine(
			route.PseudoHeaderChecksum(header.UDPProtocolNumber, pLen),
			packet.Data().Checksum(),
		))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udpHdr.SetChecksum(xsum)
	}

	err = route.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.UDPProtocolNumber,
		TTL:      route.DefaultTTL(),
		TOS:      0,
	}, packet)

	if err != nil {
		route.Stats().UDP.PacketSendErrors.Increment()
		return wrapStackError(err)
	}

	route.Stats().UDP.PacketsSent.Increment()
	return nil
}

type gUDPConn struct {
	*gonet.UDPConn
}

func (c *gUDPConn) Read(b []byte) (n int, err error) {
	n, err = c.UDPConn.Read(b)
	if err == nil {
		return
	}
	err = wrapError(err)
	return
}

func (c *gUDPConn) Write(b []byte) (n int, err error) {
	n, err = c.UDPConn.Write(b)
	if err == nil {
		return
	}
	err = wrapError(err)
	return
}

func (c *gUDPConn) Close() error {
	return c.UDPConn.Close()
}

func gWriteUnreachable(gStack *stack.Stack, packet *stack.PacketBuffer, err error) (retErr error) {
	if errors.Is(err, syscall.ENETUNREACH) {
		if packet.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			return gWriteUnreachable4(gStack, packet, stack.RejectIPv4WithICMPNetUnreachable)
		} else {
			return gWriteUnreachable6(gStack, packet, stack.RejectIPv6WithICMPNoRoute)
		}
	} else if errors.Is(err, syscall.EHOSTUNREACH) {
		if packet.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			return gWriteUnreachable4(gStack, packet, stack.RejectIPv4WithICMPHostUnreachable)
		} else {
			return gWriteUnreachable6(gStack, packet, stack.RejectIPv6WithICMPNoRoute)
		}
	} else if errors.Is(err, syscall.ECONNREFUSED) {
		if packet.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			return gWriteUnreachable4(gStack, packet, stack.RejectIPv4WithICMPPortUnreachable)
		} else {
			return gWriteUnreachable6(gStack, packet, stack.RejectIPv6WithICMPPortUnreachable)
		}
	}
	return nil
}

func gWriteUnreachable4(gStack *stack.Stack, packet *stack.PacketBuffer, icmpCode stack.RejectIPv4WithICMPType) error {
	err := gStack.NetworkProtocolInstance(header.IPv4ProtocolNumber).(stack.RejectIPv4WithHandler).SendRejectionError(packet, icmpCode, true)
	if err != nil {
		return wrapStackError(err)
	}
	return nil
}

func gWriteUnreachable6(gStack *stack.Stack, packet *stack.PacketBuffer, icmpCode stack.RejectIPv6WithICMPType) error {
	err := gStack.NetworkProtocolInstance(header.IPv6ProtocolNumber).(stack.RejectIPv6WithHandler).SendRejectionError(packet, icmpCode, true)
	if err != nil {
		return wrapStackError(err)
	}
	return nil
}
