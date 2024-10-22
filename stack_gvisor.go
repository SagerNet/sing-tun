//go:build with_gvisor

package tun

import (
	"context"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const WithGVisor = true

const defaultNIC tcpip.NICID = 1

type GVisor struct {
	ctx                    context.Context
	tun                    GVisorTun
	endpointIndependentNat bool
	udpTimeout             time.Duration
	broadcastAddr          netip.Addr
	handler                Handler
	logger                 logger.Logger
	stack                  *stack.Stack
	endpoint               stack.LinkEndpoint
}

type GVisorTun interface {
	Tun
	NewEndpoint() (stack.LinkEndpoint, error)
}

func NewGVisor(
	options StackOptions,
) (Stack, error) {
	gTun, isGTun := options.Tun.(GVisorTun)
	if !isGTun {
		return nil, E.New("gVisor stack is unsupported on current platform")
	}

	gStack := &GVisor{
		ctx:                    options.Context,
		tun:                    gTun,
		endpointIndependentNat: options.EndpointIndependentNat,
		udpTimeout:             options.UDPTimeout,
		broadcastAddr:          BroadcastAddr(options.TunOptions.Inet4Address),
		handler:                options.Handler,
		logger:                 options.Logger,
	}
	return gStack, nil
}

func (t *GVisor) Start() error {
	linkEndpoint, err := t.tun.NewEndpoint()
	if err != nil {
		return err
	}
	linkEndpoint = &LinkEndpointFilter{linkEndpoint, t.broadcastAddr, t.tun}
	ipStack, err := newGVisorStack(linkEndpoint)
	if err != nil {
		return err
	}
	tcpForwarder := tcp.NewForwarder(ipStack, 0, 1024, func(r *tcp.ForwarderRequest) {
		source := M.SocksaddrFrom(AddrFromAddress(r.ID().RemoteAddress), r.ID().RemotePort)
		destination := M.SocksaddrFrom(AddrFromAddress(r.ID().LocalAddress), r.ID().LocalPort)
		pErr := t.handler.PrepareConnection(N.NetworkTCP, source, destination)
		if pErr != nil {
			r.Complete(gWriteUnreachable(t.stack, r.Packet(), err) == os.ErrInvalid)
			return
		}
		conn := &gLazyConn{
			parentCtx:  t.ctx,
			stack:      t.stack,
			request:    r,
			localAddr:  source.TCPAddr(),
			remoteAddr: destination.TCPAddr(),
		}
		go t.handler.NewConnectionEx(t.ctx, conn, source, destination, nil)
	})
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	if !t.endpointIndependentNat {
		udpForwarder := udp.NewForwarder(ipStack, func(r *udp.ForwarderRequest) {
			source := M.SocksaddrFrom(AddrFromAddress(r.ID().RemoteAddress), r.ID().RemotePort)
			destination := M.SocksaddrFrom(AddrFromAddress(r.ID().LocalAddress), r.ID().LocalPort)
			pErr := t.handler.PrepareConnection(N.NetworkUDP, source, destination)
			if pErr != nil {
				gWriteUnreachable(t.stack, r.Packet(), err)
				r.Packet().DecRef()
				return
			}
			var wq waiter.Queue
			endpoint, err := r.CreateEndpoint(&wq)
			if err != nil {
				return
			}
			go func() {
				ctx, conn := canceler.NewPacketConn(t.ctx, bufio.NewUnbindPacketConnWithAddr(gonet.NewUDPConn(&wq, endpoint), destination), t.udpTimeout)
				t.handler.NewPacketConnectionEx(ctx, conn, source, destination, nil)
			}()
		})
		ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	} else {
		ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, NewUDPForwarder(t.ctx, ipStack, t.handler, t.udpTimeout).HandlePacket)
	}

	t.stack = ipStack
	t.endpoint = linkEndpoint
	return nil
}

func (t *GVisor) Close() error {
	t.endpoint.Attach(nil)
	t.stack.Close()
	for _, endpoint := range t.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	return nil
}

func AddressFromAddr(destination netip.Addr) tcpip.Address {
	if destination.Is6() {
		return tcpip.AddrFrom16(destination.As16())
	} else {
		return tcpip.AddrFrom4(destination.As4())
	}
}

func AddrFromAddress(address tcpip.Address) netip.Addr {
	if address.Len() == 16 {
		return netip.AddrFrom16(address.As16())
	} else {
		return netip.AddrFrom4(address.As4())
	}
}

func newGVisorStack(ep stack.LinkEndpoint) (*stack.Stack, error) {
	ipStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})
	tErr := ipStack.CreateNIC(defaultNIC, ep)
	if tErr != nil {
		return nil, E.New("create nic: ", gonet.TranslateNetstackError(tErr))
	}
	ipStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: defaultNIC},
		{Destination: header.IPv6EmptySubnet, NIC: defaultNIC},
	})
	ipStack.SetSpoofing(defaultNIC, true)
	ipStack.SetPromiscuousMode(defaultNIC, true)
	bufSize := 20 * 1024
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{
		Min:     1,
		Default: bufSize,
		Max:     bufSize,
	})
	sOpt := tcpip.TCPSACKEnabled(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)
	return ipStack, nil
}
