//go:build with_gvisor

package tun

import (
	"context"
	"errors"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type TCPForwarder struct {
	ctx       context.Context
	stack     *stack.Stack
	handler   Handler
	forwarder *tcp.Forwarder
}

func NewTCPForwarder(ctx context.Context, stack *stack.Stack, handler Handler) *TCPForwarder {
	forwarder := &TCPForwarder{
		ctx:     ctx,
		stack:   stack,
		handler: handler,
	}
	forwarder.forwarder = tcp.NewForwarder(stack, 0, 1024, forwarder.Forward)
	return forwarder
}

func (f *TCPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	return f.forwarder.HandlePacket(id, pkt)
}

func (f *TCPForwarder) Forward(r *tcp.ForwarderRequest) {
	source := M.SocksaddrFrom(AddrFromAddress(r.ID().RemoteAddress), r.ID().RemotePort)
	destination := M.SocksaddrFrom(AddrFromAddress(r.ID().LocalAddress), r.ID().LocalPort)
	pErr := f.handler.PrepareConnection(N.NetworkTCP, source, destination)
	if pErr != nil {
		r.Complete(!errors.Is(pErr, ErrDrop))
		return
	}
	conn := &gLazyConn{
		parentCtx:  f.ctx,
		stack:      f.stack,
		request:    r,
		localAddr:  source.TCPAddr(),
		remoteAddr: destination.TCPAddr(),
	}
	go f.handler.NewConnectionEx(f.ctx, conn, source, destination, nil)
}
