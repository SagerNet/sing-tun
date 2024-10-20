//go:build with_gvisor

package tun

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

type gLazyConn struct {
	tcpConn       *gonet.TCPConn
	parentCtx     context.Context
	stack         *stack.Stack
	request       *tcp.ForwarderRequest
	localAddr     net.Addr
	remoteAddr    net.Addr
	handshakeDone bool
	handshakeErr  error
}

func (c *gLazyConn) HandshakeContext(ctx context.Context) error {
	if c.handshakeDone {
		return nil
	}
	defer func() {
		c.handshakeDone = true
	}()
	var (
		wq       waiter.Queue
		endpoint tcpip.Endpoint
	)
	handshakeCtx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-c.parentCtx.Done():
			wq.Notify(wq.Events())
		case <-handshakeCtx.Done():
		}
	}()
	endpoint, err := c.request.CreateEndpoint(&wq)
	cancel()
	if err != nil {
		gErr := gonet.TranslateNetstackError(err)
		c.handshakeErr = gErr
		c.request.Complete(true)
		return gErr
	}
	c.request.Complete(false)
	endpoint.SocketOptions().SetKeepAlive(true)
	keepAliveIdle := tcpip.KeepaliveIdleOption(15 * time.Second)
	endpoint.SetSockOpt(&keepAliveIdle)
	keepAliveInterval := tcpip.KeepaliveIntervalOption(15 * time.Second)
	endpoint.SetSockOpt(&keepAliveInterval)
	tcpConn := gonet.NewTCPConn(&wq, endpoint)
	c.tcpConn = tcpConn
	return nil
}

func (c *gLazyConn) HandshakeFailure(err error) error {
	if c.handshakeDone {
		return nil
	}
	c.request.Complete(gWriteUnreachable(c.stack, c.request.Packet(), err) == os.ErrInvalid)
	c.handshakeDone = true
	c.handshakeErr = err
	return nil
}

func (c *gLazyConn) HandshakeSuccess() error {
	return c.HandshakeContext(context.Background())
}

func (c *gLazyConn) Read(b []byte) (n int, err error) {
	if !c.handshakeDone {
		err = c.HandshakeContext(context.Background())
		if err != nil {
			return
		}
	} else if c.handshakeErr != nil {
		return 0, c.handshakeErr
	}
	return c.tcpConn.Read(b)
}

func (c *gLazyConn) Write(b []byte) (n int, err error) {
	if !c.handshakeDone {
		err = c.HandshakeContext(context.Background())
		if err != nil {
			return
		}
	} else if c.handshakeErr != nil {
		return 0, c.handshakeErr
	}
	return c.tcpConn.Write(b)
}

func (c *gLazyConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *gLazyConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *gLazyConn) SetDeadline(t time.Time) error {
	if !c.handshakeDone {
		err := c.HandshakeContext(context.Background())
		if err != nil {
			return err
		}
	} else if c.handshakeErr != nil {
		return c.handshakeErr
	}
	return c.tcpConn.SetDeadline(t)
}

func (c *gLazyConn) SetReadDeadline(t time.Time) error {
	if !c.handshakeDone {
		err := c.HandshakeContext(context.Background())
		if err != nil {
			return err
		}
	} else if c.handshakeErr != nil {
		return c.handshakeErr
	}
	return c.tcpConn.SetReadDeadline(t)
}

func (c *gLazyConn) SetWriteDeadline(t time.Time) error {
	if !c.handshakeDone {
		err := c.HandshakeContext(context.Background())
		if err != nil {
			return err
		}
	} else if c.handshakeErr != nil {
		return c.handshakeErr
	}
	return c.tcpConn.SetWriteDeadline(t)
}

func (c *gLazyConn) Close() error {
	if !c.handshakeDone {
		c.request.Complete(true)
		c.handshakeErr = net.ErrClosed
		return nil
	} else if c.handshakeErr != nil {
		return nil
	}
	return c.tcpConn.Close()
}

func (c *gLazyConn) CloseRead() error {
	if !c.handshakeDone {
		c.request.Complete(true)
		c.handshakeErr = net.ErrClosed
		return nil
	} else if c.handshakeErr != nil {
		return nil
	}
	return c.tcpConn.CloseRead()
}

func (c *gLazyConn) CloseWrite() error {
	if !c.handshakeDone {
		c.request.Complete(true)
		c.handshakeErr = net.ErrClosed
		return nil
	} else if c.handshakeErr != nil {
		return nil
	}
	return c.tcpConn.CloseRead()
}

func (c *gLazyConn) ReaderReplaceable() bool {
	return c.handshakeDone && c.handshakeErr == nil
}

func (c *gLazyConn) WriterReplaceable() bool {
	return c.handshakeDone && c.handshakeErr == nil
}

func (c *gLazyConn) Upstream() any {
	return c.tcpConn
}

func gWriteUnreachable(gStack *stack.Stack, packet *stack.PacketBuffer, err error) error {
	if errors.Is(err, ErrDrop) {
		return nil
	} else if errors.Is(err, syscall.ENETUNREACH) {
		if packet.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			return gWriteUnreachable4(gStack, packet, stack.RejectIPv4WithICMPNetProhibited)
		} else {
			return gWriteUnreachable6(gStack, packet, stack.RejectIPv6WithICMPNoRoute)
		}
	} else if errors.Is(err, syscall.EHOSTUNREACH) {
		if packet.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			return gWriteUnreachable4(gStack, packet, stack.RejectIPv4WithICMPHostProhibited)
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
	return os.ErrInvalid
}

func gWriteUnreachable4(gStack *stack.Stack, packet *stack.PacketBuffer, icmpCode stack.RejectIPv4WithICMPType) error {
	return gonet.TranslateNetstackError(gStack.NetworkProtocolInstance(header.IPv4ProtocolNumber).(stack.RejectIPv4WithHandler).SendRejectionError(packet, icmpCode, true))
}

func gWriteUnreachable6(gStack *stack.Stack, packet *stack.PacketBuffer, icmpCode stack.RejectIPv6WithICMPType) error {
	return gonet.TranslateNetstackError(gStack.NetworkProtocolInstance(header.IPv6ProtocolNumber).(stack.RejectIPv6WithHandler).SendRejectionError(packet, icmpCode, true))
}
