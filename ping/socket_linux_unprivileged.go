package ping

import (
	"context"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/sing-tun/internal/gtcpip/checksum"
	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
)

type UnprivilegedConn struct {
	ctx          context.Context
	cancel       context.CancelFunc
	controlFunc  control.Func
	destination  netip.Addr
	receiveChan  chan *unprivilegedResponse
	readDeadline atomic.TypedValue[time.Time]
}

type unprivilegedResponse struct {
	Buffer *buf.Buffer
	Cmsg   *buf.Buffer
	Addr   netip.Addr
}

func newUnprivilegedConn(ctx context.Context, controlFunc control.Func, destination netip.Addr) (net.Conn, error) {
	conn, err := connect(false, controlFunc, destination)
	if err != nil {
		return nil, err
	}
	conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	return &UnprivilegedConn{
		ctx:         ctx,
		cancel:      cancel,
		controlFunc: controlFunc,
		destination: destination,
		receiveChan: make(chan *unprivilegedResponse),
	}, nil
}

func (c *UnprivilegedConn) Read(b []byte) (n int, err error) {
	select {
	case packet := <-c.receiveChan:
		n = copy(b, packet.Buffer.Bytes())
		packet.Buffer.Release()
		packet.Cmsg.Release()
		return
	case <-c.ctx.Done():
		return 0, os.ErrClosed
	}
}

func (c *UnprivilegedConn) ReadMsg(b []byte, oob []byte) (n, oobn int, addr netip.Addr, err error) {
	select {
	case packet := <-c.receiveChan:
		n = copy(b, packet.Buffer.Bytes())
		oobn = copy(oob, packet.Cmsg.Bytes())
		addr = packet.Addr
		packet.Buffer.Release()
		packet.Cmsg.Release()
		return
	case <-c.ctx.Done():
		return 0, 0, netip.Addr{}, os.ErrClosed
	}
}

func (c *UnprivilegedConn) Write(b []byte) (n int, err error) {
	conn, err := connect(false, c.controlFunc, c.destination)
	if err != nil {
		return
	}
	var identifier uint16
	if !c.destination.Is6() {
		icmpHdr := header.ICMPv4(b)
		identifier = icmpHdr.Ident()
	} else {
		icmpHdr := header.ICMPv6(b)
		identifier = icmpHdr.Ident()
	}
	if readDeadline := c.readDeadline.Load(); !readDeadline.IsZero() {
		conn.SetReadDeadline(readDeadline)
	}
	n, err = conn.Write(b)
	if err != nil {
		conn.Close()
		return
	}
	go c.fetchResponse(conn, identifier)
	return
}

func (c *UnprivilegedConn) fetchResponse(conn net.Conn, identifier uint16) {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-c.ctx.Done():
		case <-done:
		}
		conn.Close()
	}()
	buffer := buf.NewPacket()
	cmsgBuffer := buf.NewSize(1024)
	n, oobN, _, addr, err := conn.(*net.UDPConn).ReadMsgUDPAddrPort(buffer.FreeBytes(), cmsgBuffer.FreeBytes())
	if err != nil {
		buffer.Release()
		cmsgBuffer.Release()
		return
	}
	buffer.Truncate(n)
	cmsgBuffer.Truncate(oobN)
	if !c.destination.Is6() {
		icmpHdr := header.ICMPv4(buffer.Bytes())
		icmpHdr.SetIdent(identifier)
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(icmpHdr.Payload(), 0)))
	} else {
		icmpHdr := header.ICMPv6(buffer.Bytes())
		icmpHdr.SetIdent(identifier)
		// offload checksum here since we don't have source address here
	}
	select {
	case c.receiveChan <- &unprivilegedResponse{
		Buffer: buffer,
		Cmsg:   cmsgBuffer,
		Addr:   addr.Addr(),
	}:
	case <-c.ctx.Done():
		buffer.Release()
		cmsgBuffer.Release()
	}
}

func (c *UnprivilegedConn) Close() error {
	c.cancel()
	return nil
}

func (c *UnprivilegedConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *UnprivilegedConn) RemoteAddr() net.Addr {
	return M.SocksaddrFrom(c.destination, 0).UDPAddr()
}

func (c *UnprivilegedConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *UnprivilegedConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

func (c *UnprivilegedConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}
