package tun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

// SK_RMEM_MAX in include/net/sock.h is the initial receive budget of every socket, and
// SOCK_MIN_RCVBUF the floor SO_RCVBUF is clamped to.
const (
	goUDPReceiveCapacity = 212992
	goUDPReceiveMinimum  = 2304
)

type goUDPDatagram struct {
	buffer *buf.Buffer
	source netip.AddrPort
}

func (d goUDPDatagram) memoryCost() int {
	return d.buffer.RawCap() + int(unsafe.Sizeof(d)) + int(unsafe.Sizeof(*d.buffer))
}

type GoUDPConn struct {
	engine          *goEngine
	local           netip.AddrPort
	remote          netip.AddrPort
	ipVersion       uint8
	connected       bool
	access          sync.Mutex
	queue           []goUDPDatagram
	queueHead       int
	queuedBytes     int
	receiveCapacity int
	readWaitOptions N.ReadWaitOptions
	closed          bool
	openErr         error
	pendingErr      error
	openSignal      chan struct{}
	closeSignal     chan struct{}
	closeDone       chan struct{}
	readSignal      goSignal
	readDeadline    pipe.Deadline
	writeDeadline   pipe.Deadline
	openMessage     goMessage
	closeMessage    goMessage
}

func (s *Go) DialUDP(local netip.AddrPort, destination netip.AddrPort) (*GoUDPConn, error) {
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	if !destination.IsValid() || destination.Port() == 0 {
		return nil, errGoInvalidAddress
	}
	return s.openUDP(local, destination)
}

func (s *Go) ListenUDP(local netip.AddrPort) (*GoUDPConn, error) {
	return s.openUDP(local, netip.AddrPort{})
}

func (s *Go) openUDP(local netip.AddrPort, destination netip.AddrPort) (*GoUDPConn, error) {
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	if !local.Addr().IsValid() || destination.IsValid() && local.Addr().Is4() != destination.Addr().Is4() {
		return nil, errGoInvalidAddress
	}
	engine, err := s.selectEngine(local)
	if err != nil {
		return nil, err
	}
	socket := &GoUDPConn{
		engine:          engine,
		local:           local,
		remote:          destination,
		ipVersion:       goIPVersion(local.Addr()),
		connected:       destination.IsValid(),
		receiveCapacity: min(goUDPReceiveCapacity, goReceiveCapacityMax),
		openSignal:      make(chan struct{}),
		closeSignal:     make(chan struct{}),
		closeDone:       make(chan struct{}),
		readSignal:      make(goSignal, 1),
		readDeadline:    pipe.MakeDeadline(),
		writeDeadline:   pipe.MakeDeadline(),
	}
	socket.openMessage = goMessage{kind: goMessageUDPOpen, socket: socket}
	socket.closeMessage = goMessage{kind: goMessageUDPClose, socket: socket}
	engine.postMessage(&socket.openMessage)
	select {
	case <-socket.openSignal:
	case <-s.ctx.Done():
		socket.Close()
		return nil, E.Cause(context.Cause(s.ctx), "go: open UDP socket")
	}
	socket.access.Lock()
	err = socket.openErr
	socket.access.Unlock()
	if err != nil {
		return nil, err
	}
	return socket, nil
}

func (e *goEngine) handleUDPOpen(socket *GoUDPConn) {
	socket.access.Lock()
	closed := socket.closed
	socket.access.Unlock()
	if closed {
		close(socket.openSignal)
		return
	}
	available := func(port uint16) bool {
		local := netip.AddrPortFrom(socket.local.Addr(), port)
		return e.udpSockets[local] == nil && (len(e.stack.engines) == 1 || e.stack.directory.lookupUDPSocket(local) == nil)
	}
	port := socket.local.Port()
	if port == 0 {
		allocated := false
		port, allocated = goAllocatePort(available)
		if !allocated {
			socket.access.Lock()
			socket.openErr = E.Cause(syscall.EADDRINUSE, "go: ephemeral ports exhausted")
			socket.access.Unlock()
			close(socket.openSignal)
			return
		}
	} else if !available(port) {
		socket.access.Lock()
		socket.openErr = E.Cause(syscall.EADDRINUSE, "go: bind ", socket.local)
		socket.access.Unlock()
		close(socket.openSignal)
		return
	}
	socket.local = netip.AddrPortFrom(socket.local.Addr(), port)
	e.stack.directory.insertUDPSocket(socket)
	close(socket.openSignal)
}

func (e *goEngine) handleUDPClose(socket *GoUDPConn) {
	e.stack.directory.removeUDPSocket(socket)
	socket.drain()
	close(socket.closeDone)
}

func (e *goEngine) closeAllUDPSockets() {
	for _, socket := range e.udpSockets {
		e.stack.directory.removeUDPSocket(socket)
		socket.markClosed(net.ErrClosed)
		socket.drain()
	}
}

func (e *goEngine) inputUDPSocket(socket *GoUDPConn, parsed *forwardPacket) {
	if socket.connected && parsed.source != socket.remote {
		return
	}
	payload := header.UDP(parsed.transport).Payload()
	socket.access.Lock()
	if socket.closed || socket.queuedBytes >= socket.receiveCapacity {
		socket.access.Unlock()
		return
	}
	buffer := socket.readWaitOptions.NewBufferSize(len(payload))
	buffer.Write(payload)
	socket.readWaitOptions.PostReturn(buffer)
	datagram := goUDPDatagram{buffer: buffer, source: parsed.source}
	socket.queue = append(socket.queue, datagram)
	socket.queuedBytes += datagram.memoryCost()
	socket.access.Unlock()
	if socket.readSignal.notify() {
		e.wokeHandlerThisBurst = true
	}
}

func (c *GoUDPConn) deliverError(err error) {
	c.access.Lock()
	c.pendingErr = err
	c.access.Unlock()
	c.readSignal.notify()
}

func (c *GoUDPConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.access.Lock()
	c.readWaitOptions = options
	c.access.Unlock()
	return false
}

func (c *GoUDPConn) waitDatagram() (goUDPDatagram, error) {
	for {
		select {
		case <-c.readDeadline.Wait():
			return goUDPDatagram{}, os.ErrDeadlineExceeded
		default:
		}
		c.access.Lock()
		if c.pendingErr != nil {
			err := c.pendingErr
			c.pendingErr = nil
			c.access.Unlock()
			return goUDPDatagram{}, err
		}
		if c.queueHead < len(c.queue) {
			datagram := c.queue[c.queueHead]
			c.queue[c.queueHead] = goUDPDatagram{}
			c.queueHead++
			if c.queueHead == len(c.queue) {
				c.queue = c.queue[:0]
				c.queueHead = 0
			} else if c.queueHead >= len(c.queue)/2 {
				remaining := copy(c.queue, c.queue[c.queueHead:])
				clear(c.queue[remaining:])
				c.queue = c.queue[:remaining]
				c.queueHead = 0
			}
			c.queuedBytes -= datagram.memoryCost()
			datagram.buffer = c.readWaitOptions.Copy(datagram.buffer)
			c.access.Unlock()
			return datagram, nil
		}
		closed := c.closed
		c.access.Unlock()
		if closed {
			return goUDPDatagram{}, c.closeError()
		}
		select {
		case <-c.readSignal:
		case <-c.closeSignal:
		case <-c.readDeadline.Wait():
			return goUDPDatagram{}, os.ErrDeadlineExceeded
		}
	}
}

func (c *GoUDPConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	datagram, err := c.waitDatagram()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	return datagram.buffer, M.SocksaddrFromNetIP(datagram.source), nil
}

func (c *GoUDPConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	datagram, err := c.waitDatagram()
	if err != nil {
		return M.Socksaddr{}, err
	}
	defer datagram.buffer.Release()
	if buffer.FreeLen() < datagram.buffer.Len() {
		return M.SocksaddrFromNetIP(datagram.source), io.ErrShortBuffer
	}
	buffer.Write(datagram.buffer.Bytes())
	return M.SocksaddrFromNetIP(datagram.source), nil
}

func (c *GoUDPConn) ReadFromUDPAddrPort(p []byte) (int, netip.AddrPort, error) {
	datagram, err := c.waitDatagram()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	defer datagram.buffer.Release()
	return copy(p, datagram.buffer.Bytes()), datagram.source, nil
}

func (c *GoUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, source, err := c.ReadFromUDPAddrPort(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(source), nil
}

func (c *GoUDPConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFromUDPAddrPort(p)
	return n, err
}

func (c *GoUDPConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if !destination.IsIP() {
		return E.Cause(os.ErrInvalid, "go: invalid packet destination")
	}
	return c.transmit(buffer.Bytes(), destination.AddrPort())
}

func (c *GoUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	if !destination.IsIP() {
		return 0, E.Cause(os.ErrInvalid, "go: invalid packet destination")
	}
	return c.WriteToUDPAddrPort(p, destination.AddrPort())
}

func (c *GoUDPConn) WriteToUDPAddrPort(p []byte, addr netip.AddrPort) (int, error) {
	err := c.transmit(p, addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *GoUDPConn) Write(p []byte) (int, error) {
	if !c.connected {
		return 0, E.Cause(syscall.EDESTADDRREQ, "go: socket not connected")
	}
	return c.WriteToUDPAddrPort(p, c.remote)
}

func (c *GoUDPConn) transmit(payload []byte, destination netip.AddrPort) error {
	c.access.Lock()
	closed := c.closed
	c.access.Unlock()
	if closed {
		return c.closeError()
	}
	select {
	case <-c.writeDeadline.Wait():
		return os.ErrDeadlineExceeded
	default:
	}
	remote := netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	if !remote.IsValid() || remote.Addr().Is4() != c.local.Addr().Is4() || remote.Port() == 0 {
		return E.Cause(syscall.EAFNOSUPPORT, "go: packet destination ", remote)
	}
	headerLength := goNetworkHeaderLength(c.ipVersion) + header.UDPMinimumSize
	maximumPayload := 65535 - header.UDPMinimumSize
	if c.ipVersion == 4 {
		maximumPayload -= header.IPv4MinimumSize
	}
	if len(payload) > maximumPayload {
		return E.Cause(syscall.EMSGSIZE, "go: packet payload ", len(payload))
	}
	packet := buf.NewSize(headerLength + len(payload))
	defer packet.Release()
	goEncodeUDPPacket(packet.Extend(headerLength+len(payload)), c.ipVersion, c.local, remote, payload, uint16(c.engine.stack.fragmentIdentification.Add(1)))
	platformIO := c.engine.platformIO
	mtu := platformIO.mtu()
	if packet.Len() <= mtu {
		return goIgnoreDropped(platformIO.writeDatagram(packet.Bytes(), ForwardFrameMeta{}))
	}
	return goWriteFragmented(platformIO, &c.engine.stack.fragmentIdentification, packet.Bytes(), mtu)
}

func goEncodeUDPPacket(packet []byte, ipVersion uint8, source netip.AddrPort, destination netip.AddrPort, payload []byte, ident uint16) {
	udpLength := uint16(header.UDPMinimumSize + len(payload))
	pseudoSum := goEncodeNetworkHeader(packet, ipVersion, header.UDPProtocolNumber, source.Addr(), destination.Addr(), int(udpLength), ident)
	udpHdr := header.UDP(packet[goNetworkHeaderLength(ipVersion):])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: source.Port(),
		DstPort: destination.Port(),
		Length:  udpLength,
	})
	copy(udpHdr[header.UDPMinimumSize:], payload)
	sum := ^checksum.Checksum(payload, udpHdr.CalculateChecksum(pseudoSum))
	if sum == 0 {
		sum = 0xffff
	}
	udpHdr.SetChecksum(sum)
}

func (c *GoUDPConn) markClosed(err error) bool {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return false
	}
	c.closed = true
	if c.openErr == nil {
		c.openErr = err
	}
	c.access.Unlock()
	close(c.closeSignal)
	return true
}

func (c *GoUDPConn) closeError() error {
	c.access.Lock()
	defer c.access.Unlock()
	if c.openErr != nil {
		return c.openErr
	}
	return net.ErrClosed
}

func (c *GoUDPConn) drain() {
	c.access.Lock()
	for _, datagram := range c.queue[c.queueHead:] {
		datagram.buffer.Release()
	}
	clear(c.queue)
	c.queue = c.queue[:0]
	c.queueHead = 0
	c.queuedBytes = 0
	c.access.Unlock()
}

func (c *GoUDPConn) Close() error {
	if c.markClosed(net.ErrClosed) {
		c.engine.postMessage(&c.closeMessage)
	}
	select {
	case <-c.closeDone:
	case <-c.engine.exitSignal:
	}
	return nil
}

func (c *GoUDPConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.local)
}

func (c *GoUDPConn) RemoteAddr() net.Addr {
	if !c.connected {
		return nil
	}
	return net.UDPAddrFromAddrPort(c.remote)
}

func (c *GoUDPConn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	c.writeDeadline.Set(t)
	return nil
}

func (c *GoUDPConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *GoUDPConn) SetReadBuffer(size int) error {
	c.access.Lock()
	c.receiveCapacity = min(max(size, goUDPReceiveMinimum), goReceiveCapacityMax)
	c.access.Unlock()
	return nil
}

func (c *GoUDPConn) SetWriteBuffer(size int) error {
	return nil
}

func (c *GoUDPConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return nil
}

var (
	_ N.NetPacketConn    = (*GoUDPConn)(nil)
	_ N.PacketReadWaiter = (*GoUDPConn)(nil)
)
