package tun

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/pipe"
)

const goListenBacklog = 4096

type GoListener struct {
	engine       *goEngine
	local        netip.AddrPort
	access       sync.Mutex
	pending      []*GoConn
	pendingHead  int
	backlog      int
	closed       bool
	openErr      error
	openSignal   chan struct{}
	closeSignal  chan struct{}
	closeDone    chan struct{}
	acceptSignal goSignal
	deadline     pipe.Deadline
	openMessage  goMessage
	closeMessage goMessage
}

func (s *Go) ListenTCP(local netip.AddrPort) (*GoListener, error) {
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	if !local.Addr().IsValid() {
		return nil, errGoInvalidAddress
	}
	engine, err := s.selectEngine(local)
	if err != nil {
		return nil, err
	}
	listener := &GoListener{
		engine:       engine,
		local:        local,
		openSignal:   make(chan struct{}),
		closeSignal:  make(chan struct{}),
		closeDone:    make(chan struct{}),
		acceptSignal: make(goSignal, 1),
		deadline:     pipe.MakeDeadline(),
	}
	listener.openMessage = goMessage{kind: goMessageListenOpen, listener: listener}
	listener.closeMessage = goMessage{kind: goMessageListenClose, listener: listener}
	engine.postMessage(&listener.openMessage)
	select {
	case <-listener.openSignal:
	case <-s.ctx.Done():
		listener.Close()
		return nil, E.Cause(s.ctx.Err(), "go: listen")
	}
	listener.access.Lock()
	err = listener.openErr
	listener.access.Unlock()
	if err != nil {
		return nil, err
	}
	return listener, nil
}

func (e *goEngine) lookupListener(local netip.AddrPort) *GoListener {
	listener := e.tcpListeners[local]
	if listener == nil && len(e.stack.engines) > 1 {
		listener = e.stack.directory.lookupListener(local)
	}
	return listener
}

func (e *goEngine) handleListenOpen(listener *GoListener) {
	listener.access.Lock()
	closed := listener.closed
	listener.access.Unlock()
	if closed {
		close(listener.openSignal)
		return
	}
	available := func(port uint16) bool {
		return e.lookupListener(netip.AddrPortFrom(listener.local.Addr(), port)) == nil
	}
	port := listener.local.Port()
	if port == 0 {
		allocated := false
		port, allocated = goAllocatePort(available)
		if !allocated {
			listener.access.Lock()
			listener.openErr = E.Cause(syscall.EADDRINUSE, "go: ephemeral ports exhausted")
			listener.access.Unlock()
			close(listener.openSignal)
			return
		}
	} else if !available(port) {
		listener.access.Lock()
		listener.openErr = E.Cause(syscall.EADDRINUSE, "go: listen ", listener.local)
		listener.access.Unlock()
		close(listener.openSignal)
		return
	}
	listener.local = netip.AddrPortFrom(listener.local.Addr(), port)
	e.stack.directory.insertListener(listener)
	close(listener.openSignal)
}

func (e *goEngine) handleListenClose(listener *GoListener) {
	e.stack.directory.removeListener(listener)
	listener.drain()
	close(listener.closeDone)
}

func (e *goEngine) closeAllListeners() {
	for _, listener := range e.tcpListeners {
		e.stack.directory.removeListener(listener)
		listener.markClosed()
		listener.drain()
	}
}

func (l *GoListener) reserve() bool {
	l.access.Lock()
	defer l.access.Unlock()
	if l.closed || l.backlog >= goListenBacklog {
		return false
	}
	l.backlog++
	return true
}

func (l *GoListener) abandon() {
	l.access.Lock()
	l.backlog--
	l.access.Unlock()
}

func (l *GoListener) deliver(conn *GoConn) {
	l.access.Lock()
	if l.closed {
		l.backlog--
		l.access.Unlock()
		conn.fail(net.ErrClosed)
		return
	}
	l.pending = append(l.pending, conn)
	l.access.Unlock()
	l.acceptSignal.notify()
}

func (l *GoListener) AcceptTCP() (*GoConn, error) {
	for {
		l.access.Lock()
		if l.pendingHead < len(l.pending) {
			conn := l.pending[l.pendingHead]
			l.pending[l.pendingHead] = nil
			l.pendingHead++
			if l.pendingHead == len(l.pending) {
				l.pending = l.pending[:0]
				l.pendingHead = 0
			} else if l.pendingHead >= len(l.pending)/2 {
				remaining := copy(l.pending, l.pending[l.pendingHead:])
				clear(l.pending[remaining:])
				l.pending = l.pending[:remaining]
				l.pendingHead = 0
			}
			l.backlog--
			l.access.Unlock()
			return conn, nil
		}
		closed := l.closed
		l.access.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		select {
		case <-l.acceptSignal:
		case <-l.closeSignal:
		case <-l.deadline.Wait():
			return nil, os.ErrDeadlineExceeded
		}
	}
}

func (l *GoListener) Accept() (net.Conn, error) {
	conn, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (l *GoListener) markClosed() bool {
	l.access.Lock()
	if l.closed {
		l.access.Unlock()
		return false
	}
	l.closed = true
	l.access.Unlock()
	close(l.closeSignal)
	return true
}

func (l *GoListener) drain() {
	l.access.Lock()
	pending := l.pending[l.pendingHead:]
	l.backlog -= len(pending)
	l.pending = nil
	l.pendingHead = 0
	l.access.Unlock()
	for _, conn := range pending {
		conn.fail(net.ErrClosed)
	}
}

func (l *GoListener) Close() error {
	if l.markClosed() {
		l.engine.postMessage(&l.closeMessage)
	}
	select {
	case <-l.closeDone:
	case <-l.engine.exitSignal:
	}
	return nil
}

func (l *GoListener) Addr() net.Addr {
	return net.TCPAddrFromAddrPort(l.local)
}

func (l *GoListener) SetDeadline(t time.Time) error {
	l.deadline.Set(t)
	return nil
}
