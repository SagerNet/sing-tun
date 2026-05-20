package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type redirectServer struct {
	ctx        context.Context
	handler    N.TCPConnectionHandlerEx
	logger     logger.Logger
	onFatal    func(error)
	listenAddr netip.Addr
	listener   *net.TCPListener
	connTable  *connMetadataTable
	inShutdown atomic.Bool
}

func (s *redirectServer) logError(args ...any) {
	if s.logger != nil {
		s.logger.Error(args...)
	}
}

func newRedirectServerWindows(ctx context.Context, handler N.TCPConnectionHandlerEx, logger logger.Logger, listenAddr netip.Addr, onFatal func(error)) *redirectServer {
	return &redirectServer{
		ctx:        ctx,
		handler:    handler,
		logger:     logger,
		onFatal:    onFatal,
		listenAddr: listenAddr,
		connTable:  newConnMetadataTable(),
	}
}

func (s *redirectServer) Start() error {
	var listenConfig net.ListenConfig
	listenConfig.KeepAlive = 10 * time.Minute
	listener, err := listenConfig.Listen(s.ctx, M.NetworkFromNetAddr("tcp", s.listenAddr), M.SocksaddrFrom(s.listenAddr, 0).String())
	if err != nil {
		return err
	}
	s.listener = listener.(*net.TCPListener)
	go s.loopIn()
	return nil
}

func (s *redirectServer) Close() error {
	s.inShutdown.Store(true)
	if s.connTable != nil {
		s.connTable.Close()
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *redirectServer) loopIn() {
	for {
		conn, err := s.listener.AcceptTCP()
		if err != nil {
			var netError net.Error
			//nolint:staticcheck
			if errors.As(err, &netError) && netError.Temporary() {
				s.logError(err)
				continue
			}
			if s.inShutdown.Load() && E.IsClosed(err) {
				return
			}
			s.listener.Close()
			if s.onFatal != nil {
				s.onFatal(E.Cause(err, "accept redirect connection"))
			} else {
				s.logError("serve error: ", err)
			}
			return
		}
		source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
		entry, ok := s.connTable.Lookup(source)
		if !ok {
			_ = conn.SetLinger(0)
			_ = conn.Close()
			s.logError("process redirect connection from ", source, ": no metadata")
			continue
		}
		destination := entry.Destination
		if entry.IsDNS {
			destination = entry.DNSServer
		}
		ctx := entry.Context
		if ctx == nil {
			ctx = s.ctx
		}
		go s.handler.NewConnectionEx(ctx, conn, source, destination, nil)
	}
}

type connMetadataTable struct {
	mu      sync.Mutex
	entries map[connKey]*connEntry
	done    chan struct{}
}

type connKey struct {
	Addr netip.Addr
	Port uint16
}

type connEntry struct {
	Destination M.Socksaddr
	Context     context.Context
	IsDNS       bool
	DNSServer   M.Socksaddr
	CreatedAt   time.Time
}

func newConnMetadataTable() *connMetadataTable {
	t := &connMetadataTable{
		entries: make(map[connKey]*connEntry),
		done:    make(chan struct{}),
	}
	go t.cleanupLoop()
	return t
}

func (t *connMetadataTable) Close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
}

func (t *connMetadataTable) Store(src M.Socksaddr, dst M.Socksaddr, ctx context.Context) {
	key := connKey{Addr: src.Addr, Port: src.Port}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[key] = &connEntry{
		Destination: dst,
		Context:     ctx,
		CreatedAt:   time.Now(),
	}
}

func (t *connMetadataTable) StoreDNS(src M.Socksaddr, originalDst M.Socksaddr, dnsServer M.Socksaddr, ctx context.Context) {
	key := connKey{Addr: src.Addr, Port: src.Port}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[key] = &connEntry{
		Destination: originalDst,
		Context:     ctx,
		IsDNS:       true,
		DNSServer:   dnsServer,
		CreatedAt:   time.Now(),
	}
}

func (t *connMetadataTable) Lookup(src M.Socksaddr) (*connEntry, bool) {
	key := connKey{Addr: src.Addr, Port: src.Port}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[key]
	if ok {
		delete(t.entries, key)
		return entry, true
	}

	// ALE_CONNECT_REDIRECT may report an unspecified local source address
	// (0.0.0.0/::) before connect completes, while the accepted redirected
	// connection later appears as loopback with the same source port.
	if src.Addr.IsLoopback() {
		var fallbackAddr netip.Addr
		if src.Addr.Is4() {
			fallbackAddr = netip.IPv4Unspecified()
		} else {
			fallbackAddr = netip.IPv6Unspecified()
		}
		fallbackKey := connKey{Addr: fallbackAddr, Port: src.Port}
		entry, ok = t.entries[fallbackKey]
		if ok {
			delete(t.entries, fallbackKey)
		}
	}
	return entry, ok
}

func (t *connMetadataTable) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			t.mu.Lock()
			now := time.Now()
			for key, entry := range t.entries {
				if now.Sub(entry.CreatedAt) > 30*time.Second {
					delete(t.entries, key)
				}
			}
			t.mu.Unlock()
		}
	}
}
