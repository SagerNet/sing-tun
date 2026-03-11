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
	listenAddr netip.Addr
	listener   *net.TCPListener
	connTable  *connMetadataTable
	inShutdown atomic.Bool
}

func newRedirectServerWindows(ctx context.Context, handler N.TCPConnectionHandlerEx, logger logger.Logger, listenAddr netip.Addr) *redirectServer {
	return &redirectServer{
		ctx:        ctx,
		handler:    handler,
		logger:     logger,
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
				s.logger.Error(err)
				continue
			}
			if s.inShutdown.Load() && E.IsClosed(err) {
				return
			}
			s.listener.Close()
			s.logger.Error("serve error: ", err)
			return
		}
		source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
		entry, ok := s.connTable.Lookup(source)
		if !ok {
			_ = conn.SetLinger(0)
			_ = conn.Close()
			s.logger.Error("process redirect connection from ", source, ": no metadata")
			continue
		}
		destination := entry.Destination
		if entry.IsDNS {
			destination = entry.DNSServer
		}
		ctx := s.ctx
		if entry.Metadata != nil {
			ctx = ContextWithAutoRedirectMetadata(ctx, entry.Metadata)
		}
		go s.handler.NewConnectionEx(ctx, conn, source, destination, nil)
	}
}

// connMetadataTable maps source address → connection metadata.
// Entries are populated by pre-match workers before sending redirect verdicts,
// and consumed by the redirect server upon accepting connections.
type connMetadataTable struct {
	mu      sync.Mutex
	entries map[connKey]*connEntry
}

type connKey struct {
	Addr netip.Addr
	Port uint16
}

type connEntry struct {
	Destination M.Socksaddr
	Metadata    *AutoRedirectMetadata
	IsDNS       bool
	DNSServer   M.Socksaddr
	CreatedAt   time.Time
}

func newConnMetadataTable() *connMetadataTable {
	t := &connMetadataTable{
		entries: make(map[connKey]*connEntry),
	}
	go t.cleanupLoop()
	return t
}

func (t *connMetadataTable) Store(src M.Socksaddr, dst M.Socksaddr, metadata *AutoRedirectMetadata) {
	key := connKey{Addr: src.Addr, Port: src.Port}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[key] = &connEntry{
		Destination: dst,
		Metadata:    metadata,
		CreatedAt:   time.Now(),
	}
}

func (t *connMetadataTable) StoreDNS(src M.Socksaddr, originalDst M.Socksaddr, dnsServer M.Socksaddr, metadata *AutoRedirectMetadata) {
	key := connKey{Addr: src.Addr, Port: src.Port}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[key] = &connEntry{
		Destination: originalDst,
		Metadata:    metadata,
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
	}
	return entry, ok
}

func (t *connMetadataTable) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
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
