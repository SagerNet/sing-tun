//go:build linux

package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type redirectServer struct {
	ctx         context.Context
	handler     N.TCPConnectionHandlerEx
	logger      logger.Logger
	listenAddr  netip.Addr
	listener    *net.TCPListener
	access      sync.Mutex
	connections map[*net.TCPConn]struct{}
}

func newRedirectServer(ctx context.Context, handler N.TCPConnectionHandlerEx, logger logger.Logger, listenAddr netip.Addr) *redirectServer {
	return &redirectServer{
		ctx:         ctx,
		handler:     handler,
		logger:      logger,
		listenAddr:  listenAddr,
		connections: make(map[*net.TCPConn]struct{}),
	}
}

func (s *redirectServer) Start() error {
	var listenConfig net.ListenConfig
	// listenConfig.KeepAlive = C.TCPKeepAliveInitial
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
	s.access.Lock()
	connections := s.connections
	s.connections = nil
	s.access.Unlock()
	err := s.listener.Close()
	for conn := range connections {
		_ = conn.SetLinger(0)
		_ = conn.Close()
	}
	return err
}

func (s *redirectServer) loopIn() {
	var retryDelay time.Duration
	for {
		conn, err := s.listener.AcceptTCP()
		if err != nil {
			s.access.Lock()
			closed := s.connections == nil
			s.access.Unlock()
			if closed && E.IsClosed(err) {
				return
			}
			var netError net.Error
			//nolint:staticcheck
			if errors.As(err, &netError) && netError.Temporary() {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay *= 2
				}
				if retryDelay > time.Second {
					retryDelay = time.Second
				}
				s.logger.Error("accept: ", err, ": retrying in ", retryDelay)
				time.Sleep(retryDelay)
				continue
			}
			s.listener.Close()
			s.logger.Error("serve error: ", err)
			return
		}
		retryDelay = 0
		source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
		destination, err := control.GetOriginalDestination(conn)
		if err != nil {
			_ = conn.SetLinger(0)
			_ = conn.Close()
			s.logger.Error("process redirect connection from ", source, ": invalid connection: ", err)
			continue
		}
		s.access.Lock()
		if s.connections == nil {
			s.access.Unlock()
			_ = conn.SetLinger(0)
			_ = conn.Close()
			return
		}
		s.connections[conn] = struct{}{}
		s.access.Unlock()
		go s.handler.NewConnectionEx(s.ctx, conn, source, M.SocksaddrFromNetIP(destination).Unwrap(), func(error) {
			s.access.Lock()
			delete(s.connections, conn)
			s.access.Unlock()
		})
	}
}
