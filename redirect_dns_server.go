//go:build linux

package tun

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/ipv6"
)

type redirectDNSServer struct {
	ctx         context.Context
	handler     Handler
	logger      logger.Logger
	destination M.Socksaddr
	server      *redirectServer
	packetConn  *ipv6.PacketConn
}

func newRedirectDNSServer(ctx context.Context, handler Handler, logger logger.Logger, address netip.Addr) *redirectDNSServer {
	s := &redirectDNSServer{
		ctx:         ctx,
		handler:     handler,
		logger:      logger,
		destination: M.SocksaddrFrom(address, 53),
	}
	s.server = newRedirectServer(ctx, s, logger, netip.IPv6Unspecified())
	return s
}

func (s *redirectDNSServer) Start() error {
	err := s.server.Start()
	if err != nil {
		return err
	}
	var listenConfig net.ListenConfig
	conn, err := listenConfig.ListenPacket(s.ctx, "udp6", "[::]:0")
	if err != nil {
		s.server.Close()
		return err
	}
	packetConn := ipv6.NewPacketConn(conn)
	err = packetConn.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	if err != nil {
		conn.Close()
		s.server.Close()
		return err
	}
	s.packetConn = packetConn
	go s.loopIn()
	return nil
}

func (s *redirectDNSServer) Close() error {
	return E.Errors(s.server.Close(), s.packetConn.Close())
}

func (s *redirectDNSServer) tcpPort() uint16 {
	return M.AddrPortFromNet(s.server.listener.Addr()).Port()
}

func (s *redirectDNSServer) udpPort() uint16 {
	return M.AddrPortFromNet(s.packetConn.LocalAddr()).Port()
}

func (s *redirectDNSServer) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	s.handler.NewConnectionEx(ctx, conn, source, s.destination, onClose)
}

func (s *redirectDNSServer) loopIn() {
	buffer := make([]byte, 65535)
	for {
		n, controlMessage, source, err := s.packetConn.ReadFrom(buffer)
		if err != nil {
			if !E.IsClosed(err) {
				s.logger.Error(E.Cause(err, "read redirected DNS packet"))
			}
			return
		}
		if controlMessage == nil {
			continue
		}
		s.handler.NewDNSPacket(buffer[:n], M.SocksaddrFromNet(source).Unwrap(), s.destination, &redirectDNSWriter{
			packetConn: s.packetConn,
			source:     source,
			controlMessage: ipv6.ControlMessage{
				Src:     controlMessage.Dst,
				IfIndex: controlMessage.IfIndex,
			},
		})
	}
}

type redirectDNSWriter struct {
	packetConn     *ipv6.PacketConn
	source         net.Addr
	controlMessage ipv6.ControlMessage
}

func (w *redirectDNSWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	_, err := w.packetConn.WriteTo(buffer.Bytes(), &w.controlMessage, w.source)
	return err
}

var (
	_ N.TCPConnectionHandlerEx = (*redirectDNSServer)(nil)
	_ N.PacketWriter           = (*redirectDNSWriter)(nil)
)
