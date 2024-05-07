package tun

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/sagernet/sing-tun/internal/clashtcpip"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat"
)

var ErrIncludeAllNetworks = E.New("`system` and `mixed` stack are not available when `includeAllNetworks` is enabled. See https://github.com/SagerNet/sing-tun/issues/25")

type System struct {
	ctx                context.Context
	tun                Tun
	tunName            string
	mtu                int
	handler            Handler
	logger             logger.Logger
	inet4Prefixes      []netip.Prefix
	inet6Prefixes      []netip.Prefix
	inet4ServerAddress netip.Addr
	inet4Address       netip.Addr
	inet6ServerAddress netip.Addr
	inet6Address       netip.Addr
	broadcastAddr      netip.Addr
	udpTimeout         int64
	tcpListener        net.Listener
	tcpListener6       net.Listener
	tcpPort            uint16
	tcpPort6           uint16
	tcpNat             *TCPNat
	udpNat             *udpnat.Service[netip.AddrPort]
	bindInterface      bool
	interfaceFinder    control.InterfaceFinder
	frontHeadroom      int
	txChecksumOffload  bool
}

type Session struct {
	SourceAddress      netip.Addr
	DestinationAddress netip.Addr
	SourcePort         uint16
	DestinationPort    uint16
}

func NewSystem(options StackOptions) (Stack, error) {
	stack := &System{
		ctx:             options.Context,
		tun:             options.Tun,
		tunName:         options.TunOptions.Name,
		mtu:             int(options.TunOptions.MTU),
		udpTimeout:      options.UDPTimeout,
		handler:         options.Handler,
		logger:          options.Logger,
		inet4Prefixes:   options.TunOptions.Inet4Address,
		inet6Prefixes:   options.TunOptions.Inet6Address,
		broadcastAddr:   BroadcastAddr(options.TunOptions.Inet4Address),
		bindInterface:   options.ForwarderBindInterface,
		interfaceFinder: options.InterfaceFinder,
	}
	if len(options.TunOptions.Inet4Address) > 0 {
		if options.TunOptions.Inet4Address[0].Bits() == 32 {
			return nil, E.New("need one more IPv4 address in first prefix for system stack")
		}
		stack.inet4ServerAddress = options.TunOptions.Inet4Address[0].Addr()
		stack.inet4Address = stack.inet4ServerAddress.Next()
	}
	if len(options.TunOptions.Inet6Address) > 0 {
		if options.TunOptions.Inet6Address[0].Bits() == 128 {
			return nil, E.New("need one more IPv6 address in first prefix for system stack")
		}
		stack.inet6ServerAddress = options.TunOptions.Inet6Address[0].Addr()
		stack.inet6Address = stack.inet6ServerAddress.Next()
	}
	if !stack.inet4Address.IsValid() && !stack.inet6Address.IsValid() {
		return nil, E.New("missing interface address")
	}
	return stack, nil
}

func (s *System) Close() error {
	return common.Close(
		s.tcpListener,
		s.tcpListener6,
	)
}

func (s *System) Start() error {
	err := s.start()
	if err != nil {
		return err
	}
	go s.tunLoop()
	return nil
}

func (s *System) start() error {
	err := fixWindowsFirewall()
	if err != nil {
		return E.Cause(err, "fix windows firewall for system stack")
	}
	var listener net.ListenConfig
	if s.bindInterface {
		listener.Control = control.Append(listener.Control, func(network, address string, conn syscall.RawConn) error {
			bindErr := control.BindToInterface0(s.interfaceFinder, conn, network, address, s.tunName, -1, true)
			if bindErr != nil {
				s.logger.Warn("bind forwarder to interface: ", bindErr)
			}
			return nil
		})
	}
	if s.inet4Address.IsValid() {
		tcpListener, err := listener.Listen(s.ctx, "tcp4", net.JoinHostPort(s.inet4ServerAddress.String(), "0"))
		if err != nil {
			return err
		}
		s.tcpListener = tcpListener
		s.tcpPort = M.SocksaddrFromNet(tcpListener.Addr()).Port
		go s.acceptLoop(tcpListener)
	}
	if s.inet6Address.IsValid() {
		tcpListener, err := listener.Listen(s.ctx, "tcp6", net.JoinHostPort(s.inet6ServerAddress.String(), "0"))
		if err != nil {
			return err
		}
		s.tcpListener6 = tcpListener
		s.tcpPort6 = M.SocksaddrFromNet(tcpListener.Addr()).Port
		go s.acceptLoop(tcpListener)
	}
	s.tcpNat = NewNat(s.ctx, time.Second*time.Duration(s.udpTimeout))
	s.udpNat = udpnat.New[netip.AddrPort](s.udpTimeout, s.handler)
	return nil
}

func (s *System) tunLoop() {
	if winTun, isWinTun := s.tun.(WinTun); isWinTun {
		s.wintunLoop(winTun)
		return
	}
	if linuxTUN, isLinuxTUN := s.tun.(LinuxTUN); isLinuxTUN {
		s.frontHeadroom = linuxTUN.FrontHeadroom()
		s.txChecksumOffload = linuxTUN.TXChecksumOffload()
		batchSize := linuxTUN.BatchSize()
		if batchSize > 1 {
			s.batchLoop(linuxTUN, batchSize)
			return
		}
	}
	packetBuffer := make([]byte, s.mtu+PacketOffset)
	for {
		n, err := s.tun.Read(packetBuffer)
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "read packet"))
		}
		if n < clashtcpip.IPv4PacketMinLength {
			continue
		}
		rawPacket := packetBuffer[:n]
		packet := packetBuffer[PacketOffset:n]
		if s.processPacket(packet) {
			_, err = s.tun.Write(rawPacket)
			if err != nil {
				s.logger.Trace(E.Cause(err, "write packet"))
			}
		}
	}
}

func (s *System) wintunLoop(winTun WinTun) {
	for {
		packet, release, err := winTun.ReadPacket()
		if err != nil {
			return
		}
		if len(packet) < clashtcpip.IPv4PacketMinLength {
			release()
			continue
		}
		if s.processPacket(packet) {
			_, err = winTun.Write(packet)
			if err != nil {
				s.logger.Trace(E.Cause(err, "write packet"))
			}
		}
		release()
	}
}

func (s *System) batchLoop(linuxTUN LinuxTUN, batchSize int) {
	packetBuffers := make([][]byte, batchSize)
	writeBuffers := make([][]byte, batchSize)
	packetSizes := make([]int, batchSize)
	for i := range packetBuffers {
		packetBuffers[i] = make([]byte, s.mtu+s.frontHeadroom)
	}
	for {
		n, err := linuxTUN.BatchRead(packetBuffers, s.frontHeadroom, packetSizes)
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			s.logger.Error(E.Cause(err, "batch read packet"))
		}
		if n == 0 {
			continue
		}
		for i := 0; i < n; i++ {
			packetSize := packetSizes[i]
			if packetSize < clashtcpip.IPv4PacketMinLength {
				continue
			}
			packetBuffer := packetBuffers[i]
			packet := packetBuffer[s.frontHeadroom : s.frontHeadroom+packetSize]
			if s.processPacket(packet) {
				writeBuffers = append(writeBuffers, packetBuffer[:s.frontHeadroom+packetSize])
			}
		}
		if len(writeBuffers) > 0 {
			err = linuxTUN.BatchWrite(writeBuffers, s.frontHeadroom)
			if err != nil {
				s.logger.Trace(E.Cause(err, "batch write packet"))
			}
			writeBuffers = writeBuffers[:0]
		}
	}
}

func (s *System) processPacket(packet []byte) bool {
	var (
		writeBack bool
		err       error
	)
	switch ipVersion := packet[0] >> 4; ipVersion {
	case 4:
		writeBack, err = s.processIPv4(packet)
	case 6:
		writeBack, err = s.processIPv6(packet)
	default:
		err = E.New("ip: unknown version: ", ipVersion)
	}
	if err != nil {
		s.logger.Trace(err)
		return false
	}
	return writeBack
}

func (s *System) acceptLoop(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		connPort := M.SocksaddrFromNet(conn.RemoteAddr()).Port
		session := s.tcpNat.LookupBack(connPort)
		if session == nil {
			s.logger.Trace(E.New("unknown session with port ", connPort))
			continue
		}
		destination := M.SocksaddrFromNetIP(session.Destination)
		if destination.Addr.Is4() {
			for _, prefix := range s.inet4Prefixes {
				if prefix.Contains(destination.Addr) {
					destination.Addr = netip.AddrFrom4([4]byte{127, 0, 0, 1})
					break
				}
			}
		} else {
			for _, prefix := range s.inet6Prefixes {
				if prefix.Contains(destination.Addr) {
					destination.Addr = netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
					break
				}
			}
		}
		go func() {
			_ = s.handler.NewConnection(s.ctx, conn, M.Metadata{
				Source:      M.SocksaddrFromNetIP(session.Source),
				Destination: destination,
			})
			if tcpConn, isTCPConn := conn.(*net.TCPConn); isTCPConn {
				_ = tcpConn.SetLinger(0)
			}
			_ = conn.Close()
		}()
	}
}

func (s *System) processIPv4(packet clashtcpip.IPv4Packet) (writeBack bool, err error) {
	writeBack = true
	destination := packet.DestinationIP()
	if destination == s.broadcastAddr || !destination.IsGlobalUnicast() {
		return
	}
	switch packet.Protocol() {
	case clashtcpip.TCP:
		err = s.processIPv4TCP(packet, packet.Payload())
	case clashtcpip.UDP:
		writeBack = false
		err = s.processIPv4UDP(packet, packet.Payload())
	case clashtcpip.ICMP:
		err = s.processIPv4ICMP(packet, packet.Payload())
	}
	return
}

func (s *System) processIPv6(packet clashtcpip.IPv6Packet) (writeBack bool, err error) {
	writeBack = true
	if !packet.DestinationIP().IsGlobalUnicast() {
		return
	}
	switch packet.Protocol() {
	case clashtcpip.TCP:
		err = s.processIPv6TCP(packet, packet.Payload())
	case clashtcpip.UDP:
		writeBack = false
		err = s.processIPv6UDP(packet, packet.Payload())
	case clashtcpip.ICMPv6:
		err = s.processIPv6ICMP(packet, packet.Payload())
	}
	return
}

func (s *System) processIPv4TCP(packet clashtcpip.IPv4Packet, header clashtcpip.TCPPacket) error {
	source := netip.AddrPortFrom(packet.SourceIP(), header.SourcePort())
	destination := netip.AddrPortFrom(packet.DestinationIP(), header.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return nil
	} else if source.Addr() == s.inet4ServerAddress && source.Port() == s.tcpPort {
		session := s.tcpNat.LookupBack(destination.Port())
		if session == nil {
			return E.New("ipv4: tcp: session not found: ", destination.Port())
		}
		packet.SetSourceIP(session.Destination.Addr())
		header.SetSourcePort(session.Destination.Port())
		packet.SetDestinationIP(session.Source.Addr())
		header.SetDestinationPort(session.Source.Port())
	} else {
		natPort := s.tcpNat.Lookup(source, destination)
		packet.SetSourceIP(s.inet4Address)
		header.SetSourcePort(natPort)
		packet.SetDestinationIP(s.inet4ServerAddress)
		header.SetDestinationPort(s.tcpPort)
	}
	if !s.txChecksumOffload {
		header.ResetChecksum(packet.PseudoSum())
		packet.ResetChecksum()
	} else {
		header.OffloadChecksum()
		packet.ResetChecksum()
	}
	return nil
}

func (s *System) processIPv6TCP(packet clashtcpip.IPv6Packet, header clashtcpip.TCPPacket) error {
	source := netip.AddrPortFrom(packet.SourceIP(), header.SourcePort())
	destination := netip.AddrPortFrom(packet.DestinationIP(), header.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return nil
	} else if source.Addr() == s.inet6ServerAddress && source.Port() == s.tcpPort6 {
		session := s.tcpNat.LookupBack(destination.Port())
		if session == nil {
			return E.New("ipv6: tcp: session not found: ", destination.Port())
		}
		packet.SetSourceIP(session.Destination.Addr())
		header.SetSourcePort(session.Destination.Port())
		packet.SetDestinationIP(session.Source.Addr())
		header.SetDestinationPort(session.Source.Port())
	} else {
		natPort := s.tcpNat.Lookup(source, destination)
		packet.SetSourceIP(s.inet6Address)
		header.SetSourcePort(natPort)
		packet.SetDestinationIP(s.inet6ServerAddress)
		header.SetDestinationPort(s.tcpPort6)
	}
	if !s.txChecksumOffload {
		header.ResetChecksum(packet.PseudoSum())
	} else {
		header.OffloadChecksum()
	}
	return nil
}

func (s *System) processIPv4UDP(packet clashtcpip.IPv4Packet, header clashtcpip.UDPPacket) error {
	if packet.Flags()&clashtcpip.FlagMoreFragment != 0 {
		return E.New("ipv4: fragment dropped")
	}
	if packet.FragmentOffset() != 0 {
		return E.New("ipv4: udp: fragment dropped")
	}
	if !header.Valid() {
		return E.New("ipv4: udp: invalid packet")
	}
	source := netip.AddrPortFrom(packet.SourceIP(), header.SourcePort())
	destination := netip.AddrPortFrom(packet.DestinationIP(), header.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return nil
	}
	data := buf.As(header.Payload())
	if data.Len() == 0 {
		return nil
	}
	metadata := M.Metadata{
		Source:      M.SocksaddrFromNetIP(source),
		Destination: M.SocksaddrFromNetIP(destination),
	}
	s.udpNat.NewPacket(s.ctx, source, data.ToOwned(), metadata, func(natConn N.PacketConn) N.PacketWriter {
		headerLen := packet.HeaderLen() + clashtcpip.UDPHeaderSize
		headerCopy := make([]byte, headerLen)
		copy(headerCopy, packet[:headerLen])
		return &systemUDPPacketWriter4{
			s.tun,
			s.frontHeadroom + PacketOffset,
			headerCopy,
			source,
			s.txChecksumOffload,
		}
	})
	return nil
}

func (s *System) processIPv6UDP(packet clashtcpip.IPv6Packet, header clashtcpip.UDPPacket) error {
	if !header.Valid() {
		return E.New("ipv6: udp: invalid packet")
	}
	source := netip.AddrPortFrom(packet.SourceIP(), header.SourcePort())
	destination := netip.AddrPortFrom(packet.DestinationIP(), header.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return nil
	}
	data := buf.As(header.Payload())
	if data.Len() == 0 {
		return nil
	}
	metadata := M.Metadata{
		Source:      M.SocksaddrFromNetIP(source),
		Destination: M.SocksaddrFromNetIP(destination),
	}
	s.udpNat.NewPacket(s.ctx, source, data.ToOwned(), metadata, func(natConn N.PacketConn) N.PacketWriter {
		headerLen := len(packet) - int(header.Length()) + clashtcpip.UDPHeaderSize
		headerCopy := make([]byte, headerLen)
		copy(headerCopy, packet[:headerLen])
		return &systemUDPPacketWriter6{
			s.tun,
			s.frontHeadroom + PacketOffset,
			headerCopy,
			source,
			s.txChecksumOffload,
		}
	})
	return nil
}

func (s *System) processIPv4ICMP(packet clashtcpip.IPv4Packet, header clashtcpip.ICMPPacket) error {
	if header.Type() != clashtcpip.ICMPTypePingRequest || header.Code() != 0 {
		return nil
	}
	header.SetType(clashtcpip.ICMPTypePingResponse)
	sourceAddress := packet.SourceIP()
	packet.SetSourceIP(packet.DestinationIP())
	packet.SetDestinationIP(sourceAddress)
	header.ResetChecksum()
	packet.ResetChecksum()
	return nil
}

func (s *System) processIPv6ICMP(packet clashtcpip.IPv6Packet, header clashtcpip.ICMPv6Packet) error {
	if header.Type() != clashtcpip.ICMPv6EchoRequest || header.Code() != 0 {
		return nil
	}
	header.SetType(clashtcpip.ICMPv6EchoReply)
	sourceAddress := packet.SourceIP()
	packet.SetSourceIP(packet.DestinationIP())
	packet.SetDestinationIP(sourceAddress)
	header.ResetChecksum(packet.PseudoSum())
	packet.ResetChecksum()
	return nil
}

type systemUDPPacketWriter4 struct {
	tun               Tun
	frontHeadroom     int
	header            []byte
	source            netip.AddrPort
	txChecksumOffload bool
}

func (w *systemUDPPacketWriter4) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	newPacket := buf.NewSize(w.frontHeadroom + len(w.header) + buffer.Len())
	defer newPacket.Release()
	newPacket.Resize(w.frontHeadroom, 0)
	newPacket.Write(w.header)
	newPacket.Write(buffer.Bytes())
	ipHdr := clashtcpip.IPv4Packet(newPacket.Bytes())
	ipHdr.SetTotalLength(uint16(newPacket.Len()))
	ipHdr.SetDestinationIP(ipHdr.SourceIP())
	ipHdr.SetSourceIP(destination.Addr)
	udpHdr := clashtcpip.UDPPacket(ipHdr.Payload())
	udpHdr.SetDestinationPort(udpHdr.SourcePort())
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(uint16(buffer.Len() + clashtcpip.UDPHeaderSize))
	if !w.txChecksumOffload {
		udpHdr.ResetChecksum(ipHdr.PseudoSum())
		ipHdr.ResetChecksum()
	} else {
		udpHdr.OffloadChecksum()
		ipHdr.ResetChecksum()
	}
	if PacketOffset > 0 {
		newPacket.ExtendHeader(PacketOffset)[3] = syscall.AF_INET
	} else {
		newPacket.Advance(-w.frontHeadroom)
	}
	return common.Error(w.tun.Write(newPacket.Bytes()))
}

type systemUDPPacketWriter6 struct {
	tun               Tun
	frontHeadroom     int
	header            []byte
	source            netip.AddrPort
	txChecksumOffload bool
}

func (w *systemUDPPacketWriter6) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	newPacket := buf.NewSize(w.frontHeadroom + len(w.header) + buffer.Len())
	defer newPacket.Release()
	newPacket.Resize(w.frontHeadroom, 0)
	newPacket.Write(w.header)
	newPacket.Write(buffer.Bytes())
	ipHdr := clashtcpip.IPv6Packet(newPacket.Bytes())
	udpLen := uint16(clashtcpip.UDPHeaderSize + buffer.Len())
	ipHdr.SetPayloadLength(udpLen)
	ipHdr.SetDestinationIP(ipHdr.SourceIP())
	ipHdr.SetSourceIP(destination.Addr)
	udpHdr := clashtcpip.UDPPacket(ipHdr.Payload())
	udpHdr.SetDestinationPort(udpHdr.SourcePort())
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(udpLen)
	if !w.txChecksumOffload {
		udpHdr.ResetChecksum(ipHdr.PseudoSum())
	} else {
		udpHdr.OffloadChecksum()
	}
	if PacketOffset > 0 {
		newPacket.ExtendHeader(PacketOffset)[3] = syscall.AF_INET6
	} else {
		newPacket.Advance(-w.frontHeadroom)
	}
	return common.Error(w.tun.Write(newPacket.Bytes()))
}
