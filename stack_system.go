package tun

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/sagernet/sing-tun/internal/gtcpip/checksum"
	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat2"
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
	udpTimeout         time.Duration
	tcpListener        net.Listener
	tcpListener6       net.Listener
	tcpPort            uint16
	tcpPort6           uint16
	tcpNat             *TCPNat
	udpNat             *udpnat.Service
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
		if !HasNextAddress(options.TunOptions.Inet4Address[0], 1) {
			return nil, E.New("need one more IPv4 address in first prefix for system stack")
		}
		stack.inet4ServerAddress = options.TunOptions.Inet4Address[0].Addr()
		stack.inet4Address = stack.inet4ServerAddress.Next()
	}
	if len(options.TunOptions.Inet6Address) > 0 {
		if !HasNextAddress(options.TunOptions.Inet6Address[0], 1) {
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
	var tcpListener net.Listener
	if s.inet4Address.IsValid() {
		for i := 0; i < 3; i++ {
			tcpListener, err = listener.Listen(s.ctx, "tcp4", net.JoinHostPort(s.inet4ServerAddress.String(), "0"))
			if !retryableListenError(err) {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			return err
		}
		s.tcpListener = tcpListener
		s.tcpPort = M.SocksaddrFromNet(tcpListener.Addr()).Port
		go s.acceptLoop(tcpListener)
	}
	if s.inet6Address.IsValid() {
		for i := 0; i < 3; i++ {
			tcpListener, err = listener.Listen(s.ctx, "tcp6", net.JoinHostPort(s.inet6ServerAddress.String(), "0"))
			if !retryableListenError(err) {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil {
			return err
		}
		s.tcpListener6 = tcpListener
		s.tcpPort6 = M.SocksaddrFromNet(tcpListener.Addr()).Port
		go s.acceptLoop(tcpListener)
	}
	s.tcpNat = NewNat(s.ctx, s.udpTimeout)
	s.udpNat = udpnat.New(s.handler, s.preparePacketConnection, s.udpTimeout)
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
		if n < header.IPv4MinimumSize {
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
		if len(packet) < header.IPv4MinimumSize {
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
			if packetSize < header.IPv4MinimumSize {
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
		go s.handler.NewConnectionEx(s.ctx, conn, M.SocksaddrFromNetIP(session.Source), destination, nil)
	}
}

func (s *System) processIPv4(ipHdr header.IPv4) (writeBack bool, err error) {
	writeBack = true
	destination := ipHdr.DestinationAddr()
	if destination == s.broadcastAddr || !destination.IsGlobalUnicast() {
		return
	}
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		writeBack, err = s.processIPv4TCP(ipHdr, ipHdr.Payload())
	case header.UDPProtocolNumber:
		writeBack = false
		err = s.processIPv4UDP(ipHdr, ipHdr.Payload())
	case header.ICMPv4ProtocolNumber:
		err = s.processIPv4ICMP(ipHdr, ipHdr.Payload())
	}
	return
}

func (s *System) processIPv6(ipHdr header.IPv6) (writeBack bool, err error) {
	writeBack = true
	if !ipHdr.DestinationAddr().IsGlobalUnicast() {
		return
	}
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		err = s.processIPv6TCP(ipHdr, ipHdr.Payload())
	case header.UDPProtocolNumber:
		err = s.processIPv6UDP(ipHdr, ipHdr.Payload())
	case header.ICMPv6ProtocolNumber:
		err = s.processIPv6ICMP(ipHdr, ipHdr.Payload())
	}
	return
}

func (s *System) processIPv4TCP(ipHdr header.IPv4, tcpHdr header.TCP) (bool, error) {
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), tcpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), tcpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return true, nil
	} else if source.Addr() == s.inet4ServerAddress && source.Port() == s.tcpPort {
		session := s.tcpNat.LookupBack(destination.Port())
		if session == nil {
			return false, E.New("ipv4: tcp: session not found: ", destination.Port())
		}
		ipHdr.SetSourceAddr(session.Destination.Addr())
		tcpHdr.SetSourcePort(session.Destination.Port())
		ipHdr.SetDestinationAddr(session.Source.Addr())
		tcpHdr.SetDestinationPort(session.Source.Port())
	} else {
		natPort, err := s.tcpNat.Lookup(source, destination, s.handler)
		if err != nil {
			// TODO: implement ICMP port unreachable
			return false, nil
		}
		ipHdr.SetSourceAddr(s.inet4Address)
		tcpHdr.SetSourcePort(natPort)
		ipHdr.SetDestinationAddr(s.inet4ServerAddress)
		tcpHdr.SetDestinationPort(s.tcpPort)
	}
	if !s.txChecksumOffload {
		tcpHdr.SetChecksum(0)
		tcpHdr.SetChecksum(^checksum.Checksum(tcpHdr.Payload(), tcpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		)))
	} else {
		tcpHdr.SetChecksum(0)
	}
	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return true, nil
}

func (s *System) resetIPv4TCP(packet header.IPv4, header header.TCP) error {
	return nil
}

func (s *System) processIPv6TCP(ipHdr header.IPv6, tcpHdr header.TCP) error {
	source := netip.AddrPortFrom(ipHdr.SourceAddr(), tcpHdr.SourcePort())
	destination := netip.AddrPortFrom(ipHdr.DestinationAddr(), tcpHdr.DestinationPort())
	if !destination.Addr().IsGlobalUnicast() {
		return nil
	} else if source.Addr() == s.inet6ServerAddress && source.Port() == s.tcpPort6 {
		session := s.tcpNat.LookupBack(destination.Port())
		if session == nil {
			return E.New("ipv6: tcp: session not found: ", destination.Port())
		}
		ipHdr.SetSourceAddr(session.Destination.Addr())
		tcpHdr.SetSourcePort(session.Destination.Port())
		ipHdr.SetSourceAddr(session.Source.Addr())
		tcpHdr.SetDestinationPort(session.Source.Port())
	} else {
		natPort, err := s.tcpNat.Lookup(source, destination, s.handler)
		if err != nil {
			// TODO: implement ICMP port unreachable
			return nil
		}
		ipHdr.SetSourceAddr(s.inet6Address)
		tcpHdr.SetSourcePort(natPort)
		ipHdr.SetSourceAddr(s.inet6ServerAddress)
		tcpHdr.SetDestinationPort(s.tcpPort6)
	}
	if !s.txChecksumOffload {
		tcpHdr.SetChecksum(0)
		tcpHdr.SetChecksum(^checksum.Checksum(tcpHdr.Payload(), tcpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		)))
	} else {
		tcpHdr.SetChecksum(0)
	}
	return nil
}

func (s *System) processIPv4UDP(ipHdr header.IPv4, udpHdr header.UDP) error {
	if ipHdr.Flags()&header.IPv4FlagMoreFragments != 0 {
		return E.New("ipv4: fragment dropped")
	}
	if ipHdr.FragmentOffset() != 0 {
		return E.New("ipv4: udp: fragment dropped")
	}
	source := M.SocksaddrFrom(ipHdr.SourceAddr(), udpHdr.SourcePort())
	destination := M.SocksaddrFrom(ipHdr.DestinationAddr(), udpHdr.DestinationPort())
	if !destination.Addr.IsGlobalUnicast() {
		return nil
	}
	s.udpNat.NewPacket([][]byte{udpHdr.Payload()}, source, destination, ipHdr)
	return nil
}

func (s *System) processIPv6UDP(ipHdr header.IPv6, udpHdr header.UDP) error {
	source := M.SocksaddrFrom(ipHdr.SourceAddr(), udpHdr.SourcePort())
	destination := M.SocksaddrFrom(ipHdr.DestinationAddr(), udpHdr.DestinationPort())
	if !destination.Addr.IsGlobalUnicast() {
		return nil
	}
	s.udpNat.NewPacket([][]byte{udpHdr.Payload()}, source, destination, ipHdr)
	return nil
}

func (s *System) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	pErr := s.handler.PrepareConnection(source, destination)
	if pErr != nil {
		// TODO: implement ICMP port unreachable
		return false, nil, nil, nil
	}
	var writer N.PacketWriter
	if source.IsIPv4() {
		packet := userData.(header.IPv4)
		headerLen := packet.HeaderLength() + header.UDPMinimumSize
		headerCopy := make([]byte, headerLen)
		copy(headerCopy, packet[:headerLen])
		writer = &systemUDPPacketWriter4{
			s.tun,
			s.frontHeadroom + PacketOffset,
			headerCopy,
			source.AddrPort(),
			s.txChecksumOffload,
		}
	} else {
		packet := userData.(header.IPv6)
		headerLen := len(packet) - int(packet.PayloadLength()) + header.UDPMinimumSize
		headerCopy := make([]byte, headerLen)
		copy(headerCopy, packet[:headerLen])
		writer = &systemUDPPacketWriter6{
			s.tun,
			s.frontHeadroom + PacketOffset,
			headerCopy,
			source.AddrPort(),
			s.txChecksumOffload,
		}
	}
	return true, s.ctx, writer, nil
}

func (s *System) processIPv4ICMP(ipHdr header.IPv4, icmpHdr header.ICMPv4) error {
	if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
		return nil
	}
	icmpHdr.SetType(header.ICMPv4EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, checksum.Checksum(icmpHdr.Payload(), 0)))
	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return nil
}

func (s *System) processIPv6ICMP(ipHdr header.IPv6, icmpHdr header.ICMPv6) error {
	if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
		return nil
	}
	icmpHdr.SetType(header.ICMPv6EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    ipHdr.SourceAddress(),
		Dst:    ipHdr.DestinationAddress(),
	}))
	return nil
}

/*func (s *System) WritePacket4(buffer *buf.Buffer, source netip.AddrPort, destination netip.AddrPort) error {
	packet := buf.Get(header.IPv4MinimumSize + header.UDPMinimumSize + buffer.Len())
	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		Protocol: uint8(header.UDPProtocolNumber),
		SrcAddr: source.Addr(),
		DstAddr: destination.Addr(),
	})
	ipHdr.SetHeaderLength(header.IPv4MinimumSize)
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.Encode(&header.UDPFields{
		SrcPort:    source.Port(),
		DstPort:    destination.Port(),
		Length:    uint16(header.UDPMinimumSize + buffer.Len()),
	})
	copy(udpHdr.Payload(), buffer.Bytes())
	if !s.txChecksumOffload {
		...
	} else {
		udpHdr.SetChecksum(0)
	}
	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return common.Error(s.tun.Write(packet))
}

func (s *System) WritePacket6(buffer *buf.Buffer, source netip.AddrPort, destination netip.AddrPort) error {
	packet := buf.Get(header.IPv6MinimumSize + header.UDPMinimumSize + buffer.Len())
	ipHdr := header.IPv6(packet)
	ipHdr.Encode(&header.IPv6Fields{
		PayloadLength: uint16(header.UDPMinimumSize + buffer.Len()),
		TransportProtocol:    header.UDPProtocolNumber,
		SrcAddr:       source.Addr(),
		DstAddr:       destination.Addr(),
	})
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.Encode(&header.UDPFields{
		SrcPort:    source.Port(),
		DstPort:    destination.Port(),
		Length:    uint16(header.UDPMinimumSize + buffer.Len()),
	})
	copy(udpHdr.Payload(), buffer.Bytes())
	if !s.txChecksumOffload {
		...
	} else {
		udpHdr.SetChecksum(0)
	}
	return common.Error(s.tun.Write(packet))
}*/

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
	ipHdr := header.IPv4(newPacket.Bytes())
	ipHdr.SetTotalLength(uint16(newPacket.Len()))
	ipHdr.SetSourceAddress(ipHdr.SourceAddress())
	ipHdr.SetSourceAddr(destination.Addr)
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.SetDestinationPort(udpHdr.SourcePort())
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(uint16(buffer.Len() + header.UDPMinimumSize))
	if !w.txChecksumOffload {
		udpHdr.SetChecksum(0)
		udpHdr.SetChecksum(^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		)))
	} else {
		udpHdr.SetChecksum(0)
	}
	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
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
	ipHdr := header.IPv6(newPacket.Bytes())
	udpLen := uint16(header.UDPMinimumSize + buffer.Len())
	ipHdr.SetPayloadLength(udpLen)
	ipHdr.SetDestinationAddress(ipHdr.SourceAddress())
	ipHdr.SetSourceAddr(destination.Addr)
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.SetDestinationPort(udpHdr.SourcePort())
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(udpLen)
	if !w.txChecksumOffload {
		udpHdr.SetChecksum(0)
		udpHdr.SetChecksum(^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), ipHdr.PayloadLength()),
		)))
	} else {
		udpHdr.SetChecksum(0)
	}
	if PacketOffset > 0 {
		newPacket.ExtendHeader(PacketOffset)[3] = syscall.AF_INET6
	} else {
		newPacket.Advance(-w.frontHeadroom)
	}
	return common.Error(w.tun.Write(newPacket.Bytes()))
}
