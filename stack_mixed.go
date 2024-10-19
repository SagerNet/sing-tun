//go:build with_gvisor

package tun

import (
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
	"github.com/sagernet/sing-tun/internal/clashtcpip"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type Mixed struct {
	*System
	endpointIndependentNat bool
	stack                  *stack.Stack
	endpoint               *channel.Endpoint
}

func NewMixed(
	options StackOptions,
) (Stack, error) {
	system, err := NewSystem(options)
	if err != nil {
		return nil, err
	}
	return &Mixed{
		System:                 system.(*System),
		endpointIndependentNat: options.EndpointIndependentNat,
	}, nil
}

func (m *Mixed) Start() error {
	err := m.System.start()
	if err != nil {
		return err
	}
	endpoint := channel.New(1024, uint32(m.mtu), "")
	ipStack, err := newGVisorStack(endpoint)
	if err != nil {
		return err
	}
	if !m.endpointIndependentNat {
		udpForwarder := udp.NewForwarder(ipStack, func(request *udp.ForwarderRequest) {
			var wq waiter.Queue
			endpoint, err := request.CreateEndpoint(&wq)
			if err != nil {
				return
			}
			udpConn := gonet.NewUDPConn(&wq, endpoint)
			lAddr := udpConn.RemoteAddr()
			rAddr := udpConn.LocalAddr()
			if lAddr == nil || rAddr == nil {
				endpoint.Abort()
				return
			}
			go func() {
				var metadata M.Metadata
				metadata.Source = M.SocksaddrFromNet(lAddr)
				metadata.Destination = M.SocksaddrFromNet(rAddr)
				ctx, conn := canceler.NewPacketConn(m.ctx, bufio.NewUnbindPacketConnWithAddr(udpConn, metadata.Destination), time.Duration(m.udpTimeout)*time.Second)
				hErr := m.handler.NewPacketConnection(ctx, conn, metadata)
				if hErr != nil {
					endpoint.Abort()
				}
			}()
		})
		ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	} else {
		ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, NewUDPForwarder(m.ctx, ipStack, m.handler, m.udpTimeout).HandlePacket)
	}
	m.stack = ipStack
	m.endpoint = endpoint
	go m.tunLoop()
	go m.packetLoop()
	return nil
}

func (m *Mixed) tunLoop() {
	if winTun, isWinTun := m.tun.(WinTun); isWinTun {
		m.wintunLoop(winTun)
		return
	}
	if linuxTUN, isLinuxTUN := m.tun.(LinuxTUN); isLinuxTUN {
		m.frontHeadroom = linuxTUN.FrontHeadroom()
		m.txChecksumOffload = linuxTUN.TXChecksumOffload()
		batchSize := linuxTUN.BatchSize()
		if batchSize > 1 {
			m.batchLoop(linuxTUN, batchSize)
			return
		}
	}
	packetBuffer := make([]byte, m.mtu+PacketOffset)
	for {
		n, err := m.tun.Read(packetBuffer)
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			m.logger.Error(E.Cause(err, "read packet"))
		}
		if n < clashtcpip.IPv4PacketMinLength {
			continue
		}
		rawPacket := packetBuffer[:n]
		packet := packetBuffer[PacketOffset:n]
		if m.processPacket(packet) {
			_, err = m.tun.Write(rawPacket)
			if err != nil {
				m.logger.Trace(E.Cause(err, "write packet"))
			}
		}
	}
}

func (m *Mixed) wintunLoop(winTun WinTun) {
	for {
		packet, release, err := winTun.ReadPacket()
		if err != nil {
			return
		}
		if len(packet) < clashtcpip.IPv4PacketMinLength {
			release()
			continue
		}
		if m.processPacket(packet) {
			_, err = winTun.Write(packet)
			if err != nil {
				m.logger.Trace(E.Cause(err, "write packet"))
			}
		}
		release()
	}
}

func (m *Mixed) batchLoop(linuxTUN LinuxTUN, batchSize int) {
	packetBuffers := make([][]byte, batchSize)
	writeBuffers := make([][]byte, batchSize)
	packetSizes := make([]int, batchSize)
	for i := range packetBuffers {
		packetBuffers[i] = make([]byte, m.mtu+m.frontHeadroom)
	}
	for {
		n, err := linuxTUN.BatchRead(packetBuffers, m.frontHeadroom, packetSizes)
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			m.logger.Error(E.Cause(err, "batch read packet"))
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
			packet := packetBuffer[m.frontHeadroom : m.frontHeadroom+packetSize]
			if m.processPacket(packet) {
				writeBuffers = append(writeBuffers, packetBuffer[:m.frontHeadroom+packetSize])
			}
		}
		if len(writeBuffers) > 0 {
			err = linuxTUN.BatchWrite(writeBuffers, m.frontHeadroom)
			if err != nil {
				m.logger.Trace(E.Cause(err, "batch write packet"))
			}
			writeBuffers = writeBuffers[:0]
		}
	}
}

func (m *Mixed) processPacket(packet []byte) bool {
	var (
		writeBack bool
		err       error
	)
	switch ipVersion := packet[0] >> 4; ipVersion {
	case 4:
		writeBack, err = m.processIPv4(packet)
	case 6:
		writeBack, err = m.processIPv6(packet)
	default:
		err = E.New("ip: unknown version: ", ipVersion)
	}
	if err != nil {
		m.logger.Trace(err)
		return false
	}
	return writeBack
}

func (m *Mixed) processIPv4(packet clashtcpip.IPv4Packet) (writeBack bool, err error) {
	writeBack = true
	destination := packet.DestinationIP()
	if destination == m.broadcastAddr || !destination.IsGlobalUnicast() {
		return
	}
	switch packet.Protocol() {
	case clashtcpip.TCP:
		err = m.processIPv4TCP(packet, packet.Payload())
	case clashtcpip.UDP:
		writeBack = false
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           buffer.MakeWithData(packet),
			IsForwardedPacket: true,
		})
		m.endpoint.InjectInbound(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
		return
	case clashtcpip.ICMP:
		err = m.processIPv4ICMP(packet, packet.Payload())
	}
	return
}

func (m *Mixed) processIPv6(packet clashtcpip.IPv6Packet) (writeBack bool, err error) {
	writeBack = true
	if !packet.DestinationIP().IsGlobalUnicast() {
		return
	}
	switch packet.Protocol() {
	case clashtcpip.TCP:
		err = m.processIPv6TCP(packet, packet.Payload())
	case clashtcpip.UDP:
		writeBack = false
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload:           buffer.MakeWithData(packet),
			IsForwardedPacket: true,
		})
		m.endpoint.InjectInbound(header.IPv6ProtocolNumber, pkt)
		pkt.DecRef()
	case clashtcpip.ICMPv6:
		err = m.processIPv6ICMP(packet, packet.Payload())
	}
	return
}

func (m *Mixed) packetLoop() {
	for {
		packet := m.endpoint.ReadContext(m.ctx)
		if packet == nil {
			break
		}
		bufio.WriteVectorised(m.tun, packet.AsSlices())
		packet.DecRef()
	}
}

func (m *Mixed) Close() error {
	m.endpoint.Attach(nil)
	m.stack.Close()
	for _, endpoint := range m.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	return m.System.Close()
}
