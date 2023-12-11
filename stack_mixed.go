//go:build with_gvisor

package tun

import (
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/canceler"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	"github.com/metacubex/sing-tun/internal/clashtcpip"
)

type Mixed struct {
	*System
	writer                 N.VectorisedWriter
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
		writer:                 bufio.NewVectorisedWriter(options.Tun),
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
			udpConn := gonet.NewUDPConn(ipStack, &wq, endpoint)
			lAddr := udpConn.RemoteAddr()
			rAddr := udpConn.LocalAddr()
			if lAddr == nil || rAddr == nil {
				endpoint.Abort()
				return
			}
			gConn := &gUDPConn{UDPConn: udpConn}
			go func() {
				var metadata M.Metadata
				metadata.Source = M.SocksaddrFromNet(lAddr)
				metadata.Destination = M.SocksaddrFromNet(rAddr)
				ctx, conn := canceler.NewPacketConn(m.ctx, bufio.NewUnbindPacketConnWithAddr(gConn, metadata.Destination), time.Duration(m.udpTimeout)*time.Second)
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

	if batchTUN, isBatchTUN := m.tun.(BatchTUN); isBatchTUN {
		batchSize := batchTUN.BatchSize()
		if batchSize > 1 {
			m.batchLoop(batchTUN, batchSize)
			return
		}
	}
	frontHeadroom := m.tun.FrontHeadroom()
	packetBuffer := make([]byte, m.mtu+frontHeadroom+PacketOffset)
	for {
		n, err := m.tun.Read(packetBuffer[frontHeadroom:])
		if err != nil {
			if E.IsClosed(err) {
				return
			}
			m.logger.Error(E.Cause(err, "read packet"))
		}
		if n < clashtcpip.IPv4PacketMinLength {
			continue
		}
		rawPacket := packetBuffer[:frontHeadroom+n]
		packet := packetBuffer[frontHeadroom+PacketOffset : frontHeadroom+n]
		m.processPacket(rawPacket, packet)
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
		m.processPacket(packet, packet)
		release()
	}
}

func (m *Mixed) batchLoop(linuxTUN BatchTUN, batchSize int) {
	frontHeadroom := m.tun.FrontHeadroom()
	packetBuffers := make([][]byte, batchSize)
	for i := range packetBuffers {
		packetBuffers[i] = make([]byte, m.mtu+frontHeadroom+PacketOffset)
	}
	packetSizes := make([]int, batchSize)
	for {
		n, err := linuxTUN.BatchRead(packetBuffers, packetSizes)
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
			packetBuffer := packetBuffers[i][:packetSizes[i]]
			if n < clashtcpip.IPv4PacketMinLength {
				continue
			}
			rawPacket := packetBuffer[:frontHeadroom+n]
			packet := packetBuffer[frontHeadroom+PacketOffset : frontHeadroom+n]
			m.processPacket(rawPacket, packet)
		}
	}
}

func (m *Mixed) processPacket(rawPacket []byte, packet []byte) {
	var err error
	switch ipVersion := packet[0] >> 4; ipVersion {
	case 4:
		err = m.processIPv4(rawPacket, packet)
	case 6:
		err = m.processIPv6(rawPacket, packet)
	default:
		err = E.New("ip: unknown version: ", ipVersion)
	}
	if err != nil {
		m.logger.Trace(err)
	}
}

func (m *Mixed) processIPv4(rawPacket []byte, packet clashtcpip.IPv4Packet) error {
	destination := packet.DestinationIP()
	if destination == m.broadcastAddr || !destination.IsGlobalUnicast() {
		return common.Error(m.tun.Write(rawPacket))
	}
	switch packet.Protocol() {
	case clashtcpip.TCP:
		return m.processIPv4TCP(rawPacket, packet, packet.Payload())
	case clashtcpip.UDP:
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		m.endpoint.InjectInbound(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
		return nil
	case clashtcpip.ICMP:
		return m.processIPv4ICMP(rawPacket, packet, packet.Payload())
	default:
		return common.Error(m.tun.Write(rawPacket))
	}
}

func (m *Mixed) processIPv6(rawPacket []byte, packet clashtcpip.IPv6Packet) error {
	if !packet.DestinationIP().IsGlobalUnicast() {
		return common.Error(m.tun.Write(rawPacket))
	}
	switch packet.Protocol() {
	case clashtcpip.TCP:
		return m.processIPv6TCP(rawPacket, packet, packet.Payload())
	case clashtcpip.UDP:
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		m.endpoint.InjectInbound(header.IPv6ProtocolNumber, pkt)
		pkt.DecRef()
		return nil
	case clashtcpip.ICMPv6:
		return m.processIPv6ICMP(rawPacket, packet, packet.Payload())
	default:
		return common.Error(m.tun.Write(rawPacket))
	}
}

func (m *Mixed) packetLoop() {
	for {
		packet := m.endpoint.ReadContext(m.ctx)
		if packet == nil {
			break
		}
		bufio.WriteVectorised(m.writer, packet.AsSlices())
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
