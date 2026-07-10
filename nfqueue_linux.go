//go:build linux

package tun

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"

	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type nfqueueHandler struct {
	ctx        context.Context
	cancel     context.CancelFunc
	handler    Handler
	logger     logger.Logger
	nfq        *nfqueue.Nfqueue
	queue      uint16
	outputMark uint32
	resetMark  uint32
	closed     atomic.Bool
}

type nfqueueOptions struct {
	Context    context.Context
	Handler    Handler
	Logger     logger.Logger
	Queue      uint16
	OutputMark uint32
	ResetMark  uint32
}

func newNFQueueHandler(options nfqueueOptions) (*nfqueueHandler, error) {
	ctx, cancel := context.WithCancel(options.Context)
	return &nfqueueHandler{
		ctx:        ctx,
		cancel:     cancel,
		handler:    options.Handler,
		logger:     options.Logger,
		queue:      options.Queue,
		outputMark: options.OutputMark,
		resetMark:  options.ResetMark,
	}, nil
}

func (h *nfqueueHandler) setVerdict(packetID uint32, verdict int, mark uint32) {
	var err error
	if mark != 0 {
		err = h.nfq.SetVerdictWithOption(packetID, verdict, nfqueue.WithMark(mark))
	} else {
		err = h.nfq.SetVerdict(packetID, verdict)
	}
	if err != nil && !h.closed.Load() && h.ctx.Err() == nil {
		h.logger.Trace(E.Cause(err, "set verdict"))
	}
}

func (h *nfqueueHandler) Start() error {
	config := nfqueue.Config{
		NfQueue:      h.queue,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  4096,
		Copymode:     nfqueue.NfQnlCopyPacket,
		AfFamily:     unix.AF_UNSPEC,
		Flags:        nfqueue.NfQaCfgFlagFailOpen | nfqueue.NfQaCfgFlagGSO,
	}

	nfq, err := nfqueue.Open(&config)
	if err != nil {
		return E.Cause(err, "open nfqueue")
	}

	if err = nfq.SetOption(netlink.NoENOBUFS, true); err != nil {
		nfq.Close()
		return E.Cause(err, "set nfqueue option")
	}

	err = nfq.RegisterWithErrorFunc(h.ctx, h.handlePacket, func(e error) int {
		if h.ctx.Err() != nil {
			return 1
		}
		h.logger.Error("nfqueue error: ", e)
		return 0
	})
	if err != nil {
		nfq.Close()
		return E.Cause(err, "register nfqueue")
	}

	h.nfq = nfq
	return nil
}

const ipv6AuthenticationHeaderIdentifier header.IPv6ExtensionHeaderIdentifier = 51

type preMatchPacket struct {
	protocol    uint8
	network     string
	source      M.Socksaddr
	destination M.Socksaddr
}

func parsePreMatchPacket(packet []byte) (preMatchPacket, bool) {
	if len(packet) < 1 {
		return preMatchPacket{}, false
	}
	var (
		protocol        uint8
		transportOffset int
		source          netip.Addr
		destination     netip.Addr
	)
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return preMatchPacket{}, false
		}
		ipHdr := header.IPv4(packet)
		transportOffset = int(ipHdr.HeaderLength())
		if transportOffset < header.IPv4MinimumSize || transportOffset > len(packet) || int(ipHdr.TotalLength()) < transportOffset || ipHdr.FragmentOffset() != 0 {
			return preMatchPacket{}, false
		}
		protocol = uint8(ipHdr.TransportProtocol())
		source = ipHdr.SourceAddr()
		destination = ipHdr.DestinationAddr()
	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize {
			return preMatchPacket{}, false
		}
		ipHdr := header.IPv6(packet)
		var ok bool
		protocol, transportOffset, ok = parsePreMatchIPv6Transport(packet)
		if !ok {
			return preMatchPacket{}, false
		}
		source = ipHdr.SourceAddr()
		destination = ipHdr.DestinationAddr()
	default:
		return preMatchPacket{}, false
	}

	transport := packet[transportOffset:]
	parsed := preMatchPacket{protocol: protocol}
	switch protocol {
	case uint8(header.TCPProtocolNumber):
		if len(transport) < header.TCPMinimumSize {
			return preMatchPacket{}, false
		}
		tcpHdr := header.TCP(transport)
		flags := tcpHdr.Flags()
		if !flags.Contains(header.TCPFlagSyn) || flags.Contains(header.TCPFlagAck) {
			return preMatchPacket{}, false
		}
		parsed.network = N.NetworkTCP
		parsed.source = M.SocksaddrFrom(source, tcpHdr.SourcePort())
		parsed.destination = M.SocksaddrFrom(destination, tcpHdr.DestinationPort())
	case uint8(header.UDPProtocolNumber):
		if len(transport) < header.UDPMinimumSize {
			return preMatchPacket{}, false
		}
		udpHdr := header.UDP(transport)
		if int(udpHdr.Length()) < header.UDPMinimumSize {
			return preMatchPacket{}, false
		}
		parsed.network = N.NetworkUDP
		parsed.source = M.SocksaddrFrom(source, udpHdr.SourcePort())
		parsed.destination = M.SocksaddrFrom(destination, udpHdr.DestinationPort())
	case uint8(header.ICMPv4ProtocolNumber):
		if !source.Is4() || len(transport) < header.ICMPv4MinimumSize {
			return preMatchPacket{}, false
		}
		icmpHdr := header.ICMPv4(transport)
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
			return preMatchPacket{}, false
		}
		parsed.network = N.NetworkICMP
		parsed.source = M.SocksaddrFrom(source, 0)
		parsed.destination = M.SocksaddrFrom(destination, 0)
	case uint8(header.ICMPv6ProtocolNumber):
		if !source.Is6() || len(transport) < header.ICMPv6MinimumSize {
			return preMatchPacket{}, false
		}
		icmpHdr := header.ICMPv6(transport)
		if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
			return preMatchPacket{}, false
		}
		parsed.network = N.NetworkICMP
		parsed.source = M.SocksaddrFrom(source, 0)
		parsed.destination = M.SocksaddrFrom(destination, 0)
	default:
		return preMatchPacket{}, false
	}
	return parsed, true
}

func parsePreMatchIPv6Transport(packet []byte) (transportProto uint8, transportOffset int, ok bool) {
	nextHeader := header.IPv6(packet).NextHeader()
	offset := header.IPv6MinimumSize
	for {
		switch header.IPv6ExtensionHeaderIdentifier(nextHeader) {
		case header.IPv6HopByHopOptionsExtHdrIdentifier,
			header.IPv6RoutingExtHdrIdentifier,
			header.IPv6DestinationOptionsExtHdrIdentifier:
			if len(packet) < offset+2 {
				return 0, 0, false
			}
			nextHeader = packet[offset]
			extensionLength := (int(packet[offset+1]) + 1) * 8
			if len(packet) < offset+extensionLength {
				return 0, 0, false
			}
			offset += extensionLength
		case header.IPv6FragmentExtHdrIdentifier:
			if len(packet) < offset+header.IPv6FragmentHeaderSize {
				return 0, 0, false
			}
			fragmentHdr := header.IPv6Fragment(packet[offset:])
			if fragmentHdr.FragmentOffset() != 0 {
				return 0, 0, false
			}
			nextHeader = fragmentHdr.NextHeader()
			offset += header.IPv6FragmentHeaderSize
		case ipv6AuthenticationHeaderIdentifier:
			if len(packet) < offset+2 {
				return 0, 0, false
			}
			nextHeader = packet[offset]
			extensionLength := (int(packet[offset+1]) + 2) * 4
			if len(packet) < offset+extensionLength {
				return 0, 0, false
			}
			offset += extensionLength
		case header.IPv6NoNextHeaderIdentifier:
			return 0, 0, false
		default:
			return nextHeader, offset, true
		}
	}
}

func (h *nfqueueHandler) handlePacket(attr nfqueue.Attribute) int {
	if h.closed.Load() {
		return 0
	}
	if attr.PacketID == nil || attr.Payload == nil {
		return 0
	}

	packetID := *attr.PacketID
	payload := *attr.Payload

	packet, loaded := parsePreMatchPacket(payload)
	if !loaded {
		h.setVerdict(packetID, nfqueue.NfAccept, 0)
		return 0
	}

	_, pErr := h.handler.PrepareConnection(packet.network, packet.source, packet.destination, nil, 0)

	// Use NfRepeat for bypass/reset so the packet re-enters the chain
	// from the beginning, allowing mark-checking rules to save the mark
	// to conntrack. NfAccept is a terminal verdict in nftables — it exits
	// the chain immediately, skipping any rules after the queue statement.
	switch {
	case errors.Is(pErr, ErrBypass):
		h.setVerdict(packetID, nfqueue.NfRepeat, h.outputMark)
	case errors.Is(pErr, ErrReset):
		if packet.protocol == uint8(unix.IPPROTO_TCP) {
			h.setVerdict(packetID, nfqueue.NfRepeat, h.resetMark)
		} else {
			h.setVerdict(packetID, nfqueue.NfAccept, 0)
		}
	case errors.Is(pErr, ErrDrop):
		h.setVerdict(packetID, nfqueue.NfDrop, 0)
	default:
		h.setVerdict(packetID, nfqueue.NfAccept, 0)
	}

	return 0
}

func (h *nfqueueHandler) Close() error {
	h.closed.Store(true)
	h.cancel()
	if h.nfq != nil {
		h.nfq.Close()
	}
	return nil
}
