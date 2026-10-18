//go:build linux

package tun

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type nfqueueHandler struct {
	ctx            context.Context
	cancel         context.CancelFunc
	handler        AutoRedirectHandler
	logger         logger.Logger
	nfq            *nfqueue.Nfqueue
	queue          uint16
	inputMark      uint32
	outputMark     uint32
	resetMark      uint32
	tproxyMark     uint32
	markMask       uint32
	repeatOnAccept bool
	closed         atomic.Bool
	judgingAccess  sync.Mutex
	judging        map[flowKey]*nfqueueJudgement
}

type nfqueueJudgement struct {
	packet preMatchPacket
	queued []queuedPacket
}

type queuedPacket struct {
	id   uint32
	mark uint32
}

func (h *nfqueueHandler) acceptVerdict(packet preMatchPacket) (verdict int, mark uint32) {
	if !h.repeatOnAccept {
		return nfqueue.NfAccept, 0
	}
	if packet.protocol != uint8(unix.IPPROTO_TCP) {
		return nfqueue.NfRepeat, h.inputMark
	}
	if packet.destination.Addr().Is6() {
		if h.tproxyMark != 0 {
			return nfqueue.NfRepeat, h.tproxyMark
		}
		return nfqueue.NfRepeat, h.inputMark
	}
	return nfqueue.NfAccept, 0
}

func (h *nfqueueHandler) setVerdict(queued queuedPacket, verdict int, mark uint32) {
	var err error
	if mark != 0 {
		if h.markMask != 0 {
			mark = queued.mark&^h.markMask | mark
		}
		err = h.nfq.SetVerdictWithOption(queued.id, verdict, nfqueue.WithMark(mark))
	} else {
		err = h.nfq.SetVerdict(queued.id, verdict)
	}
	if err != nil && !h.closed.Load() && h.ctx.Err() == nil {
		h.logger.Trace(E.Cause(err, "set verdict"))
	}
}

// Without a bypass flag every packet a remaining NFQUEUE rule sends to an unbound queue is
// dropped, so the queue is unbound in Close rather than with the caller's context.
func (h *nfqueueHandler) Start() error {
	h.ctx, h.cancel = context.WithCancel(context.Background())
	h.judging = make(map[flowKey]*nfqueueJudgement)
	config := nfqueue.Config{
		NfQueue:      h.queue,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  4096,
		Copymode:     nfqueue.NfQnlCopyPacket,
		AfFamily:     unix.AF_UNSPEC,
		Flags:        nfqueue.NfQaCfgFlagGSO,
	}

	nfq, err := nfqueue.Open(&config)
	if err != nil {
		return E.Cause(err, "open nfqueue")
	}

	if err = nfq.SetOption(netlink.NoENOBUFS, true); err != nil {
		nfq.Close()
		return E.Cause(err, "set nfqueue option")
	}

	h.nfq = nfq
	err = nfq.RegisterWithErrorFunc(h.ctx, h.handlePacket, func(e error) int {
		if h.ctx.Err() != nil {
			return 1
		}
		h.logger.Error("nfqueue error: ", e)
		return 0
	})
	if err != nil {
		nfq.Close()
		h.nfq = nil
		return E.Cause(err, "register nfqueue")
	}
	return nil
}

const ipv6AuthenticationHeaderIdentifier header.IPv6ExtensionHeaderIdentifier = 51

type preMatchPacket struct {
	protocol    uint8
	source      netip.AddrPort
	destination netip.AddrPort
	firstPacket []byte
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
		parsed.source = netip.AddrPortFrom(source, tcpHdr.SourcePort())
		parsed.destination = netip.AddrPortFrom(destination, tcpHdr.DestinationPort())
	case uint8(header.UDPProtocolNumber):
		if len(transport) < header.UDPMinimumSize {
			return preMatchPacket{}, false
		}
		udpHdr := header.UDP(transport)
		udpLength := int(udpHdr.Length())
		if udpLength < header.UDPMinimumSize {
			return preMatchPacket{}, false
		}
		if udpLength < len(transport) {
			transport = transport[:udpLength]
		}
		parsed.source = netip.AddrPortFrom(source, udpHdr.SourcePort())
		parsed.destination = netip.AddrPortFrom(destination, udpHdr.DestinationPort())
		parsed.firstPacket = header.UDP(transport).Payload()
	case uint8(header.ICMPv4ProtocolNumber):
		if !source.Is4() || len(transport) < header.ICMPv4MinimumSize {
			return preMatchPacket{}, false
		}
		icmpHdr := header.ICMPv4(transport)
		if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
			return preMatchPacket{}, false
		}
		identifier := icmpHdr.Ident()
		parsed.source = netip.AddrPortFrom(source, identifier)
		parsed.destination = netip.AddrPortFrom(destination, identifier)
	case uint8(header.ICMPv6ProtocolNumber):
		if !source.Is6() || len(transport) < header.ICMPv6MinimumSize {
			return preMatchPacket{}, false
		}
		icmpHdr := header.ICMPv6(transport)
		if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
			return preMatchPacket{}, false
		}
		identifier := icmpHdr.Ident()
		parsed.source = netip.AddrPortFrom(source, identifier)
		parsed.destination = netip.AddrPortFrom(destination, identifier)
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

	queued := queuedPacket{id: *attr.PacketID}
	if attr.Mark != nil {
		queued.mark = *attr.Mark
	}

	packet, loaded := parsePreMatchPacket(*attr.Payload)
	if !loaded {
		h.setVerdict(queued, nfqueue.NfAccept, 0)
		return 0
	}

	key := flowKey{protocol: packet.protocol, source: packet.source, destination: packet.destination}
	h.judgingAccess.Lock()
	judgement, judging := h.judging[key]
	if judging {
		judgement.queued = append(judgement.queued, queued)
		h.judgingAccess.Unlock()
		return 0
	}
	judgement = &nfqueueJudgement{packet: packet, queued: []queuedPacket{queued}}
	h.judging[key] = judgement
	h.judgingAccess.Unlock()
	go h.judge(key, judgement)
	return 0
}

func (h *nfqueueHandler) judge(key flowKey, judgement *nfqueueJudgement) {
	packet := judgement.packet
	verdict := h.handler.JudgeFlow(
		packet.protocol,
		packet.source,
		packet.destination,
		packet.firstPacket,
	)
	for {
		h.judgingAccess.Lock()
		queuedPackets := judgement.queued
		judgement.queued = nil
		if len(queuedPackets) == 0 {
			delete(h.judging, key)
			h.judgingAccess.Unlock()
			return
		}
		h.judgingAccess.Unlock()
		for _, queued := range queuedPackets {
			h.applyVerdict(queued, packet, verdict)
		}
	}
}

func (h *nfqueueHandler) applyVerdict(queued queuedPacket, packet preMatchPacket, verdict FlowVerdict) {
	switch verdict.Action {
	case ActionBypass:
		h.setVerdict(queued, nfqueue.NfRepeat, h.outputMark)
	case ActionReject:
		if packet.protocol == uint8(unix.IPPROTO_TCP) {
			h.setVerdict(queued, nfqueue.NfRepeat, h.resetMark)
		} else {
			h.setVerdict(queued, nfqueue.NfRepeat, h.inputMark)
		}
	case ActionDrop:
		h.setVerdict(queued, nfqueue.NfDrop, 0)
	case ActionFlow, ActionHijackDNS:
		h.setVerdict(queued, nfqueue.NfRepeat, h.inputMark)
	default:
		if packet.protocol == uint8(unix.IPPROTO_TCP) {
			acceptVerdict, acceptMark := h.acceptVerdict(packet)
			h.setVerdict(queued, acceptVerdict, acceptMark)
		} else {
			h.setVerdict(queued, nfqueue.NfRepeat, h.inputMark)
		}
	}
}

func (h *nfqueueHandler) Close() error {
	h.closed.Store(true)
	h.cancel()
	if h.nfq != nil {
		h.nfq.Close()
	}
	return nil
}
