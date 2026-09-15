package tun

import (
	"context"
	"hash/maphash"
	"math/rand/v2"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	goSynRetransmit     = time.Second
	goSynAttempts       = 6
	goEphemeralPortBase = 32768
	goEphemeralPortSpan = 60999 - goEphemeralPortBase + 1
	goEphemeralAttempts = 1024
)

var errGoInvalidAddress = E.New("go: invalid address")

func (s *Go) DialTCP(ctx context.Context, source netip.Addr, destination netip.AddrPort) (*GoConn, error) {
	source = source.Unmap()
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	if !source.IsValid() || !destination.IsValid() || destination.Port() == 0 || source.Is4() != destination.Addr().Is4() {
		return nil, errGoInvalidAddress
	}
	engine, err := s.selectEngine(destination)
	if err != nil {
		return nil, err
	}
	conn := new(GoConn)
	conn.initialize(engine, flowKey{}, M.SocksaddrFromNetIP(destination), M.SocksaddrFrom(source, 0))
	conn.socket = true
	conn.ipVersion = goIPVersion(source)
	conn.state = goTCPSynSent
	conn.phase = goPhaseEngaged
	conn.localWindowShift = goLocalWindowShift
	conn.timestampsEnabled = true
	conn.sackPermitted = true
	conn.receiveCapacity = min(goReceiveCapacityBase, conn.receiveWindowBound())
	conn.dialMessage = goMessage{kind: goMessageConnDial, conn: conn}
	engine.postMessage(&conn.dialMessage)
	err = conn.awaitHandshake(ctx, nil)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func goIPVersion(addr netip.Addr) uint8 {
	if addr.Is4() {
		return 4
	}
	return 6
}

func (s *Go) selectEngine(destination netip.AddrPort) (*goEngine, error) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed.Load() {
		return nil, net.ErrClosed
	}
	return s.engines[maphash.Comparable(s.engines[0].sequenceSeed, destination)%uint64(len(s.engines))], nil
}

func goAllocatePort(available func(port uint16) bool) (uint16, bool) {
	offset := rand.IntN(goEphemeralPortSpan)
	for attempt := range goEphemeralAttempts {
		port := uint16(goEphemeralPortBase + (offset+attempt)%goEphemeralPortSpan)
		if available(port) {
			return port, true
		}
	}
	return 0, false
}

func (e *goEngine) handleDial(conn *GoConn) {
	if conn.dead {
		return
	}
	if len(e.flows) >= e.flowCapacity && !e.evictFlow() {
		e.detachConn(conn, E.Cause(syscall.ENOBUFS, "go: flow table full"), goDeathImmediate)
		return
	}
	key := flowKey{protocol: uint8(header.TCPProtocolNumber), source: conn.peer.AddrPort()}
	port, allocated := goAllocatePort(func(port uint16) bool {
		key.destination = netip.AddrPortFrom(conn.local.Addr, port)
		return e.flows[key] == nil && (len(e.stack.engines) == 1 || e.stack.directory.lookup(key) == nil) && e.lookupListener(key.destination) == nil
	})
	if !allocated {
		e.detachConn(conn, E.Cause(syscall.EADDRINUSE, "go: ephemeral ports exhausted"), goDeathImmediate)
		return
	}
	now := e.coarseTime.Load()
	conn.key = key
	conn.local.Port = port
	conn.sendISN = e.initialSequence(key, now)
	conn.lastActivity = now
	conn.buildHandshake(e.localMSS(conn.ipVersion), true, true, header.TCPFlagSyn, 0)
	conn.keyed = true
	e.stack.directory.insert(key, conn)
	err := goIgnoreDropped(conn.engine.platformIO.writePacket(conn.handshakeImage[:conn.handshakeLength], ForwardFrameMeta{}))
	if err != nil {
		e.detachConn(conn, E.Cause(err, "go: send SYN"), goDeathImmediate)
		return
	}
	conn.handshakeAttempts = 0
	conn.handshakeStamp = now
	conn.handshakeDeadline = now + int64(goSynRetransmit)
	e.rearmTimer(conn)
}

func (e *goEngine) retransmitSyn(conn *GoConn, now int64) {
	conn.handshakeAttempts++
	if conn.handshakeAttempts >= goSynAttempts {
		conn.handshakeDeadline = 0
		e.detachConn(conn, E.Cause(syscall.ETIMEDOUT, "go: connect timeout"), goDeathImmediate)
		return
	}
	conn.buildHandshake(e.localMSS(conn.ipVersion), true, true, header.TCPFlagSyn, 0)
	err := goIgnoreDropped(conn.engine.platformIO.writePacket(conn.handshakeImage[:conn.handshakeLength], ForwardFrameMeta{}))
	if err != nil {
		e.stack.logger.Trace(E.Cause(err, "go: resend SYN"))
	}
	conn.handshakeDeadline = now + int64(goSynRetransmit)<<conn.handshakeAttempts
	e.rearmTimer(conn)
}

func (e *goEngine) inputSynSent(conn *GoConn, parsed *forwardPacket, tcpHdr header.TCP, dataOffset int) {
	flags := tcpHdr.Flags()
	ackAcceptable := false
	if flags&header.TCPFlagAck != 0 {
		if tcpHdr.AckNumber() != conn.sendISN+1 {
			if flags&header.TCPFlagRst == 0 {
				e.answerNoFlow(parsed)
			}
			return
		}
		ackAcceptable = true
	}
	if flags&header.TCPFlagRst != 0 {
		if ackAcceptable {
			e.detachConn(conn, E.Cause(syscall.ECONNREFUSED, "go: connection refused"), goDeathImmediate)
		}
		return
	}
	if flags&header.TCPFlagSyn == 0 || !ackAcceptable {
		return
	}
	synOptions := header.ParseSynOptions(tcpHdr[header.TCPMinimumSize:dataOffset], true)
	now := e.coarseTime.Load()
	conn.clientISN = tcpHdr.SequenceNumber()
	conn.peerMSS = synOptions.MSS
	effectiveMSS := min(synOptions.MSS, e.localMSS(conn.ipVersion))
	conn.sackPermitted = synOptions.SACKPermitted
	if synOptions.WS >= 0 {
		conn.peerWindowShift = uint8(synOptions.WS)
	} else {
		conn.localWindowShift = 0
	}
	if synOptions.TS {
		conn.tsRecent.Store(synOptions.TSVal)
		effectiveMSS -= goTimestampOptionLength
	} else {
		conn.timestampsEnabled = false
	}
	conn.effectiveMSS.Store(uint32(effectiveMSS))
	e.initializeSession(conn, now, tcpHdr.WindowSize())
	if conn.handshakeAttempts == 0 {
		roundTrip := max((now-conn.handshakeStamp)/int64(time.Microsecond), 1)
		e.ackUpdateRoundTrip(conn, 0, roundTrip, -1, roundTrip, &e.rateSample, 0, false, now)
	}
	e.establishConn(conn)
	e.rearmTimer(conn)
	e.sendAck(conn)
}

func (e *goEngine) inputICMPError(parsed *forwardPacket) {
	inner, ok := parsed.icmpErrorInner()
	if !ok {
		return
	}
	embedded, ok := parseEmbedded(inner)
	if !ok {
		return
	}
	mtu, tooBig := goICMPPacketTooBig(parsed)
	if tooBig {
		e.inputPacketTooBig(&embedded, mtu)
		return
	}
	err := goICMPError(parsed)
	if err == nil {
		return
	}
	switch embedded.protocol {
	case uint8(header.TCPProtocolNumber):
		conn := e.flows[embedded.flowKey().reversed()]
		if conn == nil || conn.dead || conn.state != goTCPSynSent {
			return
		}
		if len(embedded.payload) < header.TCPAckNumOffset || header.TCP(embedded.payload).SequenceNumber() != conn.sendISN {
			return
		}
		e.detachConn(conn, E.Cause(err, "go: connect"), goDeathImmediate)
	case uint8(header.UDPProtocolNumber):
		socket := e.udpSockets[embedded.source]
		if socket == nil || !socket.connected || socket.remote != embedded.destination {
			return
		}
		socket.deliverError(err)
	}
}

func goICMPError(parsed *forwardPacket) error {
	switch parsed.protocol {
	case uint8(header.ICMPv4ProtocolNumber):
		icmpHdr := header.ICMPv4(parsed.transport)
		switch icmpHdr.Type() {
		case header.ICMPv4DstUnreachable:
			switch icmpHdr.Code() {
			case header.ICMPv4NetUnreachable, header.ICMPv4NetUnreachableForTos:
				return syscall.ENETUNREACH
			case header.ICMPv4HostUnreachable, header.ICMPv4HostUnreachableForTos:
				return syscall.EHOSTUNREACH
			case header.ICMPv4ProtoUnreachable:
				return syscall.EPROTO
			case header.ICMPv4PortUnreachable:
				return syscall.ECONNREFUSED
			case header.ICMPv4NetProhibited, header.ICMPv4HostProhibited:
				return syscall.EACCES
			default:
				return syscall.EHOSTUNREACH
			}
		case header.ICMPv4TimeExceeded:
			return syscall.EHOSTUNREACH
		case header.ICMPv4ParamProblem:
			return syscall.EPROTO
		default:
			return nil
		}
	case uint8(header.ICMPv6ProtocolNumber):
		icmpHdr := header.ICMPv6(parsed.transport)
		switch icmpHdr.Type() {
		case header.ICMPv6DstUnreachable:
			switch icmpHdr.Code() {
			case header.ICMPv6NetworkUnreachable:
				return syscall.ENETUNREACH
			case header.ICMPv6Prohibited:
				return syscall.EACCES
			case header.ICMPv6PortUnreachable:
				return syscall.ECONNREFUSED
			default:
				return syscall.EHOSTUNREACH
			}
		case header.ICMPv6TimeExceeded:
			return syscall.EHOSTUNREACH
		case header.ICMPv6ParamProblem:
			return syscall.EPROTO
		default:
			return nil
		}
	default:
		return nil
	}
}

func goICMPPacketTooBig(parsed *forwardPacket) (int, bool) {
	switch parsed.protocol {
	case uint8(header.ICMPv4ProtocolNumber):
		icmpHdr := header.ICMPv4(parsed.transport)
		if icmpHdr.Type() != header.ICMPv4DstUnreachable || icmpHdr.Code() != header.ICMPv4FragmentationNeeded {
			return 0, false
		}
		return int(icmpHdr.MTU()), true
	case uint8(header.ICMPv6ProtocolNumber):
		icmpHdr := header.ICMPv6(parsed.transport)
		if icmpHdr.Type() != header.ICMPv6PacketTooBig {
			return 0, false
		}
		return int(icmpHdr.MTU()), true
	default:
		return 0, false
	}
}

func (e *goEngine) inputPacketTooBig(embedded *embeddedPacket, mtu int) {
	if embedded.protocol != uint8(header.TCPProtocolNumber) || mtu == 0 {
		return
	}
	conn := e.flows[embedded.flowKey().reversed()]
	if conn == nil || conn.dead || conn.state < goTCPEstablished || len(embedded.payload) < header.TCPAckNumOffset {
		return
	}
	offset := conn.sendOffset(header.TCP(embedded.payload).SequenceNumber())
	if offset < int64(conn.sendUnacked.Load()) || offset >= int64(conn.sendNext()) {
		return
	}
	if conn.ipVersion == 4 {
		mtu = max(mtu, header.IPv4MinimumProcessableDatagramSize)
	} else {
		mtu = max(mtu, header.IPv6MinimumMTU)
	}
	mss := mtu - goNetworkHeaderLength(conn.ipVersion) - header.TCPMinimumSize
	if conn.timestampsEnabled {
		mss -= goTimestampOptionLength
	}
	if mss >= int(conn.effectiveMSS.Load()) {
		return
	}
	e.drainDescriptors(conn)
	lost := false
	start := conn.sendUnacked.Load()
	for index := range conn.scoreboard.entries {
		descriptor := &conn.scoreboard.entries[index]
		if descriptor.endOffset-start > uint64(mss) && descriptor.flags&(goDescriptorSacked|goDescriptorLost) == 0 {
			e.markLost(conn, descriptor)
			lost = true
		}
		start = descriptor.endOffset
	}
	conn.effectiveMSS.Store(uint32(mss))
	e.refreshPacketsOut(conn)
	if lost {
		e.enterCWR(conn)
		if conn.congestionState < goCongestionRecovery {
			e.enterRecovery(conn)
		}
		e.xmitRetransmitQueue(conn)
	}
	e.rearmRetransmit(conn)
	conn.publishPermit(conn.sendUnacked.Load())
}
