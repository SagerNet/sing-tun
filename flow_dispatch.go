package tun

import (
	"encoding/binary"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	tcpEstablishedTimeout = 2*time.Hour + 4*time.Minute
	tcpTransitoryTimeout  = 4 * time.Minute
	tcpClosingTimeout     = 10 * time.Second

	defaultUDPTimeout = 5 * time.Minute

	defaultICMPTimeout = time.Minute

	flowTombstoneTimeout = 4 * time.Minute

	flowTableCapacity = 16384
	flowStageCapacity = 1024

	flowSweepInterval = 30 * time.Second
	flowSweepLimit    = flowTableCapacity / int(flowTombstoneTimeout/flowSweepInterval)
)

type ForwardWriteback interface {
	ReturnHeadroom() int
	WriteReturnPackets(packets [][]byte) error
}

type ForwardFrameMeta struct {
	needsChecksum  bool
	checksumStart  uint16
	checksumOffset uint16
	gsoType        uint8
	gsoSize        uint16
}

func (m *ForwardFrameMeta) completeChecksum(raw []byte) {
	if !m.needsChecksum {
		return
	}
	m.needsChecksum = false
	checksumAt := int(m.checksumStart) + int(m.checksumOffset)
	if int(m.checksumStart) >= len(raw) || checksumAt+2 > len(raw) {
		return
	}
	initial := binary.BigEndian.Uint16(raw[checksumAt:])
	raw[checksumAt], raw[checksumAt+1] = 0, 0
	binary.BigEndian.PutUint16(raw[checksumAt:], ^checksum.Checksum(raw[m.checksumStart:], initial))
}

type flowEntry struct {
	action   FlowAction
	deadline int64
	idle     time.Duration
	flow     *forwardFlow
	verdict  FlowVerdict
}

type forwardFlow struct {
	nat          *portNAT
	owner        *ForwardStage
	reverseKey   flowKey
	forwardRule  rewriteRule
	reverseRule  rewriteRule
	effectiveMTU uint32
	protocol     uint8
	udpTimeout   time.Duration
	tracker      FlowTracker

	clientAddress            netip.Addr
	clientSelector           uint16
	clientDestinationAddress netip.Addr
	clientDestinationPort    uint16
	serverAddress            netip.Addr
	dnatAddress              bool
	dnatPort                 bool

	finForward  atomic.Bool
	established atomic.Bool
	finReverse  atomic.Bool
	reported    atomic.Bool
	closed      atomic.Bool
	lastReverse atomic.Int64
}

func (f *forwardFlow) report(reason FlowCloseReason) {
	if !f.reported.CompareAndSwap(false, true) {
		return
	}
	if f.tracker != nil {
		f.tracker.CloseFlow(reason)
	}
}

func (f *forwardFlow) close(reason FlowCloseReason) {
	if !f.closed.CompareAndSwap(false, true) {
		return
	}
	f.report(reason)
}

func (f *forwardFlow) CloseFlow() {
	f.close(FlowCloseReset)
}

func (f *forwardFlow) observeReverse(packet *forwardPacket, now int64) {
	f.lastReverse.Store(now)
	if packet.protocol != uint8(header.TCPProtocolNumber) {
		return
	}
	if f.established.CompareAndSwap(false, true) && f.tracker != nil {
		f.tracker.FlowEstablished()
	}
	if packet.tcpFlags&header.TCPFlagRst != 0 {
		f.close(FlowCloseReset)
		return
	}
	if packet.tcpFlags&header.TCPFlagFin != 0 {
		f.finReverse.Store(true)
	} else if f.finReverse.Load() && f.finForward.Load() {
		f.report(FlowCloseFinished)
	}
}

type ForwardDispatcher struct {
	epoch       time.Time
	handler     Handler
	writeback   ForwardWriteback
	logger      logger.Logger
	udpTimeout  time.Duration
	icmpTimeout time.Duration

	portsAccess     sync.Mutex
	ports           map[Port]*portNAT
	natList         atomic.Pointer[[]*portNAT]
	revNAT          atomic.Pointer[map[netip.Addr]*portNAT]
	returnPath      forwardReturn
	stagesAccess    sync.Mutex
	stages          []*ForwardStage
	stageCount      atomic.Int32
	resetGeneration atomic.Uint32
}

type stagedPort struct {
	nat     *portNAT
	packets [][]byte
}

type ForwardStage struct {
	dispatcher *ForwardDispatcher
	writeback  ForwardWriteback
	access     sync.Mutex
	table      map[flowKey]*flowEntry
	lastSweep  int64
	resetSeen  uint32

	exhaustedLogAt int64
	ports          []stagedPort
	writebackBatch [][]byte
	segmentBuffers [][]byte
	segmentSizes   []int
	segmentUsed    int
}

func addrToTCPIP(addr netip.Addr) tcpip.Address {
	if addr.Is4() {
		return tcpip.AddrFrom4(addr.As4())
	}
	return tcpip.AddrFrom16(addr.As16())
}

func NewForwardDispatcher(handler Handler, writeback ForwardWriteback, logger logger.Logger, udpTimeout time.Duration, icmpTimeout time.Duration) *ForwardDispatcher {
	dispatcher := &ForwardDispatcher{
		epoch:       time.Now(),
		handler:     handler,
		writeback:   writeback,
		logger:      logger,
		udpTimeout:  udpTimeout,
		icmpTimeout: icmpTimeout,
		ports:       make(map[Port]*portNAT),
	}
	if dispatcher.udpTimeout <= 0 {
		dispatcher.udpTimeout = defaultUDPTimeout
	}
	if dispatcher.icmpTimeout <= 0 {
		dispatcher.icmpTimeout = defaultICMPTimeout
	}
	dispatcher.returnPath.dispatcher = dispatcher
	return dispatcher
}

func (d *ForwardDispatcher) NewStage(writeback ForwardWriteback) *ForwardStage {
	if d == nil {
		return nil
	}
	if writeback == nil {
		writeback = d.writeback
	}
	stage := &ForwardStage{
		dispatcher: d,
		writeback:  writeback,
		table:      make(map[flowKey]*flowEntry),
		resetSeen:  d.resetGeneration.Load(),
	}
	d.stagesAccess.Lock()
	d.stages = append(d.stages, stage)
	d.stageCount.Store(int32(len(d.stages)))
	d.stagesAccess.Unlock()
	return stage
}

func (d *ForwardDispatcher) now() int64 {
	return int64(time.Since(d.epoch))
}

func (d *ForwardDispatcher) Close() {
	if d == nil {
		return
	}
	d.returnPath.closed.Store(true)
	d.stagesAccess.Lock()
	stages := d.stages
	d.stagesAccess.Unlock()
	for _, stage := range stages {
		stage.access.Lock()
		for key, entry := range stage.table {
			stage.removeEntry(key, entry, FlowCloseReset)
		}
		stage.access.Unlock()
	}
	d.portsAccess.Lock()
	ports := make([]Port, 0, len(d.ports))
	for port := range d.ports {
		ports = append(ports, port)
	}
	d.portsAccess.Unlock()
	for _, port := range ports {
		port.DetachReturn(&d.returnPath)
	}
}

func (s *ForwardStage) Dispatch(packet []byte) bool {
	if s == nil || s.dispatcher.returnPath.closed.Load() {
		return false
	}
	parsed, ok := parseForwardPacket(packet)
	if !ok {
		return false
	}
	return s.dispatch(packet, &parsed, nil)
}

func (s *ForwardStage) DispatchParsed(packet []byte, meta ForwardFrameMeta, parsed *forwardPacket) bool {
	if s == nil || s.dispatcher.returnPath.closed.Load() {
		return false
	}
	return s.dispatch(packet, parsed, &meta)
}

func (s *ForwardStage) dispatch(packet []byte, parsed *forwardPacket, meta *ForwardFrameMeta) bool {
	if parsed.fragment || !parsed.hasFlow {
		return false
	}
	key := parsed.flowKey()
	now := s.dispatcher.now()
	s.access.Lock()
	entry, loaded := s.table[key]
	if loaded {
		if entryExpired(entry, now) {
			s.removeEntry(key, entry, FlowCloseTimeout)
		} else {
			handled, remove := s.handleHit(entry, parsed, packet, now, meta)
			if remove {
				s.removeEntry(key, entry, FlowCloseReset)
			}
			s.access.Unlock()
			return handled
		}
	}
	s.access.Unlock()
	if parsed.protocol == uint8(header.TCPProtocolNumber) &&
		(parsed.tcpFlags&header.TCPFlagSyn == 0 || parsed.tcpFlags&header.TCPFlagAck != 0) {
		return false
	}
	return s.judgeAndInstall(key, parsed, packet, meta)
}

func (s *ForwardStage) teardownFlow(key flowKey, reason FlowCloseReason) {
	if s == nil || s.dispatcher.returnPath.closed.Load() {
		return
	}
	s.access.Lock()
	entry, loaded := s.table[key]
	if loaded {
		s.removeEntry(key, entry, reason)
	}
	s.access.Unlock()
}

func (s *ForwardStage) handleHit(entry *flowEntry, packet *forwardPacket, raw []byte, now int64, meta *ForwardFrameMeta) (handled bool, remove bool) {
	switch entry.action {
	case ActionFlow:
		flow := entry.flow
		if flow.closed.Load() {
			tombstoneEntry(entry, now)
			return true, false
		}
		var flowFinished bool
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			if packet.tcpFlags&header.TCPFlagRst != 0 {
				s.forwardToPort(flow, packet, raw, meta)
				flow.close(FlowCloseReset)
				tombstoneEntry(entry, now)
				return true, false
			}
			if packet.tcpFlags&header.TCPFlagFin != 0 {
				flow.finForward.Store(true)
			} else if flow.finForward.Load() && flow.finReverse.Load() {
				flowFinished = true
			}
		}
		entry.idle = s.dispatcher.flowIdle(flow)
		entry.deadline = now + int64(entry.idle)
		s.forwardToPort(flow, packet, raw, meta)
		if flowFinished {
			flow.report(FlowCloseFinished)
		}
		return true, false
	case ActionAccept:
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			if packet.tcpFlags&header.TCPFlagRst != 0 {
				return false, true
			}
			if packet.tcpFlags&header.TCPFlagSyn == 0 {
				entry.idle = tcpEstablishedTimeout
			}
		} else if packet.protocol == uint8(header.UDPProtocolNumber) {
			packet.verdict = entry.verdict
		}
		entry.deadline = now + int64(entry.idle)
		return false, false
	case ActionReject:
		entry.deadline = now + int64(entry.idle)
		s.stageReject(packet, raw, meta)
		return true, false
	default:
		entry.deadline = now + int64(entry.idle)
		return true, false
	}
}

func (s *ForwardStage) judgeAndInstall(key flowKey, packet *forwardPacket, raw []byte, meta *ForwardFrameMeta) bool {
	d := s.dispatcher
	var firstPacket []byte
	if packet.protocol == uint8(header.UDPProtocolNumber) {
		firstPacket = header.UDP(packet.transport).Payload()
	}
	verdict := d.handler.JudgeFlow(packet.protocol, packet.source, packet.destination, firstPacket)
	if verdict.Action == ActionBypass && verdict.Port != nil {
		verdict.Action = ActionFlow
	}
	s.access.Lock()
	defer s.access.Unlock()
	if d.returnPath.closed.Load() {
		return false
	}
	now := d.now()
	existing, loaded := s.table[key]
	if loaded {
		if entryExpired(existing, now) {
			s.removeEntry(key, existing, FlowCloseTimeout)
		} else {
			handled, remove := s.handleHit(existing, packet, raw, now, meta)
			if remove {
				s.removeEntry(key, existing, FlowCloseReset)
			}
			return handled
		}
	}
	switch verdict.Action {
	case ActionFlow:
		if verdict.Port != nil {
			flow, result := s.createFlow(packet, verdict)
			if result == createFlowOK {
				entry := &flowEntry{action: ActionFlow, flow: flow, idle: d.flowIdle(flow)}
				entry.deadline = now + int64(entry.idle)
				s.insertEntry(key, entry, now)
				s.forwardToPort(flow, packet, raw, meta)
				return true
			}
			if result == createFlowExhausted {
				if now-s.exhaustedLogAt >= int64(exhaustedLogInterval) {
					s.exhaustedLogAt = now
					d.logger.Warn("port selector range exhausted, rejecting flow to ", packet.destination)
				}
				s.installSimple(key, ActionReject, packet.protocol, now)
				s.stageReject(packet, raw, meta)
				return true
			}
		}
		s.installAccept(key, packet, verdict, now)
		return false
	case ActionReject:
		s.installSimple(key, ActionReject, packet.protocol, now)
		s.stageReject(packet, raw, meta)
		return true
	case ActionDrop:
		s.installSimple(key, ActionDrop, packet.protocol, now)
		return true
	case ActionHijackDNS:
		if packet.protocol == uint8(header.UDPProtocolNumber) {
			d.hijackDNSPacket(packet)
			return true
		}
		s.installAccept(key, packet, verdict, now)
		return false
	default:
		s.installAccept(key, packet, verdict, now)
		return false
	}
}

func (s *ForwardStage) installSimple(key flowKey, action FlowAction, protocol uint8, now int64) *flowEntry {
	entry := &flowEntry{action: action, idle: s.dispatcher.idleTimeout(protocol, false)}
	entry.deadline = now + int64(entry.idle)
	s.insertEntry(key, entry, now)
	return entry
}

func (s *ForwardStage) installAccept(key flowKey, packet *forwardPacket, verdict FlowVerdict, now int64) {
	entry := s.installSimple(key, ActionAccept, packet.protocol, now)
	if packet.protocol == uint8(header.UDPProtocolNumber) {
		entry.verdict = verdict
		packet.verdict = verdict
	}
}

func (d *ForwardDispatcher) idleTimeout(protocol uint8, established bool) time.Duration {
	switch protocol {
	case uint8(header.TCPProtocolNumber):
		if established {
			return tcpEstablishedTimeout
		}
		return tcpTransitoryTimeout
	case uint8(header.UDPProtocolNumber):
		return d.udpTimeout
	default:
		return d.icmpTimeout
	}
}

func (d *ForwardDispatcher) flowIdle(flow *forwardFlow) time.Duration {
	if flow.protocol == uint8(header.TCPProtocolNumber) && flow.finForward.Load() && flow.finReverse.Load() {
		return tcpClosingTimeout
	}
	if flow.udpTimeout > 0 {
		return flow.udpTimeout
	}
	established := flow.established.Load() && !flow.finForward.Load() && !flow.finReverse.Load()
	return d.idleTimeout(flow.protocol, established)
}

type createFlowResult uint8

const (
	createFlowOK createFlowResult = iota
	createFlowUnsupported
	createFlowExhausted
)

const exhaustedLogInterval = 5 * time.Second

func (s *ForwardStage) createFlow(packet *forwardPacket, verdict FlowVerdict) (*forwardFlow, createFlowResult) {
	var portAddress netip.Addr
	inet4Address, inet6Address := verdict.Port.PortAddresses()
	if packet.ipVersion == 6 {
		portAddress = inet6Address
	} else {
		portAddress = inet4Address
	}
	if !portAddress.IsValid() {
		return nil, createFlowUnsupported
	}
	effectiveMTU := verdict.Port.PortMTU()
	if packet.ipVersion == 6 && effectiveMTU != 0 && effectiveMTU < header.IPv6MinimumMTU {
		return nil, createFlowUnsupported
	}
	isICMP := isICMPProtocol(packet.protocol)
	clientDestinationAddress := packet.destination.Addr()
	clientDestinationPort := packet.destination.Port()
	serverAddress := clientDestinationAddress
	serverPort := clientDestinationPort
	if verdict.Destination.Addr().IsValid() {
		serverAddress = verdict.Destination.Addr()
	}
	if verdict.Destination.Port() != 0 && !isICMP {
		serverPort = verdict.Destination.Port()
	}
	nat := s.dispatcher.natFor(verdict.Port)
	if nat == nil {
		return nil, createFlowUnsupported
	}
	selector, reverseKey, allocated := nat.reserveSelector(packet.protocol, portAddress, serverAddress, serverPort, packet.source.Port())
	if !allocated {
		return nil, createFlowExhausted
	}
	var udpTimeout time.Duration
	if packet.protocol == uint8(header.UDPProtocolNumber) {
		udpTimeout = verdict.UDPTimeout
	}
	flow := &forwardFlow{
		nat:                      nat,
		owner:                    s,
		reverseKey:               reverseKey,
		effectiveMTU:             effectiveMTU,
		protocol:                 packet.protocol,
		udpTimeout:               udpTimeout,
		clientAddress:            packet.source.Addr(),
		clientSelector:           packet.source.Port(),
		clientDestinationAddress: clientDestinationAddress,
		clientDestinationPort:    clientDestinationPort,
		serverAddress:            serverAddress,
		dnatAddress:              serverAddress != clientDestinationAddress,
		dnatPort:                 serverPort != clientDestinationPort && !isICMP,
	}
	flow.forwardRule = rewriteRule{
		sourceAddress:     addrToTCPIP(portAddress),
		sourcePort:        selector,
		rewriteSourcePort: true,
	}
	if flow.dnatAddress {
		flow.forwardRule.destinationAddress = addrToTCPIP(serverAddress)
	}
	if flow.dnatPort {
		flow.forwardRule.destinationPort = serverPort
		flow.forwardRule.rewriteDestinationPort = true
	}
	flow.reverseRule = rewriteRule{
		destinationAddress:     addrToTCPIP(flow.clientAddress),
		destinationPort:        flow.clientSelector,
		rewriteDestinationPort: true,
	}
	if flow.dnatAddress {
		flow.reverseRule.sourceAddress = addrToTCPIP(clientDestinationAddress)
	}
	if flow.dnatPort {
		flow.reverseRule.sourcePort = clientDestinationPort
		flow.reverseRule.rewriteSourcePort = true
	}
	if verdict.NewTracker != nil {
		flow.tracker = verdict.NewTracker()
		if flow.tracker != nil {
			flow.tracker.AttachFlow(flow)
		}
	}
	nat.insert(reverseKey, flow)
	return flow, createFlowOK
}

func (d *ForwardDispatcher) natFor(port Port) *portNAT {
	d.portsAccess.Lock()
	defer d.portsAccess.Unlock()
	nat, loaded := d.ports[port]
	if loaded {
		return nat
	}
	err := port.AttachReturn(&d.returnPath)
	if err != nil {
		d.logger.Trace(E.Cause(err, "attach return path"))
		return nil
	}
	nat = newPortNAT(port)
	d.ports[port] = nat
	var natList []*portNAT
	current := d.natList.Load()
	if current != nil {
		natList = append(natList, *current...)
	}
	natList = append(natList, nat)
	d.natList.Store(&natList)
	revMap := make(map[netip.Addr]*portNAT)
	if currentRev := d.revNAT.Load(); currentRev != nil {
		maps.Copy(revMap, *currentRev)
	}
	v4Address, v6Address := port.PortAddresses()
	if v4Address.IsValid() {
		revMap[v4Address] = nat
	}
	if v6Address.IsValid() {
		revMap[v6Address] = nat
	}
	d.revNAT.Store(&revMap)
	return nat
}

func (s *ForwardStage) forwardToPort(flow *forwardFlow, packet *forwardPacket, raw []byte, meta *ForwardFrameMeta) {
	effectiveMTU := flow.effectiveMTU
	if meta != nil {
		meta.completeChecksum(raw)
		if meta.gsoSize != 0 && packet.protocol == uint8(header.TCPProtocolNumber) {
			headerLength := len(raw) - len(packet.transport) + int(header.TCP(packet.transport).DataOffset())
			offloadMTU := uint32(headerLength) + uint32(meta.gsoSize)
			if effectiveMTU == 0 || offloadMTU < effectiveMTU {
				effectiveMTU = offloadMTU
			}
		}
	}
	if effectiveMTU != 0 && uint32(len(raw)) > effectiveMTU {
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			if flow.tracker != nil {
				flow.tracker.CountForward(len(raw))
			}
			rewriteForward(flow, packet)
			s.resegmentTCP(flow, packet, raw, effectiveMTU)
			return
		}
		if packet.ipVersion == 4 {
			ipHdr := header.IPv4(packet.network)
			if ipHdr.Flags()&header.IPv4FlagDontFragment == 0 {
				if flow.tracker != nil {
					flow.tracker.CountForward(len(raw))
				}
				rewriteForward(flow, packet)
				fragments, ok := fragmentIPv4Packet(ipHdr, flow.effectiveMTU)
				if ok {
					for _, fragment := range fragments {
						s.stagePort(flow.nat, fragment)
					}
				}
				return
			}
			reply, ok := buildFragmentationNeeded(ipHdr, flow.effectiveMTU, s.writeback.ReturnHeadroom())
			if ok {
				s.writebackBatch = append(s.writebackBatch, reply)
			}
			return
		}
		reply, ok := buildPacketTooBig(header.IPv6(packet.network), flow.effectiveMTU, s.writeback.ReturnHeadroom())
		if ok {
			s.writebackBatch = append(s.writebackBatch, reply)
		}
		return
	}
	if flow.tracker != nil {
		flow.tracker.CountForward(len(raw))
	}
	rewriteForward(flow, packet)
	if meta != nil {
		raw = s.copyForStage(raw)
	}
	s.stagePort(flow.nat, raw)
}

func (s *ForwardStage) copyForStage(raw []byte) []byte {
	staged, _ := s.reserveSegments(1, len(raw))
	copy(staged[0], raw)
	return staged[0]
}

func rewriteForward(flow *forwardFlow, packet *forwardPacket) {
	if packet.isTCPSyn() {
		applyRewriteRaw(packet, &flow.forwardRule)
		clampTCPMSS(packet, flow.effectiveMTU)
		recomputeChecksums(packet)
	} else {
		applyRewrite(packet, &flow.forwardRule)
	}
}

func (s *ForwardStage) stagePort(nat *portNAT, packet []byte) {
	for index := range s.ports {
		if s.ports[index].nat == nat {
			s.ports[index].packets = append(s.ports[index].packets, packet)
			return
		}
	}
	s.ports = append(s.ports, stagedPort{nat: nat, packets: [][]byte{packet}})
}

func (s *ForwardStage) stageReject(packet *forwardPacket, raw []byte, meta *ForwardFrameMeta) {
	if meta != nil {
		meta.completeChecksum(raw)
	}
	reply, ok := buildReject(packet, s.writeback.ReturnHeadroom())
	if ok {
		s.writebackBatch = append(s.writebackBatch, reply)
	}
}

func (d *ForwardDispatcher) ResetNetwork() {
	if d == nil {
		return
	}
	d.resetGeneration.Add(1)
}

func (s *ForwardStage) Flush() {
	if s == nil {
		return
	}
	d := s.dispatcher
	if d.returnPath.closed.Load() {
		return
	}
	now := d.now()
	generation := d.resetGeneration.Load()
	if s.resetSeen != generation {
		s.resetSeen = generation
		s.access.Lock()
		for key, entry := range s.table {
			s.removeEntry(key, entry, FlowCloseReset)
		}
		s.access.Unlock()
	}
	for index := range s.ports {
		staged := &s.ports[index]
		if len(staged.packets) == 0 {
			continue
		}
		err := staged.nat.port.WritePackets(staged.packets)
		if err != nil {
			d.logger.Trace(E.Cause(err, "forward packets"))
		}
		clear(staged.packets)
		staged.packets = staged.packets[:0]
	}
	if retain := max(s.segmentUsed, segmentRetainCount); len(s.segmentBuffers) > retain {
		clear(s.segmentBuffers[retain:])
		s.segmentBuffers = s.segmentBuffers[:retain]
		s.segmentSizes = s.segmentSizes[:retain]
	}
	s.segmentUsed = 0
	if len(s.writebackBatch) > 0 {
		err := s.writeback.WriteReturnPackets(s.writebackBatch)
		if err != nil {
			d.logger.Trace(E.Cause(err, "write back packets"))
		}
		clear(s.writebackBatch)
		s.writebackBatch = s.writebackBatch[:0]
	}
	if now-s.lastSweep >= int64(flowSweepInterval) {
		s.lastSweep = now
		s.access.Lock()
		s.sweep(now)
		s.access.Unlock()
	}
}

func entryExpired(entry *flowEntry, now int64) bool {
	if now <= entry.deadline {
		return false
	}
	if entry.action == ActionFlow {
		lastReverse := entry.flow.lastReverse.Load()
		reverseDeadline := lastReverse + int64(entry.idle)
		if lastReverse != 0 && now <= reverseDeadline {
			entry.deadline = reverseDeadline
			return false
		}
	}
	return true
}

func tombstoneEntry(entry *flowEntry, now int64) {
	entry.action = ActionDrop
	entry.idle = flowTombstoneTimeout
	entry.deadline = now + int64(entry.idle)
}

func (s *ForwardStage) removeEntry(key flowKey, entry *flowEntry, reason FlowCloseReason) {
	delete(s.table, key)
	if entry.flow != nil {
		if reason == FlowCloseTimeout && entry.flow.finForward.Load() && entry.flow.finReverse.Load() {
			reason = FlowCloseFinished
		}
		entry.flow.close(reason)
		entry.flow.nat.delete(entry.flow.reverseKey)
	}
}

func (s *ForwardStage) insertEntry(key flowKey, entry *flowEntry, now int64) {
	if len(s.table) >= max(flowTableCapacity/int(s.dispatcher.stageCount.Load()), flowStageCapacity) {
		s.evictEntries(now)
	}
	s.table[key] = entry
}

func (s *ForwardStage) evictEntries(now int64) {
	var (
		freed     int
		visited   int
		oldestKey flowKey
		oldest    *flowEntry
	)
	for key, entry := range s.table {
		if entryExpired(entry, now) {
			s.removeEntry(key, entry, FlowCloseTimeout)
			freed++
		} else if oldest == nil || entry.deadline < oldest.deadline {
			oldestKey = key
			oldest = entry
		}
		visited++
		if visited >= flowSweepLimit {
			break
		}
	}
	if freed == 0 && oldest != nil {
		s.removeEntry(oldestKey, oldest, FlowCloseReset)
	}
}

func (s *ForwardStage) sweep(now int64) {
	visited := 0
	for key, entry := range s.table {
		if entry.action == ActionFlow && entry.flow.closed.Load() {
			tombstoneEntry(entry, now)
		} else if entryExpired(entry, now) {
			s.removeEntry(key, entry, FlowCloseTimeout)
		}
		visited++
		if visited >= flowSweepLimit {
			break
		}
	}
}

func isICMPProtocol(protocol uint8) bool {
	return protocol == uint8(header.ICMPv4ProtocolNumber) || protocol == uint8(header.ICMPv6ProtocolNumber)
}

var _ Return = (*forwardReturn)(nil)

type forwardReturn struct {
	dispatcher *ForwardDispatcher
	closed     atomic.Bool
}

func (r *forwardReturn) ReturnHeadroom() int {
	return r.dispatcher.writeback.ReturnHeadroom()
}

type returnDecision uint8

const (
	returnPass returnDecision = iota
	returnWrite
	returnDrop
)

type returnBatch struct {
	writeback ForwardWriteback
	packets   [][]byte
}

func (r *forwardReturn) ReturnPackets(packets [][]byte) [][]byte {
	if r.closed.Load() {
		return packets
	}
	natListPtr := r.dispatcher.natList.Load()
	if natListPtr == nil {
		return packets
	}
	natList := *natListPtr
	var revMap map[netip.Addr]*portNAT
	if revPtr := r.dispatcher.revNAT.Load(); revPtr != nil {
		revMap = *revPtr
	}
	headroom := r.dispatcher.writeback.ReturnHeadroom()
	now := r.dispatcher.now()
	unconsumed := packets[:0]
	var batches []returnBatch
	for _, raw := range packets {
		decision, writeback := r.classifyReturn(raw, natList, revMap, headroom, now)
		switch decision {
		case returnWrite:
			index := slices.IndexFunc(batches, func(batch returnBatch) bool { return batch.writeback == writeback })
			if index < 0 {
				batches = append(batches, returnBatch{writeback: writeback})
				index = len(batches) - 1
			}
			batches[index].packets = append(batches[index].packets, raw)
		case returnDrop:
		default:
			unconsumed = append(unconsumed, raw)
		}
	}
	for _, batch := range batches {
		err := batch.writeback.WriteReturnPackets(batch.packets)
		if err != nil {
			r.dispatcher.logger.Trace(E.Cause(err, "write return packets"))
		}
	}
	return unconsumed
}

func (r *forwardReturn) classifyReturn(raw []byte, natList []*portNAT, revMap map[netip.Addr]*portNAT, headroom int, now int64) (returnDecision, ForwardWriteback) {
	if len(raw) < headroom+header.IPv4MinimumSize {
		return returnPass, nil
	}
	parsed, ok := parseForwardPacket(raw[headroom:])
	if !ok || parsed.fragment {
		return returnPass, nil
	}
	if !parsed.hasFlow {
		if parsed.isICMPError() {
			flow := returnICMPError(natList, revMap, &parsed)
			if flow != nil {
				return returnWrite, flow.owner.writeback
			}
		}
		return returnPass, nil
	}
	flow := findReverseFlow(natList, revMap, parsed.flowKey())
	if flow == nil {
		return returnPass, nil
	}
	if flow.closed.Load() {
		return returnDrop, nil
	}
	if flow.tracker != nil {
		flow.tracker.CountReverse(len(raw) - headroom)
	}
	flow.observeReverse(&parsed, now)
	if parsed.isTCPSyn() {
		applyRewriteRaw(&parsed, &flow.reverseRule)
		clampTCPMSS(&parsed, flow.effectiveMTU)
		recomputeChecksums(&parsed)
	} else {
		applyRewrite(&parsed, &flow.reverseRule)
	}
	return returnWrite, flow.owner.writeback
}

func findReverseFlow(natList []*portNAT, revMap map[netip.Addr]*portNAT, key flowKey) *forwardFlow {
	if nat, ok := revMap[key.destination.Addr()]; ok {
		if flow := nat.lookup(key); flow != nil {
			return flow
		}
	}
	for _, nat := range natList {
		if flow := nat.lookup(key); flow != nil {
			return flow
		}
	}
	return nil
}

func returnICMPError(natList []*portNAT, revMap map[netip.Addr]*portNAT, parsed *forwardPacket) *forwardFlow {
	inner, ok := parsed.icmpErrorInner()
	if !ok {
		return nil
	}
	embedded, parsedInner := parseEmbedded(inner)
	if !parsedInner {
		return nil
	}
	flow := findReverseFlow(natList, revMap, embedded.flowKey().reversed())
	if flow == nil || flow.closed.Load() {
		return nil
	}
	rewriteEmbeddedSource(&embedded, addrToTCPIP(flow.clientAddress), flow.clientSelector, true)
	if flow.dnatAddress || flow.dnatPort {
		rewriteEmbeddedDestination(&embedded, addrToTCPIP(flow.clientDestinationAddress), flow.clientDestinationPort, flow.dnatPort)
	}
	networkHeader := parsed.networkHeader()
	networkHeader.SetDestinationAddr(flow.clientAddress)
	if networkHeader.SourceAddr() == flow.serverAddress {
		networkHeader.SetSourceAddr(flow.clientDestinationAddress)
	}
	recomputeChecksums(parsed)
	return flow
}
