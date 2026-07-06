package tun

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun/gtcpip"
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

	flowSweepInterval = 30 * time.Second
	flowSweepLimit    = flowTableCapacity / int(flowTombstoneTimeout/flowSweepInterval)
)

type ForwardWriteback interface {
	ReturnHeadroom() int
	WriteReturnPackets(packets [][]byte) error
}

type flowEntry struct {
	action   FlowAction
	deadline int64
	idle     time.Duration
	flow     *forwardFlow
}

type forwardFlow struct {
	nat          *portNAT
	reverseKey   flowKey
	forwardRule  rewriteRule
	reverseRule  rewriteRule
	effectiveMTU uint32
	protocol     uint8
	tracker      FlowTracker

	clientAddress            netip.Addr
	clientSelector           uint16
	clientDestinationAddress netip.Addr
	clientDestinationPort    uint16
	serverAddress            netip.Addr
	dnatAddress              bool
	dnatPort                 bool

	finForward  bool
	established atomic.Bool
	finReverse  atomic.Bool
	closed      atomic.Bool
	lastReverse atomic.Int64
}

func (f *forwardFlow) close(reason FlowCloseReason) {
	if !f.closed.CompareAndSwap(false, true) {
		return
	}
	if f.tracker != nil {
		f.tracker.CloseFlow(reason)
	}
}

func (f *forwardFlow) CloseFlow() {
	f.close(FlowCloseInterrupted)
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
	}
}

type ForwardDispatcher struct {
	epoch       time.Time
	handler     Handler
	writeback   ForwardWriteback
	logger      logger.Logger
	udpTimeout  time.Duration
	icmpTimeout time.Duration

	table     map[flowKey]*flowEntry
	lastSweep int64
	ports     map[Port]*portNAT
	natList   atomic.Pointer[[]*portNAT]

	activeNATs     []*portNAT
	writebackBatch [][]byte
	returnPath     forwardReturn

	segmentBuffers [][]byte
	segmentSizes   []int
}

func NewForwardDispatcher(handler Handler, writeback ForwardWriteback, logger logger.Logger, udpTimeout time.Duration, icmpTimeout time.Duration) *ForwardDispatcher {
	dispatcher := &ForwardDispatcher{
		epoch:       time.Now(),
		handler:     handler,
		writeback:   writeback,
		logger:      logger,
		udpTimeout:  udpTimeout,
		icmpTimeout: icmpTimeout,
		table:       make(map[flowKey]*flowEntry),
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

func (d *ForwardDispatcher) now() int64 {
	return int64(time.Since(d.epoch))
}

func (d *ForwardDispatcher) Close() {
	if d == nil {
		return
	}
	d.returnPath.closed.Store(true)
	for _, entry := range d.table {
		if entry.flow != nil {
			entry.flow.close(FlowCloseShutdown)
		}
	}
	for port, nat := range d.ports {
		if nat != nil {
			port.DetachReturn(&d.returnPath)
		}
	}
}

func (d *ForwardDispatcher) Dispatch(packet []byte) bool {
	if d == nil {
		return false
	}
	parsed, ok := parseForwardPacket(packet)
	if !ok || parsed.fragment || !parsed.hasFlow {
		return false
	}
	key := parsed.flowKey()
	now := d.now()
	entry, loaded := d.table[key]
	if loaded && d.entryExpired(entry, now) {
		d.removeEntry(key, entry, FlowCloseTimeout)
		loaded = false
	}
	if loaded {
		return d.handleHit(key, entry, &parsed, packet, now)
	}
	if parsed.protocol == uint8(header.TCPProtocolNumber) &&
		(parsed.tcpFlags&header.TCPFlagSyn == 0 || parsed.tcpFlags&header.TCPFlagAck != 0) {
		return false
	}
	return d.judgeAndInstall(key, &parsed, packet, now)
}

func (d *ForwardDispatcher) handleHit(key flowKey, entry *flowEntry, packet *forwardPacket, raw []byte, now int64) bool {
	switch entry.action {
	case ActionFlow:
		flow := entry.flow
		if flow.closed.Load() {
			d.tombstoneEntry(entry, now)
			return true
		}
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			if packet.tcpFlags&header.TCPFlagRst != 0 {
				d.forwardToPort(flow, packet, raw)
				flow.close(FlowCloseReset)
				d.tombstoneEntry(entry, now)
				return true
			}
			if packet.tcpFlags&header.TCPFlagFin != 0 {
				flow.finForward = true
			}
		}
		entry.idle = d.flowIdle(flow)
		entry.deadline = now + int64(entry.idle)
		d.forwardToPort(flow, packet, raw)
		return true
	case ActionAccept:
		entry.deadline = now + int64(entry.idle)
		if packet.protocol == uint8(header.TCPProtocolNumber) && packet.tcpFlags&header.TCPFlagRst != 0 {
			d.removeEntry(key, entry, FlowCloseReset)
		}
		return false
	case ActionReject:
		entry.deadline = now + int64(entry.idle)
		d.stageReject(packet)
		return true
	default:
		entry.deadline = now + int64(entry.idle)
		return true
	}
}

func (d *ForwardDispatcher) judgeAndInstall(key flowKey, packet *forwardPacket, raw []byte, now int64) bool {
	var firstPacket []byte
	if packet.protocol == uint8(header.UDPProtocolNumber) {
		firstPacket = header.UDP(packet.transport).Payload()
	}
	verdict := d.handler.JudgeFlow(packet.protocol, packet.source, packet.destination, firstPacket)
	switch verdict.Action {
	case ActionFlow:
		if verdict.Port != nil {
			flow, created := d.createFlow(packet, verdict)
			if created {
				entry := &flowEntry{action: ActionFlow, flow: flow, idle: d.flowIdle(flow)}
				entry.deadline = now + int64(entry.idle)
				d.insertEntry(key, entry, now)
				d.forwardToPort(flow, packet, raw)
				return true
			}
		}
		d.installSimple(key, ActionAccept, packet.protocol, now)
		return false
	case ActionReject:
		d.installSimple(key, ActionReject, packet.protocol, now)
		d.stageReject(packet)
		return true
	case ActionDrop:
		d.installSimple(key, ActionDrop, packet.protocol, now)
		return true
	default:
		d.installSimple(key, ActionAccept, packet.protocol, now)
		return false
	}
}

func (d *ForwardDispatcher) installSimple(key flowKey, action FlowAction, protocol uint8, now int64) {
	entry := &flowEntry{action: action, idle: d.idleTimeout(protocol, false)}
	entry.deadline = now + int64(entry.idle)
	d.insertEntry(key, entry, now)
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
	if flow.protocol == uint8(header.TCPProtocolNumber) && flow.finForward && flow.finReverse.Load() {
		return tcpClosingTimeout
	}
	established := flow.established.Load() && !flow.finForward && !flow.finReverse.Load()
	return d.idleTimeout(flow.protocol, established)
}

func (d *ForwardDispatcher) createFlow(packet *forwardPacket, verdict FlowVerdict) (*forwardFlow, bool) {
	var portAddress netip.Addr
	inet4Address, inet6Address := verdict.Port.PortAddresses()
	if packet.ipVersion == 6 {
		portAddress = inet6Address
	} else {
		portAddress = inet4Address
	}
	if !portAddress.IsValid() {
		return nil, false
	}
	effectiveMTU := verdict.Port.PortMTU()
	if packet.ipVersion == 6 && effectiveMTU != 0 && effectiveMTU < header.IPv6MinimumMTU {
		return nil, false
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
	nat := d.natFor(verdict.Port)
	if nat == nil {
		return nil, false
	}
	selector, reverseKey, allocated := nat.allocateSelector(packet.protocol, portAddress, serverAddress, serverPort, packet.source.Port())
	if !allocated {
		return nil, false
	}
	flow := &forwardFlow{
		nat:                      nat,
		reverseKey:               reverseKey,
		effectiveMTU:             effectiveMTU,
		protocol:                 packet.protocol,
		clientAddress:            packet.source.Addr(),
		clientSelector:           packet.source.Port(),
		clientDestinationAddress: clientDestinationAddress,
		clientDestinationPort:    clientDestinationPort,
		serverAddress:            serverAddress,
		dnatAddress:              serverAddress != clientDestinationAddress,
		dnatPort:                 serverPort != clientDestinationPort && !isICMP,
	}
	flow.forwardRule = rewriteRule{
		sourceAddress:     tcpip.AddrFromSlice(portAddress.AsSlice()),
		sourcePort:        selector,
		rewriteSourcePort: true,
	}
	if flow.dnatAddress {
		flow.forwardRule.destinationAddress = tcpip.AddrFromSlice(serverAddress.AsSlice())
	}
	if flow.dnatPort {
		flow.forwardRule.destinationPort = serverPort
		flow.forwardRule.rewriteDestinationPort = true
	}
	flow.reverseRule = rewriteRule{
		destinationAddress:     tcpip.AddrFromSlice(flow.clientAddress.AsSlice()),
		destinationPort:        flow.clientSelector,
		rewriteDestinationPort: true,
	}
	if flow.dnatAddress {
		flow.reverseRule.sourceAddress = tcpip.AddrFromSlice(clientDestinationAddress.AsSlice())
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
	return flow, true
}

func (d *ForwardDispatcher) natFor(port Port) *portNAT {
	nat, loaded := d.ports[port]
	if loaded {
		return nat
	}
	err := port.AttachReturn(&d.returnPath)
	if err != nil {
		d.logger.Trace(E.Cause(err, "attach return path"))
		d.ports[port] = nil
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
	return nat
}

func (d *ForwardDispatcher) forwardToPort(flow *forwardFlow, packet *forwardPacket, raw []byte) {
	if flow.effectiveMTU != 0 && uint32(len(raw)) > flow.effectiveMTU {
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			if flow.tracker != nil {
				flow.tracker.CountForward(len(raw))
			}
			d.rewriteForward(flow, packet)
			d.resegmentTCP(flow, packet, raw)
			return
		}
		if packet.ipVersion == 4 {
			ipHdr := packet.network.(header.IPv4)
			if ipHdr.Flags()&header.IPv4FlagDontFragment == 0 {
				if flow.tracker != nil {
					flow.tracker.CountForward(len(raw))
				}
				d.rewriteForward(flow, packet)
				fragments, ok := fragmentIPv4Packet(ipHdr, flow.effectiveMTU)
				if ok {
					for _, fragment := range fragments {
						d.stagePort(flow.nat, fragment)
					}
				}
				return
			}
			reply, ok := buildFragmentationNeeded(ipHdr, flow.effectiveMTU, d.writeback.ReturnHeadroom())
			if ok {
				d.writebackBatch = append(d.writebackBatch, reply)
			}
			return
		}
		reply, ok := buildPacketTooBig(packet.network.(header.IPv6), flow.effectiveMTU, d.writeback.ReturnHeadroom())
		if ok {
			d.writebackBatch = append(d.writebackBatch, reply)
		}
		return
	}
	if flow.tracker != nil {
		flow.tracker.CountForward(len(raw))
	}
	d.rewriteForward(flow, packet)
	d.stagePort(flow.nat, raw)
}

func (d *ForwardDispatcher) rewriteForward(flow *forwardFlow, packet *forwardPacket) {
	if packet.isTCPSyn() {
		applyRewriteRaw(packet, &flow.forwardRule)
		clampTCPMSS(packet, flow.effectiveMTU)
		recomputeChecksums(packet)
	} else {
		applyRewrite(packet, &flow.forwardRule)
	}
}

func (d *ForwardDispatcher) stagePort(nat *portNAT, packet []byte) {
	if len(nat.pending) == 0 {
		d.activeNATs = append(d.activeNATs, nat)
	}
	nat.pending = append(nat.pending, packet)
}

func (d *ForwardDispatcher) flushPort(nat *portNAT) {
	if len(nat.pending) == 0 {
		return
	}
	err := nat.port.WritePackets(nat.pending)
	if err != nil {
		d.logger.Trace(E.Cause(err, "forward packets"))
	}
	nat.pending = nat.pending[:0]
}

func (d *ForwardDispatcher) stageReject(packet *forwardPacket) {
	reply, ok := buildReject(packet, d.writeback.ReturnHeadroom())
	if ok {
		d.writebackBatch = append(d.writebackBatch, reply)
	}
}

func (d *ForwardDispatcher) Flush() {
	if d == nil {
		return
	}
	for _, nat := range d.activeNATs {
		d.flushPort(nat)
	}
	d.activeNATs = d.activeNATs[:0]
	if len(d.writebackBatch) > 0 {
		err := d.writeback.WriteReturnPackets(d.writebackBatch)
		if err != nil {
			d.logger.Trace(E.Cause(err, "write back packets"))
		}
		d.writebackBatch = d.writebackBatch[:0]
	}
	d.maybeSweep(d.now())
}

func (d *ForwardDispatcher) entryExpired(entry *flowEntry, now int64) bool {
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

func (d *ForwardDispatcher) tombstoneEntry(entry *flowEntry, now int64) {
	entry.action = ActionDrop
	entry.idle = flowTombstoneTimeout
	entry.deadline = now + int64(entry.idle)
}

func (d *ForwardDispatcher) removeEntry(key flowKey, entry *flowEntry, reason FlowCloseReason) {
	delete(d.table, key)
	if entry.flow != nil {
		if reason == FlowCloseTimeout && entry.flow.finForward && entry.flow.finReverse.Load() {
			reason = FlowCloseFinished
		}
		entry.flow.close(reason)
		entry.flow.nat.delete(entry.flow.reverseKey)
	}
}

func (d *ForwardDispatcher) insertEntry(key flowKey, entry *flowEntry, now int64) {
	if len(d.table) >= flowTableCapacity {
		d.evictEntries(now)
	}
	d.table[key] = entry
}

func (d *ForwardDispatcher) evictEntries(now int64) {
	var (
		freed     int
		visited   int
		oldestKey flowKey
		oldest    *flowEntry
	)
	for key, entry := range d.table {
		if d.entryExpired(entry, now) {
			d.removeEntry(key, entry, FlowCloseTimeout)
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
		d.removeEntry(oldestKey, oldest, FlowCloseEvicted)
	}
}

func (d *ForwardDispatcher) maybeSweep(now int64) {
	if now-d.lastSweep < int64(flowSweepInterval) {
		return
	}
	d.lastSweep = now
	visited := 0
	for key, entry := range d.table {
		if entry.action == ActionFlow && entry.flow.closed.Load() {
			d.tombstoneEntry(entry, now)
		} else if d.entryExpired(entry, now) {
			d.removeEntry(key, entry, FlowCloseTimeout)
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

func (r *forwardReturn) ReturnPackets(packets [][]byte) [][]byte {
	if r.closed.Load() {
		return packets
	}
	natListPtr := r.dispatcher.natList.Load()
	if natListPtr == nil {
		return packets
	}
	natList := *natListPtr
	headroom := r.dispatcher.writeback.ReturnHeadroom()
	unconsumed := packets[:0]
	var writeBatch [][]byte
	now := r.dispatcher.now()
	for _, raw := range packets {
		if len(raw) < headroom+header.IPv4MinimumSize {
			unconsumed = append(unconsumed, raw)
			continue
		}
		parsed, ok := parseForwardPacket(raw[headroom:])
		if !ok || parsed.fragment {
			unconsumed = append(unconsumed, raw)
			continue
		}
		if !parsed.hasFlow {
			if parsed.isICMPError() && returnICMPError(natList, &parsed) {
				writeBatch = append(writeBatch, raw)
			} else {
				unconsumed = append(unconsumed, raw)
			}
			continue
		}
		var flow *forwardFlow
		for _, nat := range natList {
			flow = nat.lookup(parsed.flowKey())
			if flow != nil {
				break
			}
		}
		if flow == nil {
			unconsumed = append(unconsumed, raw)
			continue
		}
		if flow.closed.Load() {
			continue
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
		writeBatch = append(writeBatch, raw)
	}
	if len(writeBatch) > 0 {
		err := r.dispatcher.writeback.WriteReturnPackets(writeBatch)
		if err != nil {
			r.dispatcher.logger.Trace(E.Cause(err, "write return packets"))
		}
	}
	return unconsumed
}

func returnICMPError(natList []*portNAT, parsed *forwardPacket) bool {
	inner, ok := parsed.icmpErrorInner()
	if !ok {
		return false
	}
	embedded, parsedInner := parseEmbedded(inner)
	if !parsedInner {
		return false
	}
	key := embedded.flowKey().reversed()
	var flow *forwardFlow
	for _, nat := range natList {
		flow = nat.lookup(key)
		if flow != nil {
			break
		}
	}
	if flow == nil || flow.closed.Load() {
		return false
	}
	rewriteEmbeddedSource(&embedded, tcpip.AddrFromSlice(flow.clientAddress.AsSlice()), flow.clientSelector, true)
	if flow.dnatAddress || flow.dnatPort {
		rewriteEmbeddedDestination(&embedded, tcpip.AddrFromSlice(flow.clientDestinationAddress.AsSlice()), flow.clientDestinationPort, flow.dnatPort)
	}
	parsed.network.SetDestinationAddr(flow.clientAddress)
	if parsed.network.SourceAddr() == flow.serverAddress {
		parsed.network.SetSourceAddr(flow.clientDestinationAddress)
	}
	recomputeChecksums(parsed)
	return true
}
