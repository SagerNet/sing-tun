package tun

import (
	"net/netip"
	"runtime"
	"slices"
	"sync"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/contrab/maphash"
)

const (
	natSelectorMin = 49152
	natSelectorMax = 65535
)

var (
	natDefaultRanges = []SelectorRange{{Start: natSelectorMin, Count: natSelectorMax - natSelectorMin + 1}}

	portNATAccess sync.Mutex
	portNATs      = make(map[Port]*portNAT)
)

type portNAT struct {
	port       Port
	references int
	hasher     maphash.Hasher[flowKey]
	shardMask  uint32
	shards     []natShard

	access         sync.RWMutex
	selectors      map[natSelectorKey]*natSelector
	mappings       map[natMappingKey]*natMapping
	counter        uint32
	mappingCounter uint32
}

type natShard struct {
	access sync.RWMutex
	flows  map[flowKey]*forwardFlow
}

type natSelectorKey struct {
	protocol    uint8
	portAddress netip.Addr
	selector    uint16
}

type natSelector struct {
	references uint32
	mapping    *natMapping
}

type natMappingKey struct {
	dispatcher  *ForwardDispatcher
	portAddress netip.Addr
	client      netip.AddrPort
	server      netip.AddrPort
}

type natMapping struct {
	key         natMappingKey
	selector    uint16
	reverseRule rewriteRule
	flows       []*forwardFlow
	anchor      *forwardFlow
}

type natReservation struct {
	selectorKey natSelectorKey
	reverseKey  flowKey
	mapping     *natMapping
}

func acquirePortNAT(port Port) *portNAT {
	portNATAccess.Lock()
	defer portNATAccess.Unlock()
	nat, loaded := portNATs[port]
	if !loaded {
		shardCount := 1
		for shardCount < runtime.GOMAXPROCS(0) {
			shardCount <<= 1
		}
		nat = &portNAT{
			port:      port,
			hasher:    maphash.NewHasher[flowKey](),
			shardMask: uint32(shardCount - 1),
			shards:    make([]natShard, shardCount),
			selectors: make(map[natSelectorKey]*natSelector),
			mappings:  make(map[natMappingKey]*natMapping),
		}
		for i := range nat.shards {
			nat.shards[i].flows = make(map[flowKey]*forwardFlow)
		}
		portNATs[port] = nat
	}
	nat.references++
	return nat
}

func releasePortNAT(nat *portNAT) {
	portNATAccess.Lock()
	defer portNATAccess.Unlock()
	nat.references--
	if nat.references == 0 {
		delete(portNATs, nat.port)
	}
}

func (n *portNAT) shard(key flowKey) *natShard {
	return &n.shards[n.hasher.Hash32(key)&n.shardMask]
}

func (n *portNAT) lookup(key flowKey) *forwardFlow {
	shard := n.shard(key)
	shard.access.RLock()
	flow := shard.flows[key]
	shard.access.RUnlock()
	return flow
}

func (n *portNAT) insertIfAbsent(key flowKey, flow *forwardFlow) bool {
	shard := n.shard(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	_, occupied := shard.flows[key]
	if occupied {
		return false
	}
	shard.flows[key] = flow
	return true
}

func (n *portNAT) replace(key flowKey, flow *forwardFlow) {
	shard := n.shard(key)
	shard.access.Lock()
	shard.flows[key] = flow
	shard.access.Unlock()
}

func (n *portNAT) delete(key flowKey, flow *forwardFlow) {
	shard := n.shard(key)
	shard.access.Lock()
	if shard.flows[key] == flow {
		delete(shard.flows, key)
	}
	shard.access.Unlock()
}

func (n *portNAT) reverseKeyFor(protocol uint8, portAddress netip.Addr, server netip.AddrPort, selector uint16) flowKey {
	if isICMPProtocol(protocol) {
		return flowKey{
			protocol:    protocol,
			source:      netip.AddrPortFrom(server.Addr(), selector),
			destination: netip.AddrPortFrom(portAddress, selector),
		}
	}
	return flowKey{
		protocol:    protocol,
		source:      server,
		destination: netip.AddrPortFrom(portAddress, selector),
	}
}

func (n *portNAT) selectorRanges(protocol uint8) (ranges []SelectorRange, ranged bool) {
	if isICMPProtocol(protocol) {
		return natDefaultRanges, false
	}
	rangedPort, isRanged := portCapability[PortWithSelectorRange](n.port)
	if !isRanged {
		return natDefaultRanges, false
	}
	return rangedPort.PortSelectorRanges(protocol), true
}

func withinRanges(ranges []SelectorRange, selector uint16) bool {
	return slices.ContainsFunc(ranges, func(selectorRange SelectorRange) bool {
		return selector >= selectorRange.Start && selector-selectorRange.Start < selectorRange.Count
	})
}

func allocateSelector(ranges []SelectorRange, counter *uint32, claim func(candidate uint16) bool) bool {
	var total uint32
	for _, selectorRange := range ranges {
		total += uint32(selectorRange.Count)
	}
	for range total {
		*counter++
		index := *counter % total
		for _, selectorRange := range ranges {
			if index < uint32(selectorRange.Count) {
				if claim(selectorRange.Start + uint16(index)) {
					return true
				}
				break
			}
			index -= uint32(selectorRange.Count)
		}
	}
	return false
}

func (n *portNAT) reserve(dispatcher *ForwardDispatcher, protocol uint8, portAddress netip.Addr, client netip.AddrPort, server netip.AddrPort) (natReservation, bool) {
	reservation := natReservation{
		selectorKey: natSelectorKey{protocol: protocol, portAddress: portAddress},
	}
	isUDP := protocol == uint8(header.UDPProtocolNumber)
	var mappingKey natMappingKey
	if isUDP {
		mappingKey = natMappingKey{
			dispatcher:  dispatcher,
			portAddress: portAddress,
			client:      client,
		}
		switch dispatcher.udpMapping {
		case NATMappingAddressDependent:
			mappingKey.server = netip.AddrPortFrom(server.Addr(), 0)
		case NATMappingAddressAndPortDependent:
			mappingKey.server = server
		}
	}
	n.access.Lock()
	defer n.access.Unlock()
	var existingMapping *natMapping
	if isUDP {
		existingMapping = n.mappings[mappingKey]
		if existingMapping != nil {
			reverseKey := n.reverseKeyFor(protocol, portAddress, server, existingMapping.selector)
			if n.insertIfAbsent(reverseKey, nil) {
				reservation.selectorKey.selector = existingMapping.selector
				reservation.reverseKey = reverseKey
				reservation.mapping = existingMapping
				n.selectors[reservation.selectorKey].references++
				return reservation, true
			}
		}
	}
	ranges, ranged := n.selectorRanges(protocol)
	reserver, hasReserver := portCapability[PortWithSelectorReservation](n.port)
	claim := func(candidate uint16) bool {
		selectorKey := natSelectorKey{protocol: protocol, portAddress: portAddress, selector: candidate}
		reverseKey := n.reverseKeyFor(protocol, portAddress, server, candidate)
		entry := n.selectors[selectorKey]
		if entry != nil {
			if isUDP || !n.insertIfAbsent(reverseKey, nil) {
				return false
			}
			entry.references++
		} else {
			address := netip.AddrPortFrom(portAddress, candidate)
			if hasReserver && !reserver.ReserveSelector(protocol, address) {
				return false
			}
			if !n.insertIfAbsent(reverseKey, nil) {
				if hasReserver {
					reserver.ReleaseSelector(protocol, address)
				}
				return false
			}
			n.selectors[selectorKey] = &natSelector{references: 1}
		}
		reservation.selectorKey = selectorKey
		reservation.reverseKey = reverseKey
		return true
	}
	claimed := client.Port() != 0 && (!ranged || withinRanges(ranges, client.Port())) && claim(client.Port())
	if !claimed {
		counter := &n.counter
		if isUDP {
			counter = &n.mappingCounter
		}
		claimed = allocateSelector(ranges, counter, claim)
	}
	if !claimed {
		return reservation, false
	}
	if isUDP && existingMapping == nil {
		reservation.mapping = &natMapping{
			key:      mappingKey,
			selector: reservation.selectorKey.selector,
			reverseRule: rewriteRule{
				destinationAddress:     addrToTCPIP(client.Addr()),
				destinationPort:        client.Port(),
				rewriteDestinationPort: true,
			},
		}
		n.mappings[mappingKey] = reservation.mapping
		n.selectors[reservation.selectorKey].mapping = reservation.mapping
	}
	return reservation, true
}

func (n *portNAT) publish(flow *forwardFlow, reservation natReservation) {
	flow.selectorKey = reservation.selectorKey
	flow.reverseKey = reservation.reverseKey
	flow.forwardRule.sourcePort = reservation.selectorKey.selector
	mapping := reservation.mapping
	if mapping == nil {
		n.replace(reservation.reverseKey, flow)
		return
	}
	n.access.Lock()
	defer n.access.Unlock()
	flow.mapping = mapping
	mapping.flows = append(mapping.flows, flow)
	if mapping.anchor == nil || mapping.anchor.closed.Load() {
		mapping.anchor = flow
	}
	n.replace(reservation.reverseKey, flow)
}

func (n *portNAT) release(flow *forwardFlow) {
	n.delete(flow.reverseKey, flow)
	n.access.Lock()
	defer n.access.Unlock()
	entry := n.selectors[flow.selectorKey]
	mapping := flow.mapping
	if mapping != nil {
		mapping.flows = slices.DeleteFunc(mapping.flows, func(owned *forwardFlow) bool { return owned == flow })
		if mapping.anchor == flow {
			mapping.anchor = mapping.liveFlowLocked()
		}
	}
	entry.references--
	if entry.references > 0 {
		return
	}
	delete(n.selectors, flow.selectorKey)
	if mapping != nil {
		delete(n.mappings, mapping.key)
	}
	reserver, hasReserver := portCapability[PortWithSelectorReservation](n.port)
	if hasReserver {
		reserver.ReleaseSelector(flow.protocol, netip.AddrPortFrom(flow.selectorKey.portAddress, flow.selectorKey.selector))
	}
}

func (m *natMapping) liveFlowLocked() *forwardFlow {
	var fallback *forwardFlow
	for _, flow := range m.flows {
		if !flow.closed.Load() {
			return flow
		}
		fallback = flow
	}
	return fallback
}

func (n *portNAT) lookupMapping(portAddress netip.Addr, selector uint16, peer netip.Addr) (*natMapping, *forwardFlow) {
	n.access.RLock()
	defer n.access.RUnlock()
	entry := n.selectors[natSelectorKey{protocol: uint8(header.UDPProtocolNumber), portAddress: portAddress, selector: selector}]
	if entry == nil || entry.mapping == nil {
		return nil, nil
	}
	mapping := entry.mapping
	switch mapping.key.dispatcher.udpFiltering {
	case NATFilteringAddressAndPortDependent:
		return nil, nil
	case NATFilteringAddressDependent:
		if !slices.ContainsFunc(mapping.flows, func(flow *forwardFlow) bool { return flow.serverAddress == peer }) {
			return nil, nil
		}
	}
	flow := mapping.anchor
	if flow == nil || flow.closed.Load() {
		flow = mapping.liveFlowLocked()
	}
	if flow == nil {
		return nil, nil
	}
	return mapping, flow
}
