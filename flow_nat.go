package tun

import (
	"net/netip"
	"runtime"
	"sync"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/contrab/maphash"
)

const (
	natSelectorMin = 49152
	natSelectorMax = 65535
)

type portNAT struct {
	port      Port
	hasher    maphash.Hasher[flowKey]
	shardMask uint32
	shards    []natShard

	counter uint32
	pending [][]byte
}

type natShard struct {
	access sync.RWMutex
	flows  map[flowKey]*forwardFlow
}

func newPortNAT(port Port) *portNAT {
	shardCount := 1
	for shardCount < runtime.GOMAXPROCS(0) {
		shardCount <<= 1
	}
	nat := &portNAT{
		port:      port,
		hasher:    maphash.NewHasher[flowKey](),
		shardMask: uint32(shardCount - 1),
		shards:    make([]natShard, shardCount),
	}
	for i := range nat.shards {
		nat.shards[i].flows = make(map[flowKey]*forwardFlow)
	}
	return nat
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

func (n *portNAT) insert(key flowKey, flow *forwardFlow) {
	shard := n.shard(key)
	shard.access.Lock()
	shard.flows[key] = flow
	shard.access.Unlock()
}

func (n *portNAT) delete(key flowKey) {
	shard := n.shard(key)
	shard.access.Lock()
	delete(shard.flows, key)
	shard.access.Unlock()
}

func (n *portNAT) reverseKeyFor(protocol uint8, portAddress, serverAddress netip.Addr, serverPort, selector uint16) flowKey {
	if protocol == uint8(header.ICMPv4ProtocolNumber) || protocol == uint8(header.ICMPv6ProtocolNumber) {
		return flowKey{
			protocol:    protocol,
			source:      netip.AddrPortFrom(serverAddress, selector),
			destination: netip.AddrPortFrom(portAddress, selector),
		}
	}
	return flowKey{
		protocol:    protocol,
		source:      netip.AddrPortFrom(serverAddress, serverPort),
		destination: netip.AddrPortFrom(portAddress, selector),
	}
}

func (n *portNAT) allocateSelector(protocol uint8, portAddress, serverAddress netip.Addr, serverPort, clientSelector uint16) (uint16, flowKey, bool) {
	if clientSelector != 0 {
		key := n.reverseKeyFor(protocol, portAddress, serverAddress, serverPort, clientSelector)
		if n.lookup(key) == nil {
			return clientSelector, key, true
		}
	}
	for range natSelectorMax - natSelectorMin + 1 {
		n.counter++
		candidate := uint16(natSelectorMin + n.counter%(natSelectorMax-natSelectorMin+1))
		key := n.reverseKeyFor(protocol, portAddress, serverAddress, serverPort, candidate)
		if n.lookup(key) == nil {
			return candidate, key, true
		}
	}
	return 0, flowKey{}, false
}
