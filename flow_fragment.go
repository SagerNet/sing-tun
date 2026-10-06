package tun

import (
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

const (
	fragmentTimeout       = 30 * time.Second
	fragmentSweepInterval = time.Second
	fragmentTableCapacity = 4096
)

type fragmentKey struct {
	source      netip.Addr
	destination netip.Addr
	protocol    uint8
	id          uint32
}

type fragmentEntry struct {
	flow     *forwardFlow
	rule     *rewriteRule
	deadline int64
	received int
	total    int
}

type fragmentTable struct {
	access    sync.Mutex
	entries   map[fragmentKey]*fragmentEntry
	lastSweep int64
}

func (t *fragmentTable) insert(key fragmentKey, flow *forwardFlow, rule *rewriteRule, received int, now int64) {
	t.access.Lock()
	defer t.access.Unlock()
	if len(t.entries) >= fragmentTableCapacity {
		if now-t.lastSweep < int64(fragmentSweepInterval) {
			return
		}
		t.lastSweep = now
		for existingKey, entry := range t.entries {
			if entry.deadline < now {
				delete(t.entries, existingKey)
			}
		}
		if len(t.entries) >= fragmentTableCapacity {
			return
		}
	}
	t.entries[key] = &fragmentEntry{flow: flow, rule: rule, deadline: now + int64(fragmentTimeout), received: received, total: -1}
}

func (t *fragmentTable) remove(key fragmentKey) {
	t.access.Lock()
	delete(t.entries, key)
	t.access.Unlock()
}

func (t *fragmentTable) lookup(key fragmentKey, info fragmentInfo, now int64) *fragmentEntry {
	t.access.Lock()
	defer t.access.Unlock()
	entry := t.entries[key]
	if entry == nil {
		return nil
	}
	if entry.deadline < now {
		delete(t.entries, key)
		return nil
	}
	entry.received += len(info.payload)
	if !info.more {
		entry.total = info.offset + len(info.payload)
	}
	if entry.total >= 0 && entry.received >= entry.total {
		delete(t.entries, key)
	}
	return entry
}

type fragmentInfo struct {
	protocol uint8
	id       uint32
	offset   int
	more     bool
	payload  []byte
}

func parseFragment(parsed *forwardPacket) (fragmentInfo, bool) {
	if parsed.ipVersion == 4 {
		ipHdr := header.IPv4(parsed.network)
		return fragmentInfo{
			protocol: parsed.protocol,
			id:       uint32(ipHdr.ID()),
			offset:   int(ipHdr.FragmentOffset()),
			more:     ipHdr.More(),
			payload:  ipHdr.Payload(),
		}, true
	}
	fragmentHeader := header.IPv6Fragment(header.IPv6(parsed.network).Payload())
	if !fragmentHeader.IsValid() {
		return fragmentInfo{}, false
	}
	return fragmentInfo{
		protocol: fragmentHeader.NextHeader(),
		id:       fragmentHeader.ID(),
		offset:   int(fragmentHeader.FragmentOffset()) * 8,
		more:     fragmentHeader.More(),
		payload:  fragmentHeader.Payload(),
	}, true
}

func (r *portReturn) classifyFragment(parsed *forwardPacket, size int, now int64) (returnDecision, ForwardWriteback) {
	info, ok := parseFragment(parsed)
	if !ok {
		return returnPass, nil
	}
	key := fragmentKey{
		source:      parsed.source.Addr(),
		destination: parsed.destination.Addr(),
		protocol:    info.protocol,
		id:          info.id,
	}
	if info.offset == 0 {
		parsed.protocol = info.protocol
		parsed.parseTransport(info.payload)
		var (
			flow *forwardFlow
			rule *rewriteRule
		)
		if parsed.hasFlow {
			flow, rule = r.matchReverse(parsed)
		}
		if flow == nil {
			r.fragments.remove(key)
			return returnPass, nil
		}
		if info.more {
			r.fragments.insert(key, flow, rule, len(info.payload), now)
		}
		if flow.closed.Load() {
			return returnDrop, nil
		}
		if flow.tracker != nil {
			flow.tracker.CountReverse(size)
		}
		flow.observeReverse(parsed, now)
		applyRewrite(parsed, rule)
		return returnWrite, flow.owner.writeback
	}
	entry := r.fragments.lookup(key, info, now)
	if entry == nil {
		return returnPass, nil
	}
	if entry.flow.closed.Load() {
		return returnDrop, nil
	}
	if entry.flow.tracker != nil {
		entry.flow.tracker.CountReverse(size)
	}
	entry.flow.lastReverse.Store(now)
	applyRewriteAddresses(parsed, entry.rule)
	return returnWrite, entry.flow.owner.writeback
}
