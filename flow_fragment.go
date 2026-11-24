package tun

import (
	"bytes"
	"net/netip"
	"time"
)

const (
	fragmentTimeout       = 30 * time.Second
	fragmentSweepInterval = time.Second
	fragmentTableCapacity = 4096
	fragmentHoldPerEntry  = 8
	fragmentHoldCapacity  = 64
)

type fragmentKey struct {
	source      netip.Addr
	destination netip.Addr
	protocol    uint8
	id          uint32
}

type fragmentInfo struct {
	id     uint32
	offset int
	more   bool
	length int
}

type fragmentEntry struct {
	flow     *forwardFlow
	rule     *rewriteRule
	pending  bool
	held     []heldPacket
	deadline int64
	total    int
	ranges   goReassemblyRanges
}

func (e *fragmentEntry) observe(info fragmentInfo) bool {
	end := info.offset + info.length
	if !info.more {
		e.total = end
	}
	e.ranges.merge(info.offset, end)
	return e.ranges.complete(e.total)
}

type fragmentTable struct {
	entries   map[fragmentKey]*fragmentEntry
	held      int
	lastSweep int64
}

func (t *fragmentTable) load(key fragmentKey, now int64) *fragmentEntry {
	entry := t.entries[key]
	if entry != nil && entry.deadline < now {
		t.remove(key, entry)
		return nil
	}
	return entry
}

func (t *fragmentTable) create(key fragmentKey, now int64) *fragmentEntry {
	if t.entries == nil {
		t.entries = make(map[fragmentKey]*fragmentEntry)
	}
	if len(t.entries) >= fragmentTableCapacity {
		if now-t.lastSweep < int64(fragmentSweepInterval) {
			return nil
		}
		t.lastSweep = now
		for existingKey, entry := range t.entries {
			if entry.deadline < now {
				t.remove(existingKey, entry)
			}
		}
		if len(t.entries) >= fragmentTableCapacity {
			return nil
		}
	}
	entry := &fragmentEntry{deadline: now + int64(fragmentTimeout), total: -1}
	t.entries[key] = entry
	return entry
}

func (t *fragmentTable) remove(key fragmentKey, entry *fragmentEntry) {
	delete(t.entries, key)
	t.held -= len(entry.held)
}

func (t *fragmentTable) reset() {
	clear(t.entries)
	t.held = 0
}

func (t *fragmentTable) pend(key fragmentKey, info fragmentInfo, now int64) {
	if !info.more {
		return
	}
	entry := t.load(key, now)
	if entry == nil {
		entry = t.create(key, now)
		if entry == nil {
			return
		}
	}
	entry.pending = true
	entry.observe(info)
}

func (t *fragmentTable) resolve(key fragmentKey, info fragmentInfo, flow *forwardFlow, rule *rewriteRule, now int64) []heldPacket {
	entry := t.load(key, now)
	if flow == nil {
		if entry == nil {
			return nil
		}
		t.remove(key, entry)
		return entry.held
	}
	if entry == nil {
		if !info.more {
			return nil
		}
		entry = t.create(key, now)
		if entry == nil {
			return nil
		}
	}
	held := entry.held
	t.held -= len(held)
	entry.held = nil
	entry.pending = false
	entry.flow = flow
	entry.rule = rule
	if entry.observe(info) {
		delete(t.entries, key)
	}
	return held
}

func (t *fragmentTable) lookup(key fragmentKey, info fragmentInfo, now int64) *fragmentEntry {
	entry := t.load(key, now)
	if entry == nil {
		return nil
	}
	if entry.observe(info) && !entry.pending {
		delete(t.entries, key)
	}
	return entry
}

func (t *fragmentTable) hold(entry *fragmentEntry, packet []byte, meta *ForwardFrameMeta) bool {
	if len(entry.held) >= fragmentHoldPerEntry || t.held >= fragmentHoldCapacity {
		return false
	}
	held := heldPacket{packet: bytes.Clone(packet)}
	if meta != nil {
		held.meta = *meta
	}
	entry.held = append(entry.held, held)
	t.held++
	return true
}

func (r *portReturn) classifyFragment(parsed *forwardPacket, now int64) (returnDecision, *forwardFlow, *rewriteRule) {
	key := parsed.fragmentKey()
	if parsed.fragmentInfo.offset == 0 {
		var (
			flow *forwardFlow
			rule *rewriteRule
		)
		if parsed.hasFlow {
			flow, rule = r.matchReverse(parsed)
		}
		r.fragmentAccess.Lock()
		r.fragments.resolve(key, parsed.fragmentInfo, flow, rule, now)
		r.fragmentAccess.Unlock()
		if flow == nil {
			return returnPass, nil, nil
		}
		if flow.closed.Load() {
			return returnDrop, nil, nil
		}
		flow.observeReverse(parsed, now)
		return returnWrite, flow, rule
	}
	var (
		flow *forwardFlow
		rule *rewriteRule
	)
	r.fragmentAccess.Lock()
	entry := r.fragments.lookup(key, parsed.fragmentInfo, now)
	if entry != nil {
		flow, rule = entry.flow, entry.rule
	}
	r.fragmentAccess.Unlock()
	if flow == nil {
		return returnPass, nil, nil
	}
	if flow.closed.Load() {
		return returnDrop, nil, nil
	}
	flow.lastReverse.Store(now)
	return returnWrite, flow, rule
}
