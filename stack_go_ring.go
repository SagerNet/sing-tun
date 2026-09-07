package tun

import (
	"slices"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
)

const (
	goSlabSize          = 32 << 10
	goReceiveSlotCount  = goReceiveCapacityMax/goSlabSize + 1
	goTransmitSlotCount = goTransmitCapacity/goSlabSize + 1
	goSlabShareMin      = 4 * goSlabSize
)

type goSlab [goSlabSize]byte

type goSlabPool struct {
	access   sync.Mutex
	free     []*goSlab
	inUse    atomic.Int32
	holders  atomic.Int32
	pressure func() MemoryPressure
}

func newGoSlabPool(pressure func() MemoryPressure) *goSlabPool {
	pool := &goSlabPool{
		free:     make([]*goSlab, 0, goSlabPoolLowWater),
		pressure: pressure,
	}
	for range goSlabPoolLowWater {
		pool.free = append(pool.free, goAllocateSlab())
	}
	return pool
}

func (p *goSlabPool) acquire() *goSlab {
	var slab *goSlab
	p.access.Lock()
	index := len(p.free) - 1
	if index >= 0 {
		slab = p.free[index]
		p.free[index] = nil
		p.free = p.free[:index]
	}
	p.access.Unlock()
	if slab == nil {
		slab = goAllocateSlab()
	}
	p.inUse.Add(1)
	return slab
}

func (p *goSlabPool) release(slab *goSlab) {
	if p.pressureLevel() != MemoryPressureNone {
		goFreeSlab(slab)
	} else {
		p.access.Lock()
		p.free = append(p.free, slab)
		p.access.Unlock()
	}
	p.inUse.Add(-1)
}

func (p *goSlabPool) trim() {
	p.access.Lock()
	defer p.access.Unlock()
	if len(p.free) <= goSlabPoolLowWater {
		return
	}
	target := goSlabPoolLowWater
	if p.pressureLevel() == MemoryPressureNone {
		target = max(goSlabPoolLowWater, len(p.free)/2)
	}
	for _, slab := range p.free[target:] {
		goFreeSlab(slab)
	}
	clear(p.free[target:])
	p.free = p.free[:target]
}

func (p *goSlabPool) pressureLevel() MemoryPressure {
	if p.pressure == nil {
		return MemoryPressureNone
	}
	return p.pressure()
}

func (p *goSlabPool) shareBytes() uint64 {
	var share int
	switch p.pressureLevel() {
	case MemoryPressureNone:
		return 0
	case MemoryPressureWarning:
		share = int(p.inUse.Load()) / max(int(p.holders.Load()), 1)
	}
	return uint64(max(share, goSlabShareMin/goSlabSize)) * goSlabSize
}

type goSlabHolder struct {
	held atomic.Int32
}

func (h *goSlabHolder) heldBytes() uint64 {
	return uint64(h.held.Load()) * goSlabSize
}

type goSlabChain struct {
	slots         []*goSlab
	pool          *goSlabPool
	holder        *goSlabHolder
	held          atomic.Int32
	releasedIndex uint64
}

func (c *goSlabChain) init(slots []*goSlab, pool *goSlabPool, holder *goSlabHolder) {
	c.slots = slots
	c.pool = pool
	c.holder = holder
}

func (c *goSlabChain) acquire() *goSlab {
	slab := c.pool.acquire()
	c.held.Add(1)
	if c.holder.held.Add(1) == 1 {
		c.pool.holders.Add(1)
	}
	return slab
}

func (c *goSlabChain) release(slab *goSlab) {
	c.held.Add(-1)
	if c.holder.held.Add(-1) == 0 {
		c.pool.holders.Add(-1)
	}
	c.pool.release(slab)
}

func (c *goSlabChain) heldBytes() uint64 {
	return uint64(c.held.Load()) * goSlabSize
}

func (c *goSlabChain) slotOf(offset uint64) int {
	return int((offset / goSlabSize) % uint64(len(c.slots)))
}

func (c *goSlabChain) reserve(offset uint64, length int) {
	first := offset / goSlabSize
	last := (offset + uint64(length) - 1) / goSlabSize
	for index := first; index <= last; index++ {
		slot := int(index % uint64(len(c.slots)))
		if c.slots[slot] != nil {
			continue
		}
		c.slots[slot] = c.acquire()
	}
}

func (c *goSlabChain) writeAt(offset uint64, data []byte) {
	for len(data) > 0 {
		slab := c.slots[c.slotOf(offset)]
		start := int(offset % goSlabSize)
		n := copy(slab[start:], data)
		data = data[n:]
		offset += uint64(n)
	}
}

func (c *goSlabChain) readAt(offset uint64, target []byte) {
	copied := 0
	for copied < len(target) {
		slab := c.slots[c.slotOf(offset)]
		start := int(offset % goSlabSize)
		n := copy(target[copied:], slab[start:])
		copied += n
		offset += uint64(n)
	}
}

func (c *goSlabChain) appendRuns(segments [][]byte, offset uint64, length int) [][]byte {
	for length > 0 {
		slab := c.slots[c.slotOf(offset)]
		start := int(offset % goSlabSize)
		n := min(goSlabSize-start, length)
		segments = append(segments, slab[start:start+n])
		offset += uint64(n)
		length -= n
	}
	return segments
}

func (c *goSlabChain) releaseBelow(offset uint64) {
	target := offset / goSlabSize
	for index := c.releasedIndex; index < target; index++ {
		slot := int(index % uint64(len(c.slots)))
		slab := c.slots[slot]
		if slab != nil {
			c.slots[slot] = nil
			c.release(slab)
		}
	}
	if target > c.releasedIndex {
		c.releasedIndex = target
	}
}

func (c *goSlabChain) releaseDrained(offset uint64) {
	c.releaseBelow(offset)
	slot := c.slotOf(offset)
	slab := c.slots[slot]
	if slab == nil {
		return
	}
	c.slots[slot] = nil
	c.release(slab)
}

func (c *goSlabChain) releaseAll() {
	for slot, slab := range c.slots {
		if slab == nil {
			continue
		}
		c.slots[slot] = nil
		c.release(slab)
	}
}

const goTransmitRunCapacity = 32

type goTransmitRun struct {
	start  uint64
	end    uint64
	buffer *buf.Buffer
	data   []byte
}

type goTransmitStore struct {
	access      sync.Mutex
	chain       goSlabChain
	runs        []goTransmitRun
	reserveTail uint64
}

func (s *goTransmitStore) init(slots []*goSlab, pool *goSlabPool, holder *goSlabHolder) {
	s.chain.init(slots, pool, holder)
	s.runs = s.runs[:0]
}

func (s *goTransmitStore) reserve(offset uint64, length int) {
	s.access.Lock()
	defer s.access.Unlock()
	s.chain.reserve(offset, length)
	s.reserveTail = offset + uint64(length)
}

func (s *goTransmitStore) shrinkReserve(tail uint64) {
	s.access.Lock()
	defer s.access.Unlock()
	if tail >= s.reserveTail {
		return
	}
	first := (tail + goSlabSize - 1) / goSlabSize
	last := (s.reserveTail - 1) / goSlabSize
	for index := first; index <= last; index++ {
		slot := int(index % uint64(len(s.chain.slots)))
		slab := s.chain.slots[slot]
		if slab == nil {
			continue
		}
		s.chain.slots[slot] = nil
		s.chain.release(slab)
	}
	s.reserveTail = tail
}

func (s *goTransmitStore) writeAt(offset uint64, data []byte) {
	for len(data) > 0 {
		s.access.Lock()
		slab := s.chain.slots[s.chain.slotOf(offset)]
		s.access.Unlock()
		start := int(offset % goSlabSize)
		n := copy(slab[start:], data)
		data = data[n:]
		offset += uint64(n)
	}
}

func (s *goTransmitStore) adopt(offset uint64, buffer *buf.Buffer) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if len(s.runs) == goTransmitRunCapacity {
		return false
	}
	data := buffer.Bytes()
	s.runs = append(s.runs, goTransmitRun{
		start:  offset,
		end:    offset + uint64(len(data)),
		buffer: buffer,
		data:   data,
	})
	return true
}

func (s *goTransmitStore) appendRuns(segments [][]byte, offset uint64, length int) [][]byte {
	s.access.Lock()
	defer s.access.Unlock()
	end := offset + uint64(length)
	for index := range s.runs {
		run := &s.runs[index]
		if run.end <= offset {
			continue
		}
		if run.start >= end {
			break
		}
		if run.start > offset {
			segments = s.chain.appendRuns(segments, offset, int(run.start-offset))
			offset = run.start
		}
		stop := min(run.end, end)
		segments = append(segments, run.data[offset-run.start:stop-run.start])
		offset = stop
		if offset == end {
			return segments
		}
	}
	if offset < end {
		segments = s.chain.appendRuns(segments, offset, int(end-offset))
	}
	return segments
}

func (s *goTransmitStore) leadingRun(offset uint64, length int) (*buf.Buffer, []byte, bool) {
	s.access.Lock()
	defer s.access.Unlock()
	for index := range s.runs {
		run := &s.runs[index]
		if run.end <= offset {
			continue
		}
		if run.start != offset || run.end < offset+uint64(length) {
			return nil, nil, false
		}
		return run.buffer, run.data[:length], true
	}
	return nil, nil, false
}

func (s *goTransmitStore) releaseBelow(offset uint64) {
	s.access.Lock()
	defer s.access.Unlock()
	s.chain.releaseBelow(offset)
	released := 0
	for released < len(s.runs) && s.runs[released].end <= offset {
		s.runs[released].buffer.Release()
		released++
	}
	if released > 0 {
		remaining := copy(s.runs, s.runs[released:])
		clear(s.runs[remaining:])
		s.runs = s.runs[:remaining]
	}
}

func (s *goTransmitStore) releaseDrained(offset uint64) {
	s.access.Lock()
	defer s.access.Unlock()
	if len(s.runs) > 0 || s.reserveTail > offset {
		return
	}
	s.chain.releaseDrained(offset)
}

func (s *goTransmitStore) releaseAll() {
	s.access.Lock()
	defer s.access.Unlock()
	s.chain.releaseAll()
	for index := range s.runs {
		s.runs[index].buffer.Release()
	}
	clear(s.runs)
	s.runs = s.runs[:0]
}

const (
	goDescriptorRetransmitted uint8 = 1 << iota
	goDescriptorNoSample
	goDescriptorSacked
	goDescriptorDropped
	goDescriptorAmend
)

type goSentDescriptor struct {
	endOffset uint64
	sentAt    int32
	flags     uint8
	_         [3]byte
}

type goDescriptorRing struct {
	entries       []goSentDescriptor
	head          atomic.Uint32
	tail          atomic.Uint32
	pending       goSentDescriptor
	pendingActive bool
}

type goDescriptorPool struct {
	access sync.Mutex
	free   [][]goSentDescriptor
}

func (p *goDescriptorPool) acquire() []goSentDescriptor {
	p.access.Lock()
	index := len(p.free) - 1
	if index >= 0 {
		entries := p.free[index]
		p.free[index] = nil
		p.free = p.free[:index]
		p.access.Unlock()
		return entries
	}
	p.access.Unlock()
	return make([]goSentDescriptor, goDescriptorRingCapacity)
}

func (p *goDescriptorPool) release(entries []goSentDescriptor) {
	p.access.Lock()
	p.free = append(p.free, entries)
	p.access.Unlock()
}

func (p *goDescriptorPool) trim() {
	p.access.Lock()
	defer p.access.Unlock()
	if len(p.free) <= goDescriptorPoolLowWater {
		return
	}
	target := max(goDescriptorPoolLowWater, len(p.free)/2)
	clear(p.free[target:])
	p.free = p.free[:target]
}

func (r *goDescriptorRing) reset(entries []goSentDescriptor) {
	r.entries = entries
	r.head.Store(0)
	r.tail.Store(0)
	r.pending = goSentDescriptor{}
	r.pendingActive = false
}

func (r *goDescriptorRing) push(endOffset uint64, sentAt int32, flags uint8) {
	if flags&goDescriptorAmend != 0 {
		r.pushAmendment(endOffset, sentAt, flags)
		return
	}
	if r.pendingActive {
		r.pending.endOffset = endOffset
		r.pending.sentAt = sentAt
		r.pending.flags |= flags
	} else {
		r.pending = goSentDescriptor{endOffset: endOffset, sentAt: sentAt, flags: flags}
		r.pendingActive = true
	}
	if r.store(r.pending) {
		r.pendingActive = false
	}
}

func (r *goDescriptorRing) pushAmendment(endOffset uint64, length int32, flags uint8) {
	if r.pendingActive {
		if !r.store(r.pending) {
			return
		}
		r.pendingActive = false
	}
	r.store(goSentDescriptor{endOffset: endOffset, sentAt: length, flags: flags})
}

func (r *goDescriptorRing) store(entry goSentDescriptor) bool {
	tail := r.tail.Load()
	if tail-r.head.Load() >= uint32(len(r.entries)) {
		return false
	}
	r.entries[tail%uint32(len(r.entries))] = entry
	r.tail.Store(tail + 1)
	return true
}

func (r *goDescriptorRing) at(index uint32) *goSentDescriptor {
	return &r.entries[index%uint32(len(r.entries))]
}

type goScoreboard struct {
	entries []goSentDescriptor
}

func (s *goScoreboard) drain(ring *goDescriptorRing, unacked uint64) {
	head := ring.head.Load()
	tail := ring.tail.Load()
	for head < tail {
		entry := *ring.at(head)
		head++
		if entry.flags&goDescriptorAmend != 0 {
			s.amend(entry.endOffset-uint64(entry.sentAt), entry.endOffset, entry.flags&^goDescriptorAmend)
			continue
		}
		if entry.endOffset > unacked {
			s.entries = append(s.entries, entry)
		}
	}
	ring.head.Store(head)
}

func (s *goScoreboard) amend(start uint64, end uint64, flags uint8) {
	for index := range s.entries {
		entry := &s.entries[index]
		if entry.endOffset > start && entry.endOffset <= end {
			entry.flags |= flags
		}
	}
}

func (s *goScoreboard) advance(acked uint64) {
	dropped := 0
	for dropped < len(s.entries) && s.entries[dropped].endOffset <= acked {
		dropped++
	}
	if dropped == 0 {
		return
	}
	remaining := copy(s.entries, s.entries[dropped:])
	s.entries = s.entries[:remaining]
}

func (s *goScoreboard) startOf(index int, unacked uint64) uint64 {
	if index == 0 {
		return unacked
	}
	return s.entries[index-1].endOffset
}

func (s *goScoreboard) split(index int, offset uint64) {
	entry := s.entries[index]
	if entry.endOffset == offset {
		return
	}
	s.entries = append(s.entries, goSentDescriptor{})
	copy(s.entries[index+1:], s.entries[index:len(s.entries)-1])
	s.entries[index].endOffset = offset
}

func (s *goScoreboard) reset() {
	s.entries = s.entries[:0]
}

const goMaxSackBlocks = 4

const goMaxSackBlocksSent = 3

type goSackBlock struct {
	start uint64
	end   uint64
}

const goMaxOOORanges = 32

type goRange struct {
	start uint64
	end   uint64
	fin   bool
}

type goRangeSet struct {
	ranges [goMaxOOORanges]goRange
	count  int
	recent [3]uint64
}

func (s *goRangeSet) reset() {
	s.count = 0
	s.recent = [3]uint64{}
}

func (s *goRangeSet) insert(start uint64, end uint64, fin bool) bool {
	index := 0
	for index < s.count && s.ranges[index].end < start {
		index++
	}
	if index == s.count || s.ranges[index].start > end {
		if s.count == goMaxOOORanges {
			return false
		}
		copy(s.ranges[index+1:s.count+1], s.ranges[index:s.count])
		s.ranges[index] = goRange{start: start, end: end, fin: fin}
		s.count++
		s.touch(start)
		return true
	}
	mergedStart := min(start, s.ranges[index].start)
	mergedEnd := end
	mergedFin := fin
	mergeEnd := index
	for mergeEnd < s.count && s.ranges[mergeEnd].start <= end {
		mergedEnd = max(mergedEnd, s.ranges[mergeEnd].end)
		mergedFin = mergedFin || s.ranges[mergeEnd].fin
		mergeEnd++
	}
	s.ranges[index] = goRange{start: mergedStart, end: mergedEnd, fin: mergedFin}
	copy(s.ranges[index+1:], s.ranges[mergeEnd:s.count])
	s.count -= mergeEnd - index - 1
	s.touch(mergedStart)
	return true
}

func (s *goRangeSet) touch(start uint64) {
	if s.recent[0] == start {
		return
	}
	s.recent[2] = s.recent[1]
	s.recent[1] = s.recent[0]
	s.recent[0] = start
}

func (s *goRangeSet) first() (goRange, bool) {
	if s.count == 0 {
		return goRange{}, false
	}
	return s.ranges[0], true
}

func (s *goRangeSet) removeBelow(offset uint64) {
	kept := 0
	for index := range s.count {
		if s.ranges[index].end <= offset {
			continue
		}
		s.ranges[kept] = s.ranges[index]
		if s.ranges[kept].start < offset {
			s.ranges[kept].start = offset
		}
		kept++
	}
	s.count = kept
}

func (s *goRangeSet) covers(start uint64, end uint64) bool {
	for index := range s.count {
		if s.ranges[index].start <= start && end <= s.ranges[index].end {
			return true
		}
	}
	return false
}

func (s *goRangeSet) bytes() uint64 {
	var total uint64
	for index := range s.count {
		total += s.ranges[index].end - s.ranges[index].start
	}
	return total
}

func (s *goRangeSet) blocks(out *[goMaxSackBlocks]goSackBlock, base int) int {
	emitted := base
	for _, start := range s.recent {
		if emitted == goMaxSackBlocksSent {
			break
		}
		if start == 0 {
			continue
		}
		found := slices.IndexFunc(s.ranges[:s.count], func(candidate goRange) bool { return candidate.start == start })
		if found < 0 {
			continue
		}
		out[emitted] = goSackBlock{start: s.ranges[found].start, end: s.ranges[found].end}
		emitted++
	}
	for index := 0; index < s.count && emitted < goMaxSackBlocksSent; index++ {
		start := s.ranges[index].start
		if slices.ContainsFunc(out[base:emitted], func(block goSackBlock) bool { return block.start == start }) {
			continue
		}
		out[emitted] = goSackBlock{start: s.ranges[index].start, end: s.ranges[index].end}
		emitted++
	}
	return emitted
}
