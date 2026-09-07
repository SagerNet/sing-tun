package tun

import (
	"slices"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
)

const (
	goSlabSize     = 32 << 10
	goSlabShareMin = 4 * goSlabSize
)

type goSlab [goSlabSize]byte

type goSlabPool struct {
	access   sync.Mutex
	free     []*goSlab
	inUse    atomic.Int32
	holders  atomic.Int32
	pressure func() MemoryPressure
	lowWater int
	closed   bool
}

func newGoSlabPool(pressure func() MemoryPressure, lowWater int) *goSlabPool {
	pool := &goSlabPool{
		free:     make([]*goSlab, 0, lowWater),
		pressure: pressure,
		lowWater: lowWater,
	}
	for range lowWater {
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
	p.access.Lock()
	if !p.closed && p.pressureLevel() == MemoryPressureNone {
		p.free = append(p.free, slab)
		p.access.Unlock()
	} else {
		p.access.Unlock()
		goFreeSlab(slab)
	}
	p.inUse.Add(-1)
}

func (p *goSlabPool) close() {
	p.access.Lock()
	p.closed = true
	free := p.free
	p.free = nil
	p.access.Unlock()
	for _, slab := range free {
		goFreeSlab(slab)
	}
}

func (p *goSlabPool) trim() {
	p.access.Lock()
	defer p.access.Unlock()
	if len(p.free) <= p.lowWater {
		return
	}
	target := p.lowWater
	if p.pressureLevel() == MemoryPressureNone {
		target = max(p.lowWater, len(p.free)/2)
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

const goSlabChainMinSlots = 4

type goSlabChain struct {
	slots         atomic.Pointer[[]*goSlab]
	pool          *goSlabPool
	holder        *goSlabHolder
	held          atomic.Int32
	maxSlots      uint32
	releasedIndex uint64
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

func (c *goSlabChain) loadSlots() []*goSlab {
	slots := c.slots.Load()
	if slots == nil {
		return nil
	}
	return *slots
}

func (c *goSlabChain) ensure(last uint64) []*goSlab {
	slots := c.loadSlots()
	required := last - c.releasedIndex + 1
	if required <= uint64(len(slots)) {
		return slots
	}
	grown := make([]*goSlab, max(required, min(max(2*uint64(len(slots)), goSlabChainMinSlots), uint64(c.maxSlots))))
	for index := c.releasedIndex; index < c.releasedIndex+uint64(len(slots)); index++ {
		grown[index%uint64(len(grown))] = slots[index%uint64(len(slots))]
	}
	c.slots.Store(&grown)
	return grown
}

func goSlotOf(slots []*goSlab, offset uint64) int {
	return int((offset / goSlabSize) % uint64(len(slots)))
}

func (c *goSlabChain) reserve(offset uint64, length int) {
	first := offset / goSlabSize
	last := (offset + uint64(length) - 1) / goSlabSize
	slots := c.ensure(last)
	for index := first; index <= last; index++ {
		slot := int(index % uint64(len(slots)))
		if slots[slot] != nil {
			continue
		}
		slots[slot] = c.acquire()
	}
}

func (c *goSlabChain) writeAt(offset uint64, data []byte) {
	slots := c.loadSlots()
	for len(data) > 0 {
		slab := slots[goSlotOf(slots, offset)]
		start := int(offset % goSlabSize)
		n := copy(slab[start:], data)
		data = data[n:]
		offset += uint64(n)
	}
}

func (c *goSlabChain) readAt(offset uint64, target []byte) {
	slots := c.loadSlots()
	copied := 0
	for copied < len(target) {
		slab := slots[goSlotOf(slots, offset)]
		start := int(offset % goSlabSize)
		n := copy(target[copied:], slab[start:])
		copied += n
		offset += uint64(n)
	}
}

func (c *goSlabChain) appendRuns(segments [][]byte, offset uint64, length int) [][]byte {
	slots := c.loadSlots()
	for length > 0 {
		slab := slots[goSlotOf(slots, offset)]
		start := int(offset % goSlabSize)
		n := min(goSlabSize-start, length)
		segments = append(segments, slab[start:start+n])
		offset += uint64(n)
		length -= n
	}
	return segments
}

func (c *goSlabChain) releaseRange(first uint64, last uint64) {
	slots := c.loadSlots()
	if len(slots) == 0 {
		return
	}
	for index := first; index <= last; index++ {
		slot := int(index % uint64(len(slots)))
		slab := slots[slot]
		if slab == nil {
			continue
		}
		slots[slot] = nil
		c.release(slab)
	}
}

func (c *goSlabChain) releaseBelow(offset uint64) {
	target := offset / goSlabSize
	if target <= c.releasedIndex {
		return
	}
	slots := c.loadSlots()
	end := min(target, c.releasedIndex+uint64(len(slots)))
	if end > c.releasedIndex {
		c.releaseRange(c.releasedIndex, end-1)
	}
	c.releasedIndex = target
}

func (c *goSlabChain) releaseDrained(offset uint64) {
	c.releaseBelow(offset)
	c.releaseRange(offset/goSlabSize, offset/goSlabSize)
}

func (c *goSlabChain) releaseAll() {
	slots := c.loadSlots()
	for slot, slab := range slots {
		if slab == nil {
			continue
		}
		slots[slot] = nil
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
	if first <= last {
		s.chain.releaseRange(first, last)
	}
	s.reserveTail = tail
}

func (s *goTransmitStore) writeAt(offset uint64, data []byte) {
	for len(data) > 0 {
		s.access.Lock()
		slots := s.chain.loadSlots()
		slab := slots[goSlotOf(slots, offset)]
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

const (
	goDescriptorBlockCapacity  = 64
	goScoreboardInlineCapacity = 16
)

type goDescriptorBlock [goDescriptorBlockCapacity]goSentDescriptor

// The producer publishes entries through tail; the engine consumes them through
// head. Blocks are allocated on demand and returned after their final entry is
// consumed. The directory stays fixed so neither side has to resize shared state.
type goDescriptorRing struct {
	blocks        [goDescriptorRingCapacity / goDescriptorBlockCapacity]atomic.Pointer[goDescriptorBlock]
	pool          *goDescriptorPool
	head          atomic.Uint32
	tail          atomic.Uint32
	pending       goSentDescriptor
	pendingActive bool
}

type goDescriptorPool struct {
	access   sync.Mutex
	free     []*goDescriptorBlock
	lowWater int
}

func (p *goDescriptorPool) acquire() *goDescriptorBlock {
	p.access.Lock()
	index := len(p.free) - 1
	if index >= 0 {
		block := p.free[index]
		p.free[index] = nil
		p.free = p.free[:index]
		p.access.Unlock()
		return block
	}
	p.access.Unlock()
	return new(goDescriptorBlock)
}

func (p *goDescriptorPool) release(block *goDescriptorBlock) {
	p.access.Lock()
	p.free = append(p.free, block)
	p.access.Unlock()
}

func (p *goDescriptorPool) trim() {
	p.access.Lock()
	defer p.access.Unlock()
	if len(p.free) <= p.lowWater {
		return
	}
	target := max(p.lowWater, len(p.free)/2)
	clear(p.free[target:])
	p.free = p.free[:target]
}

// release requires exclusive access to both sides of the ring. For a live
// connection the engine holds transmitOwner and checks that all sent data is ACKed.
func (r *goDescriptorRing) release() {
	for index := range r.blocks {
		if block := r.blocks[index].Swap(nil); block != nil {
			r.pool.release(block)
		}
	}
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
	if tail-r.head.Load() >= goDescriptorRingCapacity {
		return false
	}
	slot := &r.blocks[tail/goDescriptorBlockCapacity%uint32(len(r.blocks))]
	block := slot.Load()
	// A wrapped producer must not reuse the consumed prefix of a block that
	// the consumer still owns; the consumer releases whole blocks.
	if tail%goDescriptorBlockCapacity == 0 && block != nil {
		return false
	}
	if block == nil {
		block = r.pool.acquire()
		slot.Store(block)
	}
	block[tail%goDescriptorBlockCapacity] = entry
	r.tail.Store(tail + 1)
	return true
}

func (r *goDescriptorRing) take(index uint32) goSentDescriptor {
	slot := &r.blocks[index/goDescriptorBlockCapacity%uint32(len(r.blocks))]
	block := slot.Load()
	entry := block[index%goDescriptorBlockCapacity]
	if (index+1)%goDescriptorBlockCapacity == 0 {
		slot.Store(nil)
		r.pool.release(block)
	}
	return entry
}

type goScoreboard struct {
	entries []goSentDescriptor
	inline  [goScoreboardInlineCapacity]goSentDescriptor
}

func (s *goScoreboard) append(entry goSentDescriptor) {
	if s.entries == nil {
		s.entries = s.inline[:0]
	}
	s.entries = append(s.entries, entry)
}

func (s *goScoreboard) drain(ring *goDescriptorRing, unacked uint64) {
	head := ring.head.Load()
	tail := ring.tail.Load()
	for head != tail {
		entry := ring.take(head)
		head++
		if entry.flags&goDescriptorAmend != 0 {
			s.amend(entry.endOffset-uint64(entry.sentAt), entry.endOffset, entry.flags&^goDescriptorAmend)
			continue
		}
		if entry.endOffset > unacked {
			s.append(entry)
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
	if remaining == 0 {
		s.reset()
	}
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
	s.append(goSentDescriptor{})
	copy(s.entries[index+1:], s.entries[index:len(s.entries)-1])
	s.entries[index].endOffset = offset
}

func (s *goScoreboard) reset() {
	s.entries = nil
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
