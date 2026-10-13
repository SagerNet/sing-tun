//go:build darwin || linux

package tun

import (
	"cmp"
	"slices"
	"sync"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	goSlabChunkSlabs = 32
	goSlabChunkSize  = goSlabChunkSlabs * goSlabSize
)

const (
	goSlabFresh uint8 = iota
	goSlabLive
	goSlabCached
	goSlabReusable
)

func newGoSlabStore(lowWater int) goSlabStore {
	if !goArenaEnabled() {
		return goHeapSlabStore{}
	}
	return &goArenaSlabStore{cached: make([]*goSlab, 0, lowWater), lowWater: lowWater}
}

func goRegionMap(size int) []byte {
	size = (size + goPageSize - 1) &^ (goPageSize - 1)
	memory, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, goRegionMapFlags)
	if err != nil {
		panic(E.Cause(err, "go: map memory region"))
	}
	return memory
}

func goRegionUnmap(memory []byte) {
	unix.Munmap(memory)
}

type goSlabChunk struct {
	base     uintptr
	memory   []byte
	states   [goSlabChunkSlabs]uint8
	live     int
	cached   int
	reusable int
	fresh    int
}

func (c *goSlabChunk) slab(index int) *goSlab {
	return (*goSlab)(unsafe.Pointer(&c.memory[index*goSlabSize]))
}

func (c *goSlabChunk) span(index int) []byte {
	return c.memory[index*goSlabSize : (index+1)*goSlabSize]
}

func (c *goSlabChunk) idle() bool {
	return c.live == 0 && c.cached == 0
}

func (c *goSlabChunk) take(state uint8) (*goSlab, bool) {
	for index := range c.states {
		if c.states[index] != state {
			continue
		}
		switch state {
		case goSlabReusable:
			c.reusable--
			goRegionReuse(c.span(index))
		case goSlabFresh:
			c.fresh--
		}
		c.states[index] = goSlabLive
		c.live++
		return c.slab(index), true
	}
	return nil, false
}

type goArenaSlabStore struct {
	access   sync.Mutex
	chunks   []*goSlabChunk
	cached   []*goSlab
	lowWater int
	closed   bool
}

func (s *goArenaSlabStore) acquire() *goSlab {
	s.access.Lock()
	defer s.access.Unlock()
	if count := len(s.cached); count > 0 {
		slab := s.cached[count-1]
		s.cached[count-1] = nil
		s.cached = s.cached[:count-1]
		chunk, index := s.locate(slab)
		chunk.states[index] = goSlabLive
		chunk.cached--
		chunk.live++
		return slab
	}
	for _, chunk := range s.chunks {
		if chunk.reusable == 0 {
			continue
		}
		slab, _ := chunk.take(goSlabReusable)
		return slab
	}
	for _, chunk := range s.chunks {
		if chunk.fresh == 0 {
			continue
		}
		slab, _ := chunk.take(goSlabFresh)
		return slab
	}
	memory := goRegionMap(goSlabChunkSize)
	chunk := &goSlabChunk{base: uintptr(unsafe.Pointer(&memory[0])), memory: memory, fresh: goSlabChunkSlabs}
	position, _ := slices.BinarySearchFunc(s.chunks, chunk.base, goCompareChunk)
	s.chunks = slices.Insert(s.chunks, position, chunk)
	slab, _ := chunk.take(goSlabFresh)
	return slab
}

func goCompareChunk(chunk *goSlabChunk, base uintptr) int {
	return cmp.Compare(chunk.base, base)
}

func (s *goArenaSlabStore) locate(slab *goSlab) (*goSlabChunk, int) {
	address := uintptr(unsafe.Pointer(slab))
	position, found := slices.BinarySearchFunc(s.chunks, address, goCompareChunk)
	if !found {
		position--
	}
	chunk := s.chunks[position]
	return chunk, int((address - chunk.base) / goSlabSize)
}

func (s *goArenaSlabStore) release(slab *goSlab, discard bool) {
	s.access.Lock()
	defer s.access.Unlock()
	chunk, index := s.locate(slab)
	chunk.live--
	if discard || s.closed {
		s.park(chunk, index)
		s.trim(chunk)
		return
	}
	chunk.states[index] = goSlabCached
	chunk.cached++
	s.cached = append(s.cached, slab)
	if len(s.cached) <= s.lowWater {
		return
	}
	oldest := s.cached[0]
	remaining := copy(s.cached, s.cached[1:])
	s.cached[remaining] = nil
	s.cached = s.cached[:remaining]
	oldestChunk, oldestIndex := s.locate(oldest)
	oldestChunk.cached--
	s.park(oldestChunk, oldestIndex)
	s.trim(oldestChunk)
}

func (s *goArenaSlabStore) park(chunk *goSlabChunk, index int) {
	goRegionPark(chunk.span(index))
	chunk.states[index] = goSlabReusable
	chunk.reusable++
}

func (s *goArenaSlabStore) trim(chunk *goSlabChunk) {
	if !chunk.idle() {
		return
	}
	if !s.closed {
		idle := 0
		for _, candidate := range s.chunks {
			if candidate.idle() {
				idle++
			}
		}
		if idle <= 1 {
			return
		}
	}
	position, _ := slices.BinarySearchFunc(s.chunks, chunk.base, goCompareChunk)
	s.chunks = slices.Delete(s.chunks, position, position+1)
	goRegionUnmap(chunk.memory)
}

func (s *goArenaSlabStore) purge() {
	s.access.Lock()
	defer s.access.Unlock()
	for _, slab := range s.cached {
		chunk, index := s.locate(slab)
		chunk.cached--
		s.park(chunk, index)
	}
	clear(s.cached)
	s.cached = s.cached[:0]
	for _, chunk := range slices.Backward(s.chunks) {
		s.trim(chunk)
	}
}

func (s *goArenaSlabStore) close() {
	s.access.Lock()
	s.closed = true
	s.access.Unlock()
	s.purge()
}
