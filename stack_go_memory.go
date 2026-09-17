package tun

import (
	"os"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
)

var goPageSize = os.Getpagesize()

type goSlabStore interface {
	acquire() *goSlab
	release(slab *goSlab, discard bool)
	purge()
	close()
}

type goHeapSlabStore struct{}

func (goHeapSlabStore) acquire() *goSlab {
	return (*goSlab)(buf.Get(goSlabSize))
}

func (goHeapSlabStore) release(slab *goSlab, discard bool) {
	if discard {
		return
	}
	common.Must(buf.Put(slab[:]))
}

func (goHeapSlabStore) purge() {
}

func (goHeapSlabStore) close() {
}

type goReadSlots struct {
	buffers []*buf.Buffer
	region  []byte
	stride  int
	woken   int
}

func (s *goReadSlots) configure(count int, stride int) {
	if s.buffers != nil && len(s.buffers) == count && s.stride == stride {
		return
	}
	s.release()
	s.buffers = make([]*buf.Buffer, count)
	s.stride = stride
}

func (s *goReadSlots) wake(count int) {
	if !goArenaEnabled() {
		return
	}
	if s.region == nil {
		s.region = goRegionMap(len(s.buffers) * s.stride)
	}
	if count <= s.woken {
		return
	}
	start := s.woken * s.stride &^ (goPageSize - 1)
	end := min((count*s.stride+goPageSize-1)&^(goPageSize-1), len(s.region))
	goRegionReuse(s.region[start:end])
	s.woken = count
}

func (s *goReadSlots) slot(index int) *buf.Buffer {
	if goArenaEnabled() && index >= s.woken {
		s.wake(index + 1)
	}
	buffer := s.buffers[index]
	if buffer != nil {
		return buffer
	}
	if goArenaEnabled() {
		buffer = buf.With(s.region[index*s.stride : (index+1)*s.stride])
	} else {
		buffer = buf.NewSize(s.stride)
	}
	s.buffers[index] = buffer
	return buffer
}

func (s *goReadSlots) sleep() {
	if !goArenaEnabled() {
		buf.ReleaseMulti(s.buffers)
		clear(s.buffers)
		return
	}
	if s.woken == 0 {
		return
	}
	end := min((s.woken*s.stride+goPageSize-1)&^(goPageSize-1), len(s.region))
	goRegionPark(s.region[:end])
	s.woken = 0
}

func (s *goReadSlots) release() {
	if goArenaEnabled() {
		if s.region != nil {
			goRegionUnmap(s.region)
			s.region = nil
		}
	} else {
		buf.ReleaseMulti(s.buffers)
	}
	s.buffers = nil
	s.stride = 0
	s.woken = 0
}
