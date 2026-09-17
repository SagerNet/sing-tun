package tun

import (
	"os"
	"sync"

	"github.com/sagernet/sing/common/memory"

	"golang.org/x/sys/unix"
)

const (
	goLowMemoryLimit = 512 << 20
	goRegionMapFlags = unix.MAP_ANON | unix.MAP_PRIVATE | unix.MAP_NORESERVE
)

var goArenaEnabled = sync.OnceValue(func() bool {
	return goSlabSize%os.Getpagesize() == 0 && memory.LimitAvailable() && memory.Limit() < goLowMemoryLimit
})

func goRegionPark(memory []byte) {
	unix.Madvise(memory, unix.MADV_DONTNEED)
}

func goRegionReuse(memory []byte) {
}
