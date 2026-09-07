//go:build darwin || linux

package tun

import (
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func goAllocateSlab() *goSlab {
	memory, err := unix.Mmap(-1, 0, goSlabSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		panic(E.Cause(err, "go: allocate slab"))
	}
	return (*goSlab)(unsafe.Pointer(&memory[0]))
}

func goFreeSlab(slab *goSlab) {
	unix.Munmap(unsafe.Slice(&slab[0], goSlabSize))
}
