package tun

import "golang.org/x/sys/unix"

const goRegionMapFlags = unix.MAP_ANON | unix.MAP_PRIVATE

func goArenaEnabled() bool {
	return true
}

func goRegionPark(memory []byte) {
	unix.Madvise(memory, unix.MADV_FREE_REUSABLE)
}

func goRegionReuse(memory []byte) {
	unix.Madvise(memory, unix.MADV_FREE_REUSE)
}
