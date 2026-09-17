//go:build !darwin && !linux

package tun

func goArenaEnabled() bool {
	return false
}

func newGoSlabStore(lowWater int) goSlabStore {
	return goHeapSlabStore{}
}

func goRegionMap(size int) []byte {
	return nil
}

func goRegionUnmap(memory []byte) {
}

func goRegionPark(memory []byte) {
}

func goRegionReuse(memory []byte) {
}
