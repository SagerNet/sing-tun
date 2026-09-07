package tschecksum

//go:noescape
func checksumNEON(b []byte, initial uint16) uint16

func Checksum(data []byte, initial uint16) uint16 {
	return checksumNEON(data, initial)
}
