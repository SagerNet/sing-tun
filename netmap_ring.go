package tun

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"unsafe"
)

// FreeBSD netmap (NETMAP_API 14) shared-memory layout.
//
// Struct offsets match sys/net/netmap.h on LP64: timeval is 16 bytes and
// NM_CACHE_ALIGN is 128, so netmap_ring slots start at byte 256.
// netmap_if.ni_name is IFNAMSIZ (16) and ring_ofs begins at byte 56.
//
// Ioctl numbers are _IOC() values from sys/ioccom.h:
//
//	NIOCCTRL   _IOWR('i', 151, struct nmreq_header)  sizeof 88
//	NIOCRXSYNC _IO('i', 149)
//	NIOCTXSYNC _IO('i', 148)

const (
	netmapAPI         = 14
	netmapReqRegister = 1
	nrRegNICSW        = 3
	nrExclusive       = 0x800

	niocCtrl   = 0xC0586997
	niocTxSync = 0x20006994
	niocRxSync = 0x20006995

	netmapIFNameLen  = 16
	netmapIFRingsOff = 56
	netmapRingSlots  = 256
	netmapSlotSize   = 16

	// Release consumed slots back to the kernel after this many packets.
	// The kernel only notices userspace head during NIOCRXSYNC or poll;
	// holding every slot looks like a full ring and netmap_transmit drops.
	netmapReleaseEvery = 32
)

// nmreqHeader is struct nmreq_header. nr_body is a userspace pointer.
type nmreqHeader struct {
	Version  uint16
	ReqType  uint16
	Reserved uint32
	Name     [64]byte
	Options  uint64
	Body     uint64
}

// nmreqRegister is struct nmreq_register. Padding before Flags matches C
// on LP64: nr_flags is aligned to 8, so the struct is 56 bytes.
type nmreqRegister struct {
	Offset      uint64
	Memsize     uint64
	TxSlots     uint32
	RxSlots     uint32
	TxRings     uint16
	RxRings     uint16
	HostTxRings uint16
	HostRxRings uint16
	MemID       uint16
	RingID      uint16
	Mode        uint32
	ExtraBufs   uint32
	Flags       uint64
}

// netmapRing is the host RX ring inside a netmap mmap.
type netmapRing struct {
	mem     []byte
	ringOff int
	bufSize uint32
	slots   uint32
}

var errNetmapMap = errors.New("netmap shared memory is truncated or has no host RX ring")

// netmapHostRX locates the first host RX ring. Ring offsets in netmap_if are
// relative to the netmap_if, which itself sits at nifpOff in the mapping.
// Ring order is NIC TX, host TX, NIC RX, host RX.
func netmapHostRX(mem []byte, nifpOff uint64) (netmapRing, error) {
	base := int(nifpOff)
	if base < 0 || base+netmapIFRingsOff > len(mem) {
		return netmapRing{}, errNetmapMap
	}
	tx := native32(mem[base+24:])
	rx := native32(mem[base+28:])
	hostTx := native32(mem[base+36:])
	hostRx := native32(mem[base+40:])
	if hostRx == 0 {
		return netmapRing{}, errNetmapMap
	}
	idx := tx + hostTx + rx
	ofsPos := base + netmapIFRingsOff + int(idx)*8
	if ofsPos < base || ofsPos+8 > len(mem) {
		return netmapRing{}, errNetmapMap
	}
	abs := int64(base) + int64(native64(mem[ofsPos:]))
	if abs < 0 || abs+netmapRingSlots > int64(len(mem)) {
		return netmapRing{}, errNetmapMap
	}
	ringOff := int(abs)
	slots := native32(mem[ringOff+8:])
	bufSize := native32(mem[ringOff+12:])
	if slots < 2 || bufSize == 0 {
		return netmapRing{}, errNetmapMap
	}
	need := abs + int64(netmapRingSlots) + int64(slots)*netmapSlotSize
	if need > int64(len(mem)) {
		return netmapRing{}, errNetmapMap
	}
	return netmapRing{mem: mem, ringOff: ringOff, bufSize: bufSize, slots: slots}, nil
}

func (r netmapRing) empty() bool {
	return r.head() == r.tail()
}

func (r netmapRing) head() uint32 {
	return load32(r.mem, r.ringOff+20)
}

func (r netmapRing) tail() uint32 {
	return load32(r.mem, r.ringOff+28)
}

func (r netmapRing) bufBytes() uint32 {
	return r.bufSize
}

// copyOut copies the packet at head into dst and advances head and cur.
// The returned length may be shorter than the slot when dst is smaller,
// matching a short read on /dev/tun. The slot is always consumed.
func (r netmapRing) copyOut(dst []byte) (int, error) {
	head := r.head()
	if head >= r.slots {
		return 0, errNetmapMap
	}
	slot := r.ringOff + netmapRingSlots + int(head)*netmapSlotSize
	if slot < 0 || slot+6 > len(r.mem) {
		return 0, errNetmapMap
	}
	bufIdx := native32(r.mem[slot:])
	length := int(native16(r.mem[slot+4:]))
	if length < 0 || uint32(length) > r.bufSize {
		return 0, errNetmapMap
	}
	bufOfs := int64(native64(r.mem[r.ringOff:]))
	abs := int64(r.ringOff) + bufOfs + int64(bufIdx)*int64(r.bufSize)
	if abs < 0 || abs+int64(length) > int64(len(r.mem)) {
		return 0, errNetmapMap
	}
	n := length
	if n > len(dst) {
		n = len(dst)
	}
	copy(dst, r.mem[abs:abs+int64(n)])
	next := head + 1
	if next == r.slots {
		next = 0
	}
	store32(r.mem, r.ringOff+20, next)
	store32(r.mem, r.ringOff+24, next)
	return n, nil
}

func native16(b []byte) uint16 {
	return binary.NativeEndian.Uint16(b)
}

func native32(b []byte) uint32 {
	return binary.NativeEndian.Uint32(b)
}

func native64(b []byte) uint64 {
	return binary.NativeEndian.Uint64(b)
}

func load32(mem []byte, off int) uint32 {
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&mem[off])))
}

func store32(mem []byte, off int, v uint32) {
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&mem[off])), v)
}
