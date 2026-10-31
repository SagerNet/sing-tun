package tun

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestNetmapLayout(t *testing.T) {
	if unsafe.Sizeof(nmreqHeader{}) != 88 {
		t.Fatalf("nmreq_header size = %d, want 88", unsafe.Sizeof(nmreqHeader{}))
	}
	if unsafe.Sizeof(nmreqRegister{}) != 56 {
		t.Fatalf("nmreq_register size = %d, want 56", unsafe.Sizeof(nmreqRegister{}))
	}
	reg := nmreqRegister{}
	if off := unsafe.Offsetof(reg.Flags); off != 48 {
		t.Fatalf("nr_flags offset = %d, want 48", off)
	}
	if unsafe.Offsetof(reg.Mode) != 36 {
		t.Fatalf("nr_mode offset = %d, want 36", unsafe.Offsetof(reg.Mode))
	}
	if unix.IFNAMSIZ != netmapIFNameLen {
		t.Fatalf("IFNAMSIZ = %d, netmap_if name is %d", unix.IFNAMSIZ, netmapIFNameLen)
	}
	if got := ioc(0xC0000000, 'i', 151, 88); got != niocCtrl {
		t.Fatalf("NIOCCTRL = %#x, want %#x", got, uint32(niocCtrl))
	}
	if got := ioc(0x20000000, 'i', 149, 0); got != niocRxSync {
		t.Fatalf("NIOCRXSYNC = %#x, want %#x", got, uint32(niocRxSync))
	}
	if got := ioc(0x20000000, 'i', 148, 0); got != niocTxSync {
		t.Fatalf("NIOCTXSYNC = %#x, want %#x", got, uint32(niocTxSync))
	}
}

func ioc(inout, group, num, length uint32) uint32 {
	return inout | ((length & 0x1fff) << 16) | (group << 8) | num
}

func TestNetmapHostRX(t *testing.T) {
	mem := alignedBytes(t, 16384)
	put32(mem, 24, 1) // tx rings
	put32(mem, 28, 1) // rx rings
	put32(mem, 36, 1) // host tx
	put32(mem, 40, 1) // host rx
	// host RX is ring index 3; ring_ofs starts at 56.
	put64(mem, 56+3*8, 4096)

	const (
		ring    = 4096
		bufSize = 64
		slots   = 4
		dataAt  = 128
	)
	bufOfs := int64(dataAt - ring) // negative: buffers sit before the ring
	put64(mem, ring, uint64(bufOfs))
	put32(mem, ring+8, slots)
	put32(mem, ring+12, bufSize)
	put32(mem, ring+20, 0) // head
	put32(mem, ring+24, 0) // cur
	put32(mem, ring+28, 2) // tail: two packets

	putSlot(mem, ring, 0, 0, 8)
	copy(mem[dataAt:dataAt+8], []byte{0, 0, 0, 2, 10, 11, 12, 13})
	putSlot(mem, ring, 1, 1, 6)
	copy(mem[dataAt+bufSize:dataAt+bufSize+6], []byte{0, 0, 0, 28, 21, 22})

	view, err := netmapHostRX(mem, 0)
	if err != nil {
		t.Fatal(err)
	}
	if view.bufBytes() != bufSize || view.slots != slots {
		t.Fatalf("ring buf %d slots %d", view.bufBytes(), view.slots)
	}
	got := make([]byte, 32)
	n, err := view.copyOut(got)
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 || string(got[:n]) != string([]byte{0, 0, 0, 2, 10, 11, 12, 13}) {
		t.Fatalf("packet 0 = %v len %d", got[:n], n)
	}
	n, err = view.copyOut(got)
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 || string(got[:n]) != string([]byte{0, 0, 0, 28, 21, 22}) {
		t.Fatalf("packet 1 = %v len %d", got[:n], n)
	}
	if !view.empty() {
		t.Fatal("ring should be empty after the two packets")
	}

	// head is 2. Slot 2, then slot 3, then tail wraps to 0.
	putSlot(mem, ring, 2, 2, 4)
	copy(mem[dataAt+2*bufSize:dataAt+2*bufSize+4], []byte{0, 0, 0, 2})
	store32(mem, ring+28, 3)
	n, err = view.copyOut(got[:4])
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || view.head() != 3 {
		t.Fatalf("slot 2 n=%d head=%d", n, view.head())
	}
	putSlot(mem, ring, 3, 3, 4)
	copy(mem[dataAt+3*bufSize:dataAt+3*bufSize+4], []byte{1, 2, 3, 4})
	store32(mem, ring+28, 0)
	n, err = view.copyOut(got[:4])
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || view.head() != 0 || string(got[:4]) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("wrap n=%d head=%d pkt=%v", n, view.head(), got[:4])
	}
	short := make([]byte, 2)
	putSlot(mem, ring, 0, 0, 8)
	store32(mem, ring+28, 1)
	n, err = view.copyOut(short)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || view.head() != 1 {
		t.Fatalf("short read n=%d head=%d", n, view.head())
	}
}

func alignedBytes(t *testing.T, n int) []byte {
	t.Helper()
	raw := make([]byte, n+8)
	start := int(uintptr(unsafe.Pointer(&raw[0])) & 7)
	if start != 0 {
		start = 8 - start
	}
	return raw[start : start+n]
}

func put32(mem []byte, off int, v uint32) {
	binary.NativeEndian.PutUint32(mem[off:], v)
}

func put64(mem []byte, off int, v uint64) {
	binary.NativeEndian.PutUint64(mem[off:], v)
}

func putSlot(mem []byte, ring int, index, bufIdx uint32, length uint16) {
	off := ring + netmapRingSlots + int(index)*netmapSlotSize
	put32(mem, off, bufIdx)
	binary.NativeEndian.PutUint16(mem[off+4:], length)
}
