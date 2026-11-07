/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

// Frozen handleGRO from 7ac0256fa09ddf7215f3a7ccd0845ed18b235c4a.
// Both paths use the same unchanged TCP/UDP GRO implementations.
func controlHandleGRO(bufs [][]byte, offset int, tcpTable *tcpGROTable, udpTable *udpGROTable, gro groDisablementFlags, toWrite *[]int) error {
	for i := range bufs {
		if offset < virtioNetHdrLen || offset > len(bufs[i])-1 {
			return errors.New("invalid offset")
		}
		var result groResult
		switch packetIsGROCandidate(bufs[i][offset:], gro) {
		case tcp4GROCandidate:
			result = tcpGRO(bufs, offset, i, tcpTable, false)
		case tcp6GROCandidate:
			result = tcpGRO(bufs, offset, i, tcpTable, true)
		case udp4GROCandidate:
			result = udpGRO(bufs, offset, i, udpTable, false)
		case udp6GROCandidate:
			result = udpGRO(bufs, offset, i, udpTable, true)
		}
		switch result {
		case groResultNoop:
			hdr := virtioNetHdr{}
			err := hdr.encode(bufs[i][offset-virtioNetHdrLen:])
			if err != nil {
				return err
			}
			fallthrough
		case groResultTableInsert:
			*toWrite = append(*toWrite, i)
		}
	}
	errTCP := applyTCPCoalesceAccounting(bufs, offset, tcpTable)
	errUDP := applyUDPCoalesceAccounting(bufs, offset, udpTable)
	return errors.Join(errTCP, errUDP)
}

func groTestChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func groTestPacket(src, dst netip.Addr, udp bool, port uint16, seq, ack uint32, flags byte, data []byte) []byte {
	ipLen, transportLen, protocol := 20, 20, byte(6)
	if src.Is6() {
		ipLen = 40
	}
	if udp {
		transportLen, protocol = 8, 17
	}
	packet := make([]byte, ipLen+transportLen+len(data))
	if src.Is4() {
		packet[0], packet[8], packet[9] = 0x45, 64, protocol
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		copy(packet[12:16], src.AsSlice())
		copy(packet[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(packet[10:12], groTestChecksum(packet[:20]))
	} else {
		packet[0], packet[6], packet[7] = 0x60, protocol, 64
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
		copy(packet[8:24], src.AsSlice())
		copy(packet[24:40], dst.AsSlice())
	}
	segment := packet[ipLen:]
	binary.BigEndian.PutUint16(segment[0:2], 12345)
	binary.BigEndian.PutUint16(segment[2:4], port)
	checksumOffset := 16
	if udp {
		binary.BigEndian.PutUint16(segment[4:6], uint16(len(segment)))
		checksumOffset = 6
	} else {
		binary.BigEndian.PutUint32(segment[4:8], seq)
		binary.BigEndian.PutUint32(segment[8:12], ack)
		segment[12], segment[13] = 0x50, flags
		binary.BigEndian.PutUint16(segment[14:16], 65535)
	}
	copy(segment[transportLen:], data)
	var pseudo []byte
	if src.Is4() {
		pseudo = make([]byte, 12+len(segment))
		copy(pseudo[:4], src.AsSlice())
		copy(pseudo[4:8], dst.AsSlice())
		pseudo[9] = protocol
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
		copy(pseudo[12:], segment)
	} else {
		pseudo = make([]byte, 40+len(segment))
		copy(pseudo[:16], src.AsSlice())
		copy(pseudo[16:32], dst.AsSlice())
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(segment)))
		pseudo[39] = protocol
		copy(pseudo[40:], segment)
	}
	check := groTestChecksum(pseudo)
	if udp && check == 0 {
		check = 0xffff
	}
	binary.BigEndian.PutUint16(segment[checksumOffset:checksumOffset+2], check)
	return packet
}

func tcpPacket(src, dst netip.Addr, seq, ack uint32, flags byte, data []byte) []byte {
	return groTestPacket(src, dst, false, 443, seq, ack, flags, data)
}

func udpPacket(src, dst netip.Addr, port uint16, data []byte) []byte {
	return groTestPacket(src, dst, true, port, 0, 0, 0, data)
}

func TestSingleGROHeadroom(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, udp := range []bool{false, true} {
			for _, offset := range []int{10, 16, 32, 64} {
				packet := groPackets(ipv6, udp, 1, 64)[0]
				a, b := bytes.Repeat([]byte{0xa5}, offset+len(packet)), bytes.Repeat([]byte{0xa5}, offset+len(packet))
				copy(a[offset:], packet)
				copy(b[offset:], packet)
				wa, wb := []int{7, 8}, []int{7, 8}
				ea := controlHandleGRO([][]byte{a}, offset, newTCPGROTable(), newUDPGROTable(), 0, &wa)
				eb := handleGRO([][]byte{b}, offset, newTCPGROTable(), newUDPGROTable(), 0, &wb)
				if ea != nil || eb != nil || !bytes.Equal(a, b) || !slices.Equal(wa, wb) || !bytes.Equal(b[offset:], packet) || !bytes.Equal(b[offset-10:offset], make([]byte, 10)) {
					t.Fatalf("headroom=%d IPv6=%v UDP=%v: %v/%v", offset, ipv6, udp, ea, eb)
				}
			}
		}
	}
}

func groPackets(ipv6, udp bool, n, payload int) [][]byte {
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2")
	if ipv6 {
		src, dst = netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	}
	out := make([][]byte, n)
	for i := range out {
		data := bytes.Repeat([]byte{byte(i + 1)}, payload)
		if udp {
			out[i] = udpPacket(src, dst, 53, data)
		} else {
			flags := byte(0x10)
			if i == n-1 {
				flags |= 0x08
			}
			out[i] = tcpPacket(src, dst, 100+uint32(i*payload), 1, flags, data)
		}
	}
	return out
}

func groBuffers(packets [][]byte) [][]byte {
	out := make([][]byte, len(packets))
	for i, p := range packets {
		out[i] = make([]byte, virtioNetHdrLen+len(p), 65536+virtioNetHdrLen)
		for j := range virtioNetHdrLen {
			out[i][j] = 0xa5
		}
		copy(out[i][virtioNetHdrLen:], p)
	}
	return out
}

func TestSingleGROEquivalence(t *testing.T) {
	tcpA, tcpB, udpA, udpB := newTCPGROTable(), newTCPGROTable(), newUDPGROTable(), newUDPGROTable()
	cases := 0
	check := func(packets [][]byte, offset int, flags groDisablementFlags) {
		t.Helper()
		a, b := groBuffers(packets), groBuffers(packets)
		var wa, wb []int
		ea := controlHandleGRO(a, offset, tcpA, udpA, flags, &wa)
		eb := handleGRO(b, offset, tcpB, udpB, flags, &wb)
		if fmt.Sprint(ea) != fmt.Sprint(eb) || !slices.Equal(wa, wb) {
			t.Fatalf("offset=%d count=%d errors=%v/%v indices=%v/%v", offset, len(packets), ea, eb, wa, wb)
		}
		for i := range a {
			if !bytes.Equal(a[i], b[i]) {
				t.Fatalf("packet %d differs", i)
			}
		}
		tcpA.reset()
		tcpB.reset()
		udpA.reset()
		udpB.reset()
		cases++
	}
	for _, ipv6 := range []bool{false, true} {
		for _, udp := range []bool{false, true} {
			for _, n := range []int{1, 2, 3, 64, 1} { // reset/reuse after a coalesced batch
				for _, payload := range []int{0, 1, 64, 512} {
					for flags := range groDisablementFlags(4) {
						check(groPackets(ipv6, udp, n, payload), virtioNetHdrLen, flags)
					}
				}
			}
			p := groPackets(ipv6, udp, 1, 64)[0]
			for _, offset := range []int{-1, 0, 9, 10, 13, 10 + len(p), 11 + len(p)} {
				check([][]byte{p}, offset, 0)
			}
			for i := range p {
				m := append([]byte(nil), p...)
				m[i] ^= 0xff
				check([][]byte{m}, 10, 0)
			}
			// IPv4 fragment/options and IPv6 extension header cases are noops,
			// with unchanged data and an explicitly cleared virtio header.
			m := append([]byte(nil), p...)
			if ipv6 {
				m[6] = 0
			} else {
				m[6] |= 0x20
			}
			check([][]byte{m}, 10, 0)
			if !ipv6 {
				m[0] = 0x46
				check([][]byte{m}, 10, 0)
			}
			if !udp {
				off := 20
				if ipv6 {
					off = 40
				}
				for _, f := range []byte{0x02, 0x12, 0x01, 0x04, 0x10, 0x18} {
					m = append([]byte(nil), p...)
					m[off+13] = f
					check([][]byte{m}, 10, 0)
				}
			}
		}
	}
	check(nil, 10, 0)
	for n := range 80 {
		check([][]byte{bytes.Repeat([]byte{byte(n)}, n)}, 10, 0)
	}
	// Confirm a valid single packet clears stale GSO flags from earlier use.
	p := groBuffers(groPackets(false, false, 1, 64))
	var indices []int
	if err := handleGRO(p, 10, tcpB, udpB, 0, &indices); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p[0][:10], make([]byte, 10)) || !slices.Equal(indices, []int{0}) {
		t.Fatal("stale virtio header")
	}
	t.Logf("GRO differential cases: %d", cases)
}

func BenchmarkGROPaths(b *testing.B) {
	for _, n := range []int{1, 2, 64} {
		for _, udp := range []bool{false, true} {
			for _, candidate := range []bool{false, true} {
				b.Run(fmt.Sprintf("n%d_udp%v_candidate%v", n, udp, candidate), func(b *testing.B) {
					packets := groPackets(false, udp, n, 512)
					bufs := groBuffers(packets)
					tcp, ut := newTCPGROTable(), newUDPGROTable()
					indices := make([]int, 0, n)
					fn := controlHandleGRO
					if candidate {
						fn = handleGRO
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if n > 1 {
							for j, p := range packets {
								bufs[j] = bufs[j][:10+len(p)]
								copy(bufs[j][10:], p)
							}
						}
						indices = indices[:0]
						if err := fn(bufs, 10, tcp, ut, 0, &indices); err != nil {
							b.Fatal(err)
						}
						tcp.reset()
						ut.reset()
					}
				})
			}
		}
	}
}
