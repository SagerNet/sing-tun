//go:build darwin && !ios

package tun

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	rawfile "github.com/sagernet/sing-tun/internal/rawfile_darwin"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

func TestGoDarwinProcUUIDFraming(t *testing.T) {
	for _, size := range []int{4, 20} {
		for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
			t.Run(fmt.Sprintf("header=%d/family=%d", size, family), func(t *testing.T) {
				fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fds[0])
				defer unix.Close(fds[1])
				for _, fd := range fds {
					if err = unix.SetNonblock(fd, true); err != nil {
						t.Fatal(err)
					}
				}
				device := &NativeTun{
					packetHeaderSize: size,
					packetHeaderVec4: utunHeaderVector(size, unix.AF_INET),
					packetHeaderVec6: utunHeaderVector(size, unix.AF_INET6),
				}
				o := &goDarwinIO{
					stack: &Go{tun: device, mtu: 1500}, tunFd: fds[0],
					transmitAccess: &sync.Mutex{}, receiveBatch: 1,
					receiveIovecs: make([]unix.Iovec, goReadBatch), messageHeaders: make([]rawfile.MsgHdrX, goReadBatch),
					batchHeaders:  make([]byte, goDarwinTransmitBatch*goDarwinBatchHeader),
					batchIovecs:   make([]unix.Iovec, goDarwinTransmitBatch*goDarwinBatchIovecs),
					batchMessages: make([]rawfile.MsgHdrX, goDarwinTransmitBatch), batchSpilled: make([]bool, goDarwinTransmitBatch),
				}
				defer o.receiveSlots.release()
				packet := bytes.Repeat([]byte{0xa5}, 1500)
				headerLength := 28
				packet[0] = 0x45
				if family == unix.AF_INET6 {
					packet[0] = 0x60
					headerLength = 48
				}
				wire := bytes.Repeat([]byte{0x11}, size)
				copy(wire, []byte{0, 0, 0, family})
				wire = append(wire, packet...)
				if _, err = unix.Write(fds[1], wire); err != nil {
					t.Fatal(err)
				}
				frames := make([]goFrame, 1)
				n, _, err := o.readBurst(frames, N.ReadWaitOptions{FrontHeadroom: 7, RearHeadroom: 9})
				if err != nil || n != 1 || !bytes.Equal(frames[0].buffer.Bytes(), packet) {
					t.Fatalf("GoStack read did not preserve framed MTU packet: n=%d err=%v", n, err)
				}
				want := make([]byte, size)
				want[3] = family
				want = append(want, packet...)
				checkWrite := func(t *testing.T) {
					t.Helper()
					got := make([]byte, 1600)
					n, err := unix.Read(fds[1], got)
					if err != nil || !bytes.Equal(got[:max(n, 0)], want) {
						t.Fatalf("GoStack write framing mismatch: n=%d err=%v", n, err)
					}
				}
				t.Run("writev", func(t *testing.T) {
					if err := o.writePacket(packet, ForwardFrameMeta{}); err != nil {
						t.Fatal(err)
					}
					checkWrite(t)
				})
				t.Run("writeback-headroom", func(t *testing.T) {
					writer := &goWriteback{platformIO: o}
					if writer.ReturnHeadroom() != size {
						t.Fatal("wrong return headroom")
					}
					packetWithPrefix := append(make([]byte, size), packet...)
					if err := writer.WriteReturnPackets([][]byte{packetWithPrefix}); err != nil {
						t.Fatal(err)
					}
					checkWrite(t)
				})
				t.Run("queued-sendmsg", func(t *testing.T) {
					if err := o.writeData([][]byte{packet[:headerLength], packet[headerLength:]}, ForwardFrameMeta{}, nil, 0); err != nil {
						t.Fatal(err)
					}
					o.flush()
					checkWrite(t)
				})
				t.Run("udp-batch", func(t *testing.T) {
					frame := goUDPFrame{length: headerLength, payload: packet[headerLength:]}
					copy(frame.header[:], packet[:headerLength])
					if err := o.writePacketBatch([]goUDPFrame{frame}); err != nil {
						t.Fatal(err)
					}
					checkWrite(t)
				})
			})
		}
	}
}
