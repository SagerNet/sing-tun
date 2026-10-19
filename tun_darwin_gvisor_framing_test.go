//go:build with_gvisor && darwin && !ios

package tun

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"

	"golang.org/x/sys/unix"
)

type framingDispatcher struct{ packets chan []byte }

func (d *framingDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, p *stack.PacketBuffer) {
	var packet []byte
	for _, part := range p.AsSlices() {
		packet = append(packet, part...)
	}
	select {
	case d.packets <- packet:
	default:
	}
}
func (*framingDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// Exercise the real fd-based dispatcher with datagram sockets, including its
// independent write path. No public interface, routes or root are needed.
func TestDarwinGVisorProcUUID(t *testing.T) {
	for _, size := range []int{4, 20} {
		for _, sendMsgX := range []bool{false, true} {
			for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
				t.Run(fmt.Sprintf("header=%d/family=%d/sendmsg=%v", size, family, sendMsgX), func(t *testing.T) {
					fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { unix.Close(fds[0]); unix.Close(fds[1]) })
					device := &NativeTun{
						tunFd: fds[0], options: Options{MTU: 1500, EXP_SendMsgX: sendMsgX},
						packetHeaderSize: size, packetHeaderVec4: utunHeaderVector(size, unix.AF_INET),
						packetHeaderVec6: utunHeaderVector(size, unix.AF_INET6),
					}
					ep, nic, err := device.NewEndpoint()
					if err != nil {
						t.Fatal(err)
					}
					defer nic.QDisc.Close()
					d := &framingDispatcher{packets: make(chan []byte, 1)}
					ep.Attach(d)
					defer ep.Attach(nil)
					packet := make([]byte, 32)
					packet[0], packet[3], packet[8], packet[9] = 0x45, 32, 64, 17
					copy(packet[12:20], []byte{198, 19, 1, 249, 198, 19, 1, 250})
					copy(packet[20:], []byte{0xb0, 0, 0xb0, 1, 0, 12, 0, 0, 1, 2, 3, 4})
					protocol := tcpip.NetworkProtocolNumber(0x0800)
					if family == unix.AF_INET6 {
						packet = make([]byte, 52)
						packet[0], packet[5], packet[6], packet[7] = 0x60, 12, 17, 64
						packet[8], packet[23], packet[24], packet[39] = 0xfd, 1, 0xfd, 2
						copy(packet[40:], []byte{0xb0, 0, 0xb0, 1, 0, 12, 0, 0, 1, 2, 3, 4})
						protocol = 0x86dd
					}
					frame := make([]byte, size)
					frame[3] = family
					for i := 4; i < size; i++ {
						frame[i] = 0x11
					}
					frame = append(frame, packet...)
					if _, err = unix.Write(fds[1], frame); err != nil {
						t.Fatal(err)
					}
					select {
					case got := <-d.packets:
						if !bytes.Equal(got, packet) {
							t.Fatal("gVisor did not preserve IP packet")
						}
					case <-time.After(time.Second):
						t.Fatal("gVisor failed to deliver framed IP packet")
					}
					p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
					defer p.DecRef()
					p.NetworkProtocolNumber = protocol
					var packets stack.PacketBufferList
					packets.PushBack(p)
					if n, e := ep.WritePackets(packets); e != nil || n != 1 {
						t.Fatalf("gVisor write: %d %v", n, e)
					}
					if err = unix.SetNonblock(fds[1], true); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, 2048)
					n, err := unix.Read(fds[1], got)
					if err != nil {
						t.Fatal(err)
					}
					want := make([]byte, size)
					want[3] = family
					want = append(want, packet...)
					if !bytes.Equal(got[:n], want) {
						t.Fatalf("wrong outgoing header length: got %d, want %d", n, len(want))
					}
				})
			}
		}
	}
}
