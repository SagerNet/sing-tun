//go:build linux && !android

package tun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"

	"golang.org/x/sys/unix"
)

func TestGoKernelPacketOffload(t *testing.T) {
	allocator := &kernelPacketAllocator{Allocator: buf.DefaultAllocator}
	buf.DefaultAllocator = allocator
	t.Cleanup(func() { buf.DefaultAllocator = allocator.Allocator })
	for _, multiQueue := range []bool{false, true} {
		t.Run(fmt.Sprintf("mq=%v", multiQueue), func(queueTest *testing.T) {
			fixture := newKernelStackFixture(queueTest, kernelStackConfig{mtu: 1500, gso: true, multiQueue: multiQueue})
			for _, ipv6 := range []bool{false, true} {
				for _, mode := range []string{"direct", "socks", "socks-fqdn"} {
					queueTest.Run(fmt.Sprintf("ipv6=%v/%s", ipv6, mode), func(scenarioTest *testing.T) {
						client, conn, destination := fixture.packetPair(scenarioTest, ipv6)
						network := "udp4"
						address := net.IPv4(127, 0, 0, 1)
						if ipv6 {
							network = "udp6"
							address = net.IPv6loopback
						}
						peer, err := net.ListenUDP(network, &net.UDPAddr{IP: address})
						if err != nil {
							scenarioTest.Fatal(err)
						}
						defer peer.Close()
						peer.SetDeadline(time.Now().Add(3 * time.Second))
						peer.SetReadBuffer(1 << 20)
						upstream, err := net.DialUDP(network, nil, peer.LocalAddr().(*net.UDPAddr))
						if err != nil {
							scenarioTest.Fatal(err)
						}
						defer upstream.Close()
						upstream.SetReadBuffer(1 << 20)
						rawUpstream, err := upstream.SyscallConn()
						if err != nil {
							scenarioTest.Fatal(err)
						}
						var (
							monitorDescriptor int
							monitorError      error
						)
						err = rawUpstream.Control(func(descriptor uintptr) {
							monitorDescriptor, monitorError = unix.FcntlInt(descriptor, unix.F_DUPFD_CLOEXEC, 0)
						})
						if err != nil || monitorError != nil {
							scenarioTest.Fatalf("duplicate socket for GRO inspection: %v, %v", err, monitorError)
						}
						defer unix.Close(monitorDescriptor)
						for _, socket := range []*net.UDPConn{client, peer} {
							rawConn, rawError := socket.SyscallConn()
							if rawError != nil {
								scenarioTest.Fatal(rawError)
							}
							controlError := rawConn.Control(func(descriptor uintptr) {
								err = unix.SetsockoptInt(int(descriptor), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
							})
							if controlError != nil || err != nil {
								scenarioTest.Fatalf("enable peer GRO: %v, %v", controlError, err)
							}
						}
						options := SplicePacketOptions{NAT: PacketNAT{Origin: destination, Destination: M.SocksaddrFromNet(peer.LocalAddr())}}
						var prefix []byte
						if mode != "direct" {
							target := M.ParseSocksaddr("192.0.2.1:53")
							prefix = []byte{0, 0, 0, 1, 192, 0, 2, 1, 0, 53}
							if ipv6 {
								target = M.ParseSocksaddr("[2001:db8::1]:53")
								prefix = append([]byte{0, 0, 0, 4}, netip.MustParseAddr("2001:db8::1").AsSlice()...)
								prefix = append(prefix, 0, 53)
							}
							if mode == "socks-fqdn" {
								target = M.ParseSocksaddr("batch.example:53")
								prefix = append([]byte{0, 0, 0, 3, byte(len(target.Fqdn))}, target.Fqdn...)
								prefix = append(prefix, 0, 53)
							}
							associate := socks.NewAssociatePacketConn(upstream, target, upstream)
							options.Offload, _ = associate.CreatePacketOffload()
							options.FrontHeadroom = associate.FrontHeadroom()
							options.NAT.Destination = target
						}
						if !conn.Splice(&kernelPacketSocket{UDPConn: upstream}, options) {
							scenarioTest.Fatal("UDP splice refused")
						}
						for cycle := range 2 {
							payloads := make([][]byte, 20)
							wirePackets := make([][]byte, len(payloads))
							for index := range payloads {
								size := 1200
								if index == len(payloads)-1 {
									size = 133
								}
								payloads[index] = kernelPayload(size, uint32(index+cycle*31+53))
								wirePackets[index] = append(bytes.Clone(prefix), payloads[index]...)
							}
							_, _, err = client.WriteMsgUDP(bytes.Join(payloads, nil), kernelUDPSegmentControl(1200), nil)
							if err != nil {
								scenarioTest.Fatal("kernel GSO upload:", err)
							}
							source := kernelReadUDPSegments(scenarioTest, peer, wirePackets)
							gro, inspectError := unix.GetsockoptInt(monitorDescriptor, unix.IPPROTO_UDP, unix.UDP_GRO)
							if inspectError != nil || gro != 1 {
								scenarioTest.Fatalf("splice socket GRO disabled: %d, %v", gro, inspectError)
							}
							_, _, err = peer.WriteMsgUDP(bytes.Join(wirePackets, nil), kernelUDPSegmentControl(1200+len(prefix)), source)
							if err != nil {
								scenarioTest.Fatal("peer GSO download:", err)
							}
							kernelReadUDPSegments(scenarioTest, client, payloads)
							allocator.waitIdle(scenarioTest)
							time.Sleep(10 * time.Millisecond)
						}
					})
				}
			}
		})
	}
}

func kernelUDPSegmentControl(size int) []byte {
	control := make([]byte, unix.CmsgSpace(2))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&control[0]))
	header.Level = unix.IPPROTO_UDP
	header.Type = unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(control[unix.CmsgLen(0):], uint16(size))
	return control
}

func kernelReadUDPSegments(t *testing.T, socket *net.UDPConn, expected [][]byte) *net.UDPAddr {
	t.Helper()
	data := make([]byte, 65535)
	control := make([]byte, 128)
	var source *net.UDPAddr
	segmented := false
	for index := 0; index < len(expected); {
		length, controlLength, flags, sender, err := socket.ReadMsgUDP(data, control)
		if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			t.Fatalf("receive segment %d: flags=%d, %v", index, flags, err)
		}
		source = sender
		messages, err := unix.ParseSocketControlMessage(control[:controlLength])
		if err != nil {
			t.Fatal(err)
		}
		segmentSize := length
		for _, message := range messages {
			if message.Header.Level == unix.IPPROTO_UDP && message.Header.Type == unix.UDP_GRO {
				segmentSize = int(binary.NativeEndian.Uint32(message.Data))
				segmented = segmented || segmentSize < length
			}
		}
		for offset := 0; offset < length; offset += segmentSize {
			packet := data[offset:min(offset+segmentSize, length)]
			if index >= len(expected) || !bytes.Equal(packet, expected[index]) {
				t.Fatalf("segment %d corrupted: length=%d", index, len(packet))
			}
			index++
		}
	}
	if !segmented {
		t.Fatal("kernel received no UDP GSO/GRO aggregate")
	}
	return source
}
