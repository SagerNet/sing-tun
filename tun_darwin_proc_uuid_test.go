//go:build darwin && !ios

package tun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"

	"golang.org/x/sys/unix"
)

// This integration test only uses a newly allocated utun and a /32 peer in the
// benchmark range. IP_BOUND_IF prevents a test datagram from using another link.
func TestDarwinNativeTunProcUUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires administrator authorization for an isolated kernel utun")
	}
	for _, flags := range []int{0, 4} {
		for _, batch := range []bool{false, true} {
			t.Run(fmt.Sprintf("flags=%d/batch=%v", flags, batch), func(t *testing.T) {
				fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
				if err != nil {
					t.Fatal(err)
				}
				transferred := false
				defer func() {
					if !transferred {
						_ = unix.Close(fd)
					}
				}()
				var info unix.CtlInfo
				copy(info.Name[:], utunControlName)
				if err = unix.IoctlCtlInfo(fd, &info); err != nil {
					t.Fatal(err)
				}
				interfaces, err := net.Interfaces()
				if err != nil {
					t.Fatal(err)
				}
				used := make(map[string]bool)
				for _, iface := range interfaces {
					used[iface.Name] = true
				}
				index := 200
				for used[fmt.Sprintf("utun%d", index)] {
					index++
				}
				address := &unix.SockaddrCtl{ID: info.Id, Unit: uint32(index + 1)}
				if err = unix.Bind(fd, address); err != nil {
					t.Fatal(err)
				}
				if err = unix.SetsockoptInt(fd, 2, 1, flags); err != nil {
					t.Fatal(err)
				}
				if err = unix.Connect(fd, address); err != nil {
					t.Fatal(err)
				}
				actualFlags, err := unix.GetsockoptInt(fd, 2, 1)
				if err != nil || actualFlags != flags {
					t.Fatalf("utun flags=%d: %v", actualFlags, err)
				}
				device, err := New(Options{FileDescriptor: fd, MTU: 1500, EXP_ExternalConfiguration: true})
				if err != nil {
					t.Fatal(err)
				}
				transferred = true
				var closeOnce sync.Once
				closeDevice := func() { closeOnce.Do(func() { _ = device.Close() }) }
				t.Cleanup(closeDevice)
				name, err := device.Name()
				if err != nil {
					t.Fatal(err)
				}
				// Different peers avoid reusing a route being removed by a prior subtest.
				peerIndex := flags + 1
				if batch {
					peerIndex++
				}
				localIPText := fmt.Sprintf("198.19.%d.249", peerIndex)
				peerIP := net.ParseIP(fmt.Sprintf("198.19.%d.250", peerIndex))
				output, err := exec.Command("/sbin/ifconfig", name, "inet", localIPText, peerIP.String(), "netmask", "255.255.255.255", "up").CombinedOutput()
				if err != nil {
					t.Fatalf("configure own interface: %s: %v", output, err)
				}
				iface, err := net.InterfaceByName(name)
				if err != nil {
					t.Fatal(err)
				}
				conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(localIPText)})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				raw, err := conn.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var bindError error
				if err = raw.Control(func(socket uintptr) { bindError = unix.SetsockoptInt(int(socket), unix.IPPROTO_IP, 25, iface.Index) }); err != nil {
					t.Fatal(err)
				}
				if bindError != nil {
					t.Fatal(bindError)
				}
				payload := []byte("deus-utun-frame-test")
				if _, err = conn.WriteToUDP(payload, &net.UDPAddr{IP: peerIP, Port: 45321}); err != nil {
					t.Fatal(err)
				}
				guard := time.AfterFunc(5*time.Second, closeDevice)
				defer guard.Stop()
				var frame []byte
				for !bytes.Contains(frame, payload) {
					if batch {
						packets, readErr := device.(DarwinTUN).BatchRead(0, 0)
						if readErr != nil {
							t.Fatal(readErr)
						}
						for _, packet := range packets {
							if bytes.Contains(packet.Bytes(), payload) {
								frame = append([]byte{0, 0, 0, unix.AF_INET}, packet.Bytes()...)
							}
							packet.Release()
						}
					} else {
						frame = make([]byte, 1500+PacketOffset)
						n, readErr := device.Read(frame)
						if readErr != nil {
							t.Fatal(readErr)
						}
						frame = frame[:n]
					}
					if !bytes.Contains(frame, payload) && len(frame) > 0 {
						t.Logf("ignoring unrelated kernel packet: %x", frame[:min(len(frame), 32)])
					}
				}
				guard.Stop()
				if len(frame) < 32 || frame[4]>>4 != 4 {
					t.Fatalf("flags=%d: expected IPv4 after canonical 4-byte header, got prefix %x", flags, frame[:min(len(frame), 24)])
				}
				packet := frame[4:]
				if packet[9] != 17 || !bytes.Equal(packet[28:], payload) {
					t.Fatal("UDP payload was not preserved")
				}
				// Construct the reply independently of the framing implementation.
				localIP := append([]byte(nil), packet[12:16]...)
				copy(packet[12:16], packet[16:20])
				copy(packet[16:20], localIP)
				sourcePort := binary.BigEndian.Uint16(packet[20:22])
				copy(packet[20:22], packet[22:24])
				binary.BigEndian.PutUint16(packet[22:24], sourcePort)
				packet[26], packet[27], packet[10], packet[11] = 0, 0, 0, 0
				var sum uint32
				for i := 0; i < 20; i += 2 {
					sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
				}
				for sum>>16 != 0 {
					sum = sum&0xffff + sum>>16
				}
				binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
				if batch {
					buffer := buf.NewSize(len(packet))
					_, _ = buffer.Write(packet)
					writeErr := device.(DarwinTUN).BatchWrite([]*buf.Buffer{buffer})
					buffer.Release()
					if writeErr != nil {
						t.Fatal(writeErr)
					}
				} else if n, writeErr := device.Write(frame); writeErr != nil || n != len(frame) {
					t.Fatalf("write reply: n=%d: %v", n, writeErr)
				}
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				response := make([]byte, 128)
				n, _, err := conn.ReadFromUDP(response)
				if err != nil || !bytes.Equal(response[:n], payload) {
					t.Fatalf("UDP reply did not reach its socket: %v", err)
				}
				t.Logf("kernel flags=%d, %s: bidirectional UDP frame preserved", flags, name)
			})
		}
	}
}
