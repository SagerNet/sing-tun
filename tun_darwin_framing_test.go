//go:build darwin && !ios

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	rawfile "github.com/sagernet/sing-tun/internal/rawfile_darwin"

	"golang.org/x/sys/unix"
)

func TestDarwinNativeFramingMTU(t *testing.T) {
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[1])
			if err = unix.SetNonblock(fds[0], true); err != nil {
				unix.Close(fds[0])
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fds[0]), "framing-test")
			defer file.Close()
			tun := &NativeTun{tunFile: file, packetHeaderSize: 20}
			packet := bytes.Repeat([]byte{0xa5}, 1500)
			if family == unix.AF_INET {
				packet[0] = 0x45
			} else {
				packet[0] = 0x60
			}
			wire := bytes.Repeat([]byte{0x11}, 20)
			copy(wire, []byte{0, 0, 0, family})
			wire = append(wire, packet...)
			if _, err = unix.Write(fds[1], wire); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 1504)
			n, err := tun.Read(got)
			want := append([]byte{0, 0, 0, family}, packet...)
			if err != nil || n != len(want) || !bytes.Equal(got[:n], want) {
				t.Fatalf("MTU read lost or corrupted bytes: %d %v", n, err)
			}
			if n, err = tun.Write(want); err != nil || n != len(want) {
				t.Fatalf("canonical write count: %d %v", n, err)
			}
			if err = unix.SetNonblock(fds[1], true); err != nil {
				t.Fatal(err)
			}
			got = make([]byte, 1600)
			n, err = unix.Read(fds[1], got)
			clear(wire[4:20])
			if err != nil || n != len(wire) || !bytes.Equal(got[:n], wire) {
				t.Fatalf("MTU write framing mismatch: %d %v", n, err)
			}
			if _, err = tun.Read(make([]byte, 3)); !errors.Is(err, io.ErrShortBuffer) {
				t.Fatalf("short destination: %v", err)
			}
			if _, err = tun.Write(make([]byte, 3)); !errors.Is(err, io.ErrShortBuffer) {
				t.Fatalf("short input: %v", err)
			}
			if _, err = unix.Write(fds[1], []byte{0, 0, 0}); err != nil {
				t.Fatal(err)
			}
			if _, err = tun.Read(make([]byte, 1504)); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated framing accepted: %v", err)
			}
		})
	}
}

func TestDarwinBatchFramingHeadroom(t *testing.T) {
	for _, size := range []int{4, 20} {
		for _, oversized := range []bool{false, true} {
			t.Run(fmt.Sprintf("header=%d/oversized=%v", size, oversized), func(t *testing.T) {
				fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(fds[0])
				defer unix.Close(fds[1])
				if err = unix.SetNonblock(fds[0], true); err != nil {
					t.Fatal(err)
				}
				tun := &NativeTun{
					tunFd: fds[0], packetHeaderSize: size, batchSize: 1,
					iovecs: []iovecBuffer{newIovecBuffer(1500, size)}, msgHdrs: make([]rawfile.MsgHdrX, 1),
				}
				defer func() {
					if tun.iovecs[0].buffer != nil {
						tun.iovecs[0].buffer.Release()
					}
				}()
				length := 1500
				if oversized {
					length++
				}
				packet := bytes.Repeat([]byte{0xa5}, length)
				packet[0] = 0x45
				wire := make([]byte, size)
				wire[3] = unix.AF_INET
				wire = append(wire, packet...)
				if _, err = unix.Write(fds[1], wire); err != nil {
					t.Fatal(err)
				}
				packets, err := tun.BatchRead(7, 9)
				if oversized {
					for _, p := range packets {
						p.Release()
					}
					if err == nil {
						t.Fatal("truncated batch datagram was accepted")
					}
					return
				}
				if err != nil || len(packets) != 1 {
					t.Fatalf("batch read: %v", err)
				}
				defer packets[0].Release()
				if !bytes.Equal(packets[0].Bytes(), packet) || packets[0].Start() != 7 {
					t.Fatal("packet or front headroom was not preserved")
				}
			})
		}
	}
}
