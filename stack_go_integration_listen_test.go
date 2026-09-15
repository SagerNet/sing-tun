//go:build (linux && !android) || (darwin && !ios)

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestGoListenTCP(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true, noHandler: true})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(addressTest *testing.T) {
			addressTest.Run("duplex", func(test *testing.T) {
				listener, err := fixture.stack.ListenTCP(netip.AddrPortFrom(fixture.kernelAddress(ipv6).Next(), 0))
				if err != nil {
					test.Fatal(err)
				}
				defer listener.Close()
				listener.SetDeadline(time.Now().Add(3 * time.Second))
				dialer := net.Dialer{Timeout: 3 * time.Second}
				kernel, err := dialer.Dial("tcp", listener.Addr().String())
				if err != nil {
					test.Fatal(err)
				}
				defer kernel.Close()
				kernel.SetDeadline(time.Now().Add(10 * time.Second))
				conn, err := listener.AcceptTCP()
				if err != nil {
					test.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				if conn.LocalAddr().String() != listener.Addr().String() {
					test.Fatalf("accepted local address %s, listener %s", conn.LocalAddr(), listener.Addr())
				}
				if conn.RemoteAddr().String() != kernel.LocalAddr().String() {
					test.Fatalf("accepted remote address %s, kernel %s", conn.RemoteAddr(), kernel.LocalAddr())
				}
				result := make(chan error, 1)
				go func() { result <- kernelTransfer(conn, kernel, kernelPayload(4<<20, 31), false) }()
				err = kernelTransfer(kernel, conn, kernelPayload(4<<20, 47), false)
				if err != nil {
					test.Error("upload:", err)
				}
				err = <-result
				if err != nil {
					test.Error("download:", err)
				}
			})
			addressTest.Run("close", func(test *testing.T) {
				listener, err := fixture.stack.ListenTCP(netip.AddrPortFrom(fixture.kernelAddress(ipv6).Next(), 0))
				if err != nil {
					test.Fatal(err)
				}
				dialer := net.Dialer{Timeout: 3 * time.Second}
				kernel, err := dialer.Dial("tcp", listener.Addr().String())
				if err != nil {
					test.Fatal(err)
				}
				defer kernel.Close()
				kernel.SetDeadline(time.Now().Add(3 * time.Second))
				listener.Close()
				_, err = kernel.Read(make([]byte, 1))
				if !errors.Is(err, syscall.ECONNRESET) {
					test.Fatalf("kernel read on a connection queued at a closed listener: %v", err)
				}
				_, err = listener.Accept()
				if !errors.Is(err, net.ErrClosed) {
					test.Fatalf("accept on a closed listener: %v", err)
				}
				_, err = dialer.Dial("tcp", listener.Addr().String())
				if !errors.Is(err, syscall.ECONNREFUSED) {
					test.Fatalf("connect to a closed listener: %v", err)
				}
			})
		})
	}
}

func TestGoListenPrecedence(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			port := uint16(30000 + fixture.port.Add(1))
			local := netip.AddrPortFrom(fixture.kernelAddress(ipv6).Next(), port)
			listener, err := fixture.stack.ListenTCP(local)
			if err != nil {
				test.Fatal(err)
			}
			defer listener.Close()
			listener.SetDeadline(time.Now().Add(3 * time.Second))
			_, err = fixture.stack.ListenTCP(local)
			if !errors.Is(err, syscall.EADDRINUSE) {
				test.Fatalf("second listener on %s: %v", local, err)
			}
			kernel, err := fixture.dialer.Dial("tcp", local.String())
			if err != nil {
				test.Fatal(err)
			}
			defer kernel.Close()
			kernel.SetDeadline(time.Now().Add(3 * time.Second))
			conn, err := listener.AcceptTCP()
			if err != nil {
				test.Fatal(err)
			}
			defer conn.Close()
			_, err = kernel.Write([]byte("listener"))
			if err != nil {
				test.Fatal(err)
			}
			received := make([]byte, 8)
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, err = conn.Read(received)
			if err != nil {
				test.Fatal(err)
			}
			if string(received) != "listener" {
				test.Fatalf("listener received %q", received)
			}
		})
	}
}

func TestGoListenUDPPort(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			port := uint16(30000 + fixture.port.Add(1))
			local := netip.AddrPortFrom(fixture.kernelAddress(ipv6).Next(), port)
			socket, err := fixture.stack.ListenUDP(local)
			if err != nil {
				test.Fatal(err)
			}
			defer socket.Close()
			socket.SetDeadline(time.Now().Add(3 * time.Second))
			if socket.LocalAddr().String() != local.String() {
				test.Fatalf("bound to %s, want %s", socket.LocalAddr(), local)
			}
			_, err = fixture.stack.ListenUDP(local)
			if !errors.Is(err, syscall.EADDRINUSE) {
				test.Fatalf("second socket on %s: %v", local, err)
			}
			peer, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(fixture.kernelAddress(ipv6), 0)))
			if err != nil {
				test.Fatal(err)
			}
			defer peer.Close()
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			payload := kernelPayload(1200, 21)
			_, err = peer.WriteToUDPAddrPort(payload, local)
			if err != nil {
				test.Fatal(err)
			}
			storage := make([]byte, 2000)
			n, source, err := socket.ReadFromUDPAddrPort(storage)
			if err != nil {
				test.Fatal(err)
			}
			if !bytes.Equal(storage[:n], payload) {
				test.Fatalf("received %d bytes with corrupted payload", n)
			}
			_, err = socket.WriteToUDPAddrPort(storage[:n], source)
			if err != nil {
				test.Fatal(err)
			}
			n, _, err = peer.ReadFrom(storage)
			if err != nil {
				test.Fatal(err)
			}
			if !bytes.Equal(storage[:n], payload) {
				test.Fatalf("reply carried %d bytes with corrupted payload", n)
			}
		})
	}
}
