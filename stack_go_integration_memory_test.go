//go:build (linux && !android) || (darwin && !ios)

package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

func kernelListen(t *testing.T, fixture *kernelStackFixture, ipv6 bool) (*net.TCPListener, netip.AddrPort) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(fixture.kernelAddress(ipv6), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener, listener.Addr().(*net.TCPAddr).AddrPort()
}

func kernelAcceptTCP(t *testing.T, listener *net.TCPListener) *net.TCPConn {
	t.Helper()
	listener.SetDeadline(time.Now().Add(3 * time.Second))
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

func TestGoMemoryDial(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(addressTest *testing.T) {
			addressTest.Run("duplex", func(test *testing.T) {
				listener, address := kernelListen(test, fixture, ipv6)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				conn, err := fixture.stack.DialTCP(ctx, fixture.kernelAddress(ipv6).Next(), address)
				if err != nil {
					test.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				server := kernelAcceptTCP(test, listener)
				if conn.RemoteAddr().String() != address.String() {
					test.Fatalf("remote address %s, want %s", conn.RemoteAddr(), address)
				}
				if conn.LocalAddr().String() != server.RemoteAddr().String() {
					test.Fatalf("local address %s, kernel peer %s", conn.LocalAddr(), server.RemoteAddr())
				}
				payload := kernelPayload(4<<20, 31)
				response := kernelPayload(4<<20, 47)
				result := make(chan error, 1)
				go func() { result <- kernelTransfer(conn, server, payload, false) }()
				err = kernelTransfer(server, conn, response, false)
				if err != nil {
					test.Error("download:", err)
				}
				err = <-result
				if err != nil {
					test.Error("upload:", err)
				}
			})
			addressTest.Run("close", func(test *testing.T) {
				listener, address := kernelListen(test, fixture, ipv6)
				conn, err := fixture.stack.DialTCP(context.Background(), fixture.kernelAddress(ipv6).Next(), address)
				if err != nil {
					test.Fatal(err)
				}
				server := kernelAcceptTCP(test, listener)
				_, err = conn.Write([]byte("hello"))
				if err != nil {
					test.Fatal(err)
				}
				err = conn.Close()
				if err != nil {
					test.Fatal(err)
				}
				data, err := io.ReadAll(server)
				if err != nil {
					test.Fatal(err)
				}
				if string(data) != "hello" {
					test.Fatalf("kernel received %q", data)
				}
			})
			addressTest.Run("refused", func(test *testing.T) {
				listener, address := kernelListen(test, fixture, ipv6)
				listener.Close()
				started := time.Now()
				_, err := fixture.stack.DialTCP(context.Background(), fixture.kernelAddress(ipv6).Next(), address)
				if !errors.Is(err, syscall.ECONNREFUSED) {
					test.Fatalf("dial to a closed port returned %v", err)
				}
				if time.Since(started) > time.Second {
					test.Fatalf("refusal took %v", time.Since(started))
				}
			})
			addressTest.Run("unreachable", func(test *testing.T) {
				prefix := netip.MustParsePrefix("198.19.255.0/24")
				destination := netip.MustParseAddrPort("198.19.255.254:9")
				if ipv6 {
					prefix = netip.MustParsePrefix("fd73:ab91:ffff::/48")
					destination = netip.MustParseAddrPort("[fd73:ab91:ffff::254]:9")
				}
				if !kernelAddUnreachableRoute(test, prefix) {
					test.Skip("unreachable routes are not configurable on this platform")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_, err := fixture.stack.DialTCP(ctx, fixture.kernelAddress(ipv6).Next(), destination)
				if !E.IsMulti(err, syscall.EHOSTUNREACH, syscall.ENETUNREACH) {
					test.Fatalf("dial to an unroutable address returned %v", err)
				}
			})
			addressTest.Run("cancel", func(test *testing.T) {
				listener, address := kernelListen(test, fixture, ipv6)
				fixture.bridge.pauseOutbound(true)
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				defer cancel()
				_, err := fixture.stack.DialTCP(ctx, fixture.kernelAddress(ipv6).Next(), address)
				fixture.bridge.pauseOutbound(false)
				if !errors.Is(err, context.DeadlineExceeded) {
					test.Fatalf("cancelled dial returned %v", err)
				}
				listener.SetDeadline(time.Now().Add(500 * time.Millisecond))
				conn, acceptErr := listener.Accept()
				if acceptErr == nil {
					conn.SetReadDeadline(time.Now().Add(time.Second))
					_, readErr := conn.Read(make([]byte, 1))
					conn.Close()
					if !errors.Is(readErr, syscall.ECONNRESET) {
						test.Fatalf("stale handshake was not reset: %v", readErr)
					}
				}
			})
			addressTest.Run("retransmit", func(test *testing.T) {
				listener, address := kernelListen(test, fixture, ipv6)
				fixture.bridge.outboundDrop.Store(1)
				started := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := fixture.stack.DialTCP(ctx, fixture.kernelAddress(ipv6).Next(), address)
				if err != nil {
					test.Fatal(err)
				}
				defer conn.Close()
				if time.Since(started) < goSynRetransmit {
					test.Fatalf("handshake completed in %v with the first SYN dropped", time.Since(started))
				}
				server := kernelAcceptTCP(test, listener)
				err = kernelTransfer(conn, server, kernelPayload(64<<10, 5), false)
				if err != nil {
					test.Fatal(err)
				}
			})
			addressTest.Run("stall", func(test *testing.T) {
				listener, address := kernelListen(test, fixture, ipv6)
				conn, err := fixture.stack.DialTCP(context.Background(), fixture.kernelAddress(ipv6).Next(), address)
				if err != nil {
					test.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				server := kernelAcceptTCP(test, listener)
				payload := kernelPayload(2<<20, 61)
				fixture.bridge.pauseOutbound(true)
				result := make(chan error, 1)
				go func() { result <- kernelTransfer(conn, server, payload, false) }()
				select {
				case err = <-result:
					test.Fatalf("transfer finished through a paused link: %v", err)
				case <-time.After(300 * time.Millisecond):
				}
				fixture.bridge.pauseOutbound(false)
				err = <-result
				if err != nil {
					test.Fatal(err)
				}
			})
		})
	}
}

func TestGoMemoryUDP(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(addressTest *testing.T) {
			addressTest.Run("listen", func(test *testing.T) {
				socket, err := fixture.stack.ListenUDP(netip.AddrPortFrom(fixture.kernelAddress(ipv6).Next(), 0))
				if err != nil {
					test.Fatal(err)
				}
				defer socket.Close()
				socket.SetDeadline(time.Now().Add(3 * time.Second))
				peer, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(fixture.kernelAddress(ipv6), 0)))
				if err != nil {
					test.Fatal(err)
				}
				defer peer.Close()
				peer.SetDeadline(time.Now().Add(3 * time.Second))
				storage := make([]byte, 65535)
				for index, size := range []int{1, 1200, 9000, kernelMaxDatagram} {
					payload := kernelPayload(size, uint32(index+1))
					_, err = peer.WriteToUDPAddrPort(payload, socket.LocalAddr().(*net.UDPAddr).AddrPort())
					if err != nil {
						test.Fatal(err)
					}
					n, source, readErr := socket.ReadFrom(storage)
					if readErr != nil {
						test.Fatalf("size=%d: %v", size, readErr)
					}
					if source.String() != peer.LocalAddr().String() {
						test.Fatalf("size=%d: source %s, want %s", size, source, peer.LocalAddr())
					}
					if !bytes.Equal(storage[:n], payload) {
						test.Fatalf("size=%d: received %d bytes with corrupted payload", size, n)
					}
					_, err = socket.WriteTo(payload, source)
					if err != nil {
						test.Fatal(err)
					}
					n, _, readErr = peer.ReadFrom(storage)
					if readErr != nil {
						test.Fatalf("size=%d: reply: %v", size, readErr)
					}
					if !bytes.Equal(storage[:n], payload) {
						test.Fatalf("size=%d: reply carried %d bytes with corrupted payload", size, n)
					}
				}
			})
			addressTest.Run("connected", func(test *testing.T) {
				peer, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(fixture.kernelAddress(ipv6), 0)))
				if err != nil {
					test.Fatal(err)
				}
				defer peer.Close()
				peer.SetDeadline(time.Now().Add(3 * time.Second))
				stranger, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(fixture.kernelAddress(ipv6), 0)))
				if err != nil {
					test.Fatal(err)
				}
				defer stranger.Close()
				socket, err := fixture.stack.DialUDP(netip.AddrPortFrom(fixture.kernelAddress(ipv6).Next(), 0), peer.LocalAddr().(*net.UDPAddr).AddrPort())
				if err != nil {
					test.Fatal(err)
				}
				defer socket.Close()
				socket.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = socket.Write([]byte("ping"))
				if err != nil {
					test.Fatal(err)
				}
				storage := make([]byte, 64)
				n, source, err := peer.ReadFrom(storage)
				if err != nil {
					test.Fatal(err)
				}
				if string(storage[:n]) != "ping" || source.String() != socket.LocalAddr().String() {
					test.Fatalf("kernel received %q from %s", storage[:n], source)
				}
				_, err = stranger.WriteTo([]byte("stranger"), source)
				if err != nil {
					test.Fatal(err)
				}
				_, err = peer.WriteTo([]byte("pong"), source)
				if err != nil {
					test.Fatal(err)
				}
				n, err = socket.Read(storage)
				if err != nil {
					test.Fatal(err)
				}
				if string(storage[:n]) != "pong" {
					test.Fatalf("connected socket received %q", storage[:n])
				}
				socket.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				_, err = socket.Read(storage)
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					test.Fatalf("datagram from another peer leaked into a connected socket: %v", err)
				}
			})
			addressTest.Run("refused", func(test *testing.T) {
				closedPeer, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(fixture.kernelAddress(ipv6), 0)))
				if err != nil {
					test.Fatal(err)
				}
				address := closedPeer.LocalAddr().(*net.UDPAddr).AddrPort()
				closedPeer.Close()
				socket, err := fixture.stack.DialUDP(netip.AddrPortFrom(fixture.kernelAddress(ipv6).Next(), 0), address)
				if err != nil {
					test.Fatal(err)
				}
				defer socket.Close()
				socket.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = socket.Write([]byte("anyone"))
				if err != nil {
					test.Fatal(err)
				}
				_, err = socket.Read(make([]byte, 64))
				if !errors.Is(err, syscall.ECONNREFUSED) {
					test.Fatalf("datagram to a closed port returned %v", err)
				}
			})
		})
	}
}

func TestGoMemoryMTUUpdate(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			client, server := fixture.pair(test, ipv6)
			payload := kernelPayload(4<<20, 79)
			result := make(chan error, 1)
			go func() { result <- kernelTransfer(server, client, payload, false) }()
			time.Sleep(20 * time.Millisecond)
			fixture.memoryTun.UpdateMTU(576)
			err := <-result
			if err != nil {
				test.Fatal(err)
			}
			fixture.bridge.outboundLargest.Store(0)
			client, server = fixture.pair(test, ipv6)
			err = kernelTransfer(server, client, kernelPayload(1<<20, 83), false)
			if err != nil {
				test.Fatal(err)
			}
			largest := fixture.bridge.outboundLargest.Load()
			if largest > 576 {
				test.Fatalf("stack emitted a %d byte packet after the MTU dropped to 576", largest)
			}
			fixture.memoryTun.UpdateMTU(1500)
		})
	}
}

func TestGoMemoryNoHandler(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true, noHandler: true})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(addressTest *testing.T) {
			addressTest.Run("tcp", func(test *testing.T) {
				dialer := net.Dialer{Timeout: 2 * time.Second}
				_, err := dialer.Dial("tcp", fixture.address(ipv6, 8080))
				if !errors.Is(err, syscall.ECONNREFUSED) {
					test.Fatalf("connect to a handler-less stack returned %v", err)
				}
			})
			addressTest.Run("udp", func(test *testing.T) {
				peer, err := net.Dial("udp", fixture.address(ipv6, 8080))
				if err != nil {
					test.Fatal(err)
				}
				defer peer.Close()
				peer.SetDeadline(time.Now().Add(2 * time.Second))
				_, err = peer.Write([]byte("anyone"))
				if err != nil {
					test.Fatal(err)
				}
				_, err = peer.Read(make([]byte, 64))
				if !errors.Is(err, syscall.ECONNREFUSED) {
					test.Fatalf("datagram to a handler-less stack returned %v", err)
				}
			})
			addressTest.Run("dial", func(test *testing.T) {
				listener, address := kernelListen(test, fixture, ipv6)
				conn, err := fixture.stack.DialTCP(context.Background(), fixture.kernelAddress(ipv6).Next(), address)
				if err != nil {
					test.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				server := kernelAcceptTCP(test, listener)
				err = kernelTransfer(server, conn, kernelPayload(256<<10, 11), false)
				if err != nil {
					test.Fatal(err)
				}
			})
		})
	}
}

func TestGoMemoryOutboundReply(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true, memoryOutbound: true})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			client, conn, destination := fixture.packetPair(test, ipv6)
			time.Sleep(100 * time.Millisecond)
			payload := kernelPayload(64, 97)
			options := N.NewReadWaitOptions(nil, conn)
			packet := options.NewBufferSize(len(payload))
			packet.Write(payload)
			options.PostReturn(packet)
			started := time.Now()
			err := conn.WritePacket(packet, destination)
			if err != nil {
				test.Fatal(err)
			}
			client.SetReadDeadline(time.Now().Add(time.Second))
			received := make([]byte, 1500)
			n, err := client.Read(received)
			elapsed := time.Since(started)
			if err != nil || !bytes.Equal(received[:n], payload) {
				test.Fatalf("reply: %x, %v", received[:n], err)
			}
			if elapsed > 100*time.Millisecond {
				test.Fatalf("reply reached the kernel after %v", elapsed)
			}
		})
	}
}

func TestGoMemoryOutboundBound(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true, memoryOutbound: true})
	client, conn, destination := fixture.packetPair(t, false)
	err := client.SetReadBuffer(4 << 20)
	if err != nil {
		t.Fatal(err)
	}
	fixture.bridge.pauseOutbound(true)
	options := N.NewReadWaitOptions(nil, conn)
	payload := kernelPayload(100, 113)
	sendReply := func() error {
		packet := options.NewBufferSize(len(payload))
		packet.Write(payload)
		options.PostReturn(packet)
		return conn.WritePacket(packet, destination)
	}
	capacity := len(fixture.memoryTun.datagram.packets)
	for range 4 * capacity {
		err = sendReply()
		if err != nil {
			t.Fatal(err)
		}
	}
	fixture.bridge.pauseOutbound(false)
	received := make([]byte, 1500)
	delivered := 0
	for {
		client.SetReadDeadline(time.Now().Add(time.Second))
		_, err = client.Read(received)
		if err != nil {
			break
		}
		delivered++
	}
	if delivered < capacity || delivered > capacity+fixture.memoryTun.batchSize {
		t.Fatalf("%d replies delivered after the outbound handler resumed, want between %d and %d", delivered, capacity, capacity+fixture.memoryTun.batchSize)
	}
	marker := kernelPayload(7, 131)
	packet := options.NewBufferSize(len(marker))
	packet.Write(marker)
	options.PostReturn(packet)
	err = conn.WritePacket(packet, destination)
	if err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	n, err := client.Read(received)
	if err != nil || !bytes.Equal(received[:n], marker) {
		t.Fatalf("reply after backlog: %x, %v", received[:n], err)
	}
}

func TestGoMemoryControlPriority(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true, memoryOutbound: true})
	_, conn, destination := fixture.packetPair(t, false)
	listener, address := kernelListen(t, fixture, false)
	fixture.bridge.pauseOutbound(true)
	options := N.NewReadWaitOptions(nil, conn)
	payload := kernelPayload(100, 113)
	for range 4 * len(fixture.memoryTun.datagram.packets) {
		packet := options.NewBufferSize(len(payload))
		packet.Write(payload)
		options.PostReturn(packet)
		err := conn.WritePacket(packet, destination)
		if err != nil {
			t.Fatal(err)
		}
	}
	dialed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		dialConn, err := fixture.stack.DialTCP(ctx, fixture.kernelAddress(false).Next(), address)
		if err == nil {
			dialConn.Close()
		}
		dialed <- err
	}()
	time.Sleep(100 * time.Millisecond)
	resumed := time.Now()
	fixture.bridge.pauseOutbound(false)
	server := kernelAcceptTCP(t, listener)
	server.Close()
	err := <-dialed
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(resumed); elapsed > 500*time.Millisecond {
		t.Fatalf("handshake completed %v after the link resumed, the SYN waited behind the datagram backlog", elapsed)
	}
}

func TestGoMemoryPathMTU(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1408, memoryLink: true})
	var tooBig atomic.Int32
	fixture.bridge.filterOutbound(func(packet []byte) bool {
		if header.IPVersion(packet) != header.IPv6Version || len(packet) <= header.IPv6MinimumMTU {
			return true
		}
		reply, built := buildPacketTooBig(header.IPv6(packet), header.IPv6MinimumMTU, 0)
		if built {
			tooBig.Add(1)
			fixture.memoryTun.WritePackets([][]byte{reply})
		}
		return false
	})
	t.Cleanup(func() { fixture.bridge.filterOutbound(nil) })
	for _, dialed := range []bool{true, false} {
		t.Run(fmt.Sprintf("dialed=%v", dialed), func(test *testing.T) {
			tooBig.Store(0)
			conn, kernel, _ := openConnection(test, fixture, true, dialed)
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			kernel.SetDeadline(time.Now().Add(3 * time.Second))
			payload := kernelPayload(32<<10, 151)
			written := make(chan error, 1)
			go func() {
				_, writeErr := conn.Write(payload)
				written <- writeErr
			}()
			received := make([]byte, len(payload))
			_, err := io.ReadFull(kernel, received)
			if err != nil {
				test.Fatalf("transfer over a %d byte path stalled after %d Packet Too Big messages: %v", header.IPv6MinimumMTU, tooBig.Load(), err)
			}
			err = <-written
			if err != nil {
				test.Fatal(err)
			}
			if !bytes.Equal(received, payload) {
				test.Fatal("payload corrupted")
			}
			if tooBig.Load() == 0 {
				test.Fatal("no segment exceeded the path MTU")
			}
		})
	}
}
