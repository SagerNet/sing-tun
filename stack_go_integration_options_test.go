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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

func dialKernel(t *testing.T, fixture *kernelStackFixture, ipv6 bool) (*GoConn, *net.TCPConn) {
	t.Helper()
	listener, address := kernelListen(t, fixture, ipv6)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := fixture.stack.DialTCP(ctx, fixture.kernelAddress(ipv6).Next(), address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, kernelAcceptTCP(t, listener)
}

func openConnection(t *testing.T, fixture *kernelStackFixture, ipv6 bool, dialed bool) (*GoConn, *net.TCPConn, uint16) {
	t.Helper()
	if dialed {
		conn, kernel := dialKernel(t, fixture, ipv6)
		return conn, kernel, conn.LocalAddr().(*net.TCPAddr).AddrPort().Port()
	}
	kernel, conn := fixture.pair(t, ipv6)
	return conn, kernel, kernel.RemoteAddr().(*net.TCPAddr).AddrPort().Port()
}

func connectionCases(t *testing.T, fixture *kernelStackFixture, run func(test *testing.T, conn *GoConn, kernel *net.TCPConn, port uint16)) {
	for _, ipv6 := range []bool{false, true} {
		for _, dialed := range []bool{true, false} {
			t.Run(fmt.Sprintf("ipv6=%v,dialed=%v", ipv6, dialed), func(test *testing.T) {
				conn, kernel, port := openConnection(test, fixture, ipv6, dialed)
				run(test, conn, kernel, port)
			})
		}
	}
}

type wireSegment struct {
	outbound bool
	flags    header.TCPFlags
	sequence uint32
	ack      uint32
	window   uint32
	payload  int
}

func (s wireSegment) probe() bool {
	return s.outbound && s.payload == 0 && s.flags == header.TCPFlagAck
}

type wireRecorder struct {
	access   sync.Mutex
	port     uint16
	segments []wireSegment
}

func recordWire(t *testing.T, fixture *kernelStackFixture, port uint16) *wireRecorder {
	recorder := &wireRecorder{port: port}
	fixture.bridge.observe(
		func(packet []byte) { recorder.record(packet, false) },
		func(packet []byte) { recorder.record(packet, true) },
	)
	t.Cleanup(func() { fixture.bridge.observe(nil, nil) })
	return recorder
}

func (r *wireRecorder) record(packet []byte, outbound bool) {
	var transport []byte
	switch header.IPVersion(packet) {
	case 4:
		ipHdr := header.IPv4(packet)
		if ipHdr.Protocol() != uint8(header.TCPProtocolNumber) {
			return
		}
		transport = ipHdr.Payload()
	case 6:
		ipHdr := header.IPv6(packet)
		if ipHdr.NextHeader() != uint8(header.TCPProtocolNumber) {
			return
		}
		transport = ipHdr.Payload()
	default:
		return
	}
	tcpHdr := header.TCP(transport)
	if outbound && tcpHdr.SourcePort() != r.port || !outbound && tcpHdr.DestinationPort() != r.port {
		return
	}
	segment := wireSegment{
		outbound: outbound,
		flags:    tcpHdr.Flags(),
		sequence: tcpHdr.SequenceNumber(),
		ack:      tcpHdr.AckNumber(),
		payload:  len(transport) - int(tcpHdr.DataOffset()),
	}
	if outbound {
		segment.window = uint32(tcpHdr.WindowSize()) << goLocalWindowShift
	}
	r.access.Lock()
	r.segments = append(r.segments, segment)
	r.access.Unlock()
}

func (r *wireRecorder) take() []wireSegment {
	r.access.Lock()
	defer r.access.Unlock()
	segments := r.segments
	r.segments = nil
	return segments
}

func TestGoConnKeepalive(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true})
	t.Run("vanished", func(scenario *testing.T) {
		connectionCases(scenario, fixture, func(test *testing.T, conn *GoConn, kernel *net.TCPConn, port uint16) {
			err := conn.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 500 * time.Millisecond, Interval: 500 * time.Millisecond, Count: 2})
			if err != nil {
				test.Fatal(err)
			}
			recorder := recordWire(test, fixture, port)
			fixture.bridge.pauseInbound(true)
			defer fixture.bridge.pauseInbound(false)
			start := time.Now()
			_, err = conn.Read(make([]byte, 1))
			if !errors.Is(err, syscall.ETIMEDOUT) {
				test.Fatalf("read after unanswered probes: %v", err)
			}
			if elapsed := time.Since(start); elapsed > 4*time.Second {
				test.Fatalf("keepalive gave up after %v", elapsed)
			}
			probes := 0
			reset := false
			for deadline := time.Now().Add(time.Second); !reset && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				for _, segment := range recorder.take() {
					switch {
					case segment.probe():
						probes++
					case segment.outbound && segment.flags&header.TCPFlagRst != 0:
						reset = true
					}
				}
			}
			if probes != 2 || !reset {
				test.Fatalf("sent %d probes and reset=%v before giving up on a peer that stopped answering", probes, reset)
			}
		})
	})
	t.Run("answered", func(scenario *testing.T) {
		connectionCases(scenario, fixture, func(test *testing.T, conn *GoConn, kernel *net.TCPConn, port uint16) {
			err := conn.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 100 * time.Millisecond, Interval: 100 * time.Millisecond, Count: 2})
			if err != nil {
				test.Fatal(err)
			}
			recorder := recordWire(test, fixture, port)
			time.Sleep(2 * time.Second)
			probes := 0
			answered := 0
			var awaiting []uint32
			for _, segment := range recorder.take() {
				switch {
				case segment.probe():
					probes++
					awaiting = append(awaiting, segment.sequence+1)
				case !segment.outbound && segment.payload == 0 && len(awaiting) > 0 && segment.ack == awaiting[0]:
					answered++
					awaiting = awaiting[1:]
				}
			}
			if probes < 2 || answered != probes {
				test.Fatalf("kernel answered %d of %d probes sent while idle for 2s", answered, probes)
			}
			err = kernelTransfer(conn, kernel, kernelPayload(1<<20, 5), false)
			if err != nil {
				test.Fatal("after probes:", err)
			}
		})
	})
}

func TestGoConnNoDelay(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true})
	for _, noDelay := range []bool{true, false} {
		t.Run(fmt.Sprintf("nodelay=%v", noDelay), func(scenario *testing.T) {
			connectionCases(scenario, fixture, func(test *testing.T, conn *GoConn, kernel *net.TCPConn, port uint16) {
				err := conn.SetNoDelay(noDelay)
				if err != nil {
					test.Fatal(err)
				}
				recorder := recordWire(test, fixture, port)
				fixture.bridge.pauseInbound(true)
				defer fixture.bridge.pauseInbound(false)
				for _, letter := range []byte("abcdef") {
					_, err = conn.Write([]byte{letter})
					if err != nil {
						test.Fatal(err)
					}
					time.Sleep(20 * time.Millisecond)
				}
				time.Sleep(100 * time.Millisecond)
				dataSegments := make(map[uint32]bool)
				for _, segment := range recorder.take() {
					if segment.outbound && segment.payload > 0 {
						dataSegments[segment.sequence] = true
					}
				}
				if noDelay && len(dataSegments) != 6 {
					test.Fatalf("sent %d data segments for 6 writes without delay", len(dataSegments))
				}
				if !noDelay && len(dataSegments) != 1 {
					test.Fatalf("sent %d data segments while the first byte was unacknowledged", len(dataSegments))
				}
				fixture.bridge.pauseInbound(false)
				received := make([]byte, 6)
				_, err = io.ReadFull(kernel, received)
				if err != nil {
					test.Fatal(err)
				}
				if string(received) != "abcdef" {
					test.Fatalf("kernel received %q", received)
				}
				if !noDelay {
					coalesced := false
					for _, segment := range recorder.take() {
						if segment.outbound && segment.payload == 5 {
							coalesced = true
						}
					}
					if !coalesced {
						test.Fatal("held bytes were not sent as one segment once the acknowledgement arrived")
					}
				}
			})
		})
	}
}

func TestGoConnLinger(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true})
	t.Run("abort", func(scenario *testing.T) {
		connectionCases(scenario, fixture, func(test *testing.T, conn *GoConn, kernel *net.TCPConn, port uint16) {
			_, err := conn.Write([]byte("hello"))
			if err != nil {
				test.Fatal(err)
			}
			_, err = io.ReadFull(kernel, make([]byte, 5))
			if err != nil {
				test.Fatal(err)
			}
			err = conn.SetLinger(0)
			if err != nil {
				test.Fatal(err)
			}
			conn.Close()
			_, err = kernel.Read(make([]byte, 1))
			if !errors.Is(err, syscall.ECONNRESET) {
				test.Fatalf("kernel read after linger 0 close: %v", err)
			}
		})
	})
	t.Run("prompt", func(scenario *testing.T) {
		connectionCases(scenario, fixture, func(test *testing.T, conn *GoConn, kernel *net.TCPConn, port uint16) {
			err := conn.SetLinger(3)
			if err != nil {
				test.Fatal(err)
			}
			_, err = conn.Write([]byte("x"))
			if err != nil {
				test.Fatal(err)
			}
			start := time.Now()
			conn.Close()
			if elapsed := time.Since(start); elapsed > time.Second {
				test.Fatalf("close waited %v although the peer acknowledged the FIN", elapsed)
			}
			received, err := io.ReadAll(kernel)
			if err != nil {
				test.Fatal(err)
			}
			if string(received) != "x" {
				test.Fatalf("kernel received %q", received)
			}
		})
	})
	t.Run("expire", func(scenario *testing.T) {
		connectionCases(scenario, fixture, func(test *testing.T, conn *GoConn, kernel *net.TCPConn, port uint16) {
			err := conn.SetLinger(1)
			if err != nil {
				test.Fatal(err)
			}
			fixture.bridge.pauseOutbound(true)
			defer fixture.bridge.pauseOutbound(false)
			_, err = conn.Write([]byte("x"))
			if err != nil {
				test.Fatal(err)
			}
			start := time.Now()
			conn.Close()
			elapsed := time.Since(start)
			if elapsed < time.Second || elapsed > 3*time.Second {
				test.Fatalf("close waited %v with the FIN undeliverable and linger 1s", elapsed)
			}
			fixture.bridge.pauseOutbound(false)
			received, err := io.ReadAll(kernel)
			if err != nil {
				test.Fatal(err)
			}
			if string(received) != "x" {
				test.Fatalf("kernel received %q", received)
			}
		})
	})
}

func TestGoConnBuffers(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true})
	t.Run("read", func(scenario *testing.T) {
		connectionCases(scenario, fixture, func(test *testing.T, conn *GoConn, kernel *net.TCPConn, port uint16) {
			err := conn.SetReadBuffer(goSlabSize)
			if err != nil {
				test.Fatal(err)
			}
			recorder := recordWire(test, fixture, port)
			payload := kernelPayload(4<<20, 11)
			err = kernelTransfer(kernel, conn, payload, false)
			if err != nil {
				test.Fatal(err)
			}
			var first *wireSegment
			var largest uint32
			for _, segment := range recorder.take() {
				if !segment.outbound {
					continue
				}
				if first == nil {
					first = &segment
				}
				if segment.ack-first.ack < uint32(len(payload)/2) {
					continue
				}
				largest = max(largest, segment.window)
			}
			if largest == 0 || largest > goSlabSize {
				test.Fatalf("advertised a %d byte window in the second half of the transfer with a %d byte read buffer", largest, goSlabSize)
			}
		})
	})
	t.Run("write", func(scenario *testing.T) {
		connectionCases(scenario, fixture, func(test *testing.T, conn *GoConn, kernel *net.TCPConn, port uint16) {
			err := conn.SetWriteBuffer(goSlabSize)
			if err != nil {
				test.Fatal(err)
			}
			fixture.bridge.pauseOutbound(true)
			defer fixture.bridge.pauseOutbound(false)
			conn.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
			n, err := conn.Write(kernelPayload(4<<20, 13))
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				test.Fatalf("write against a stalled link: %v", err)
			}
			if n != goSlabSize {
				test.Fatalf("buffered %d bytes with a %d byte write buffer", n, goSlabSize)
			}
		})
	})
}

func TestGoUDPReadBuffer(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: true})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			socket, err := fixture.stack.ListenUDP(netip.AddrPortFrom(fixture.kernelAddress(ipv6).Next(), 0))
			if err != nil {
				test.Fatal(err)
			}
			defer socket.Close()
			err = socket.SetReadBuffer(8192)
			if err != nil {
				test.Fatal(err)
			}
			peer, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(fixture.kernelAddress(ipv6), 0)))
			if err != nil {
				test.Fatal(err)
			}
			defer peer.Close()
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			target := socket.LocalAddr().(*net.UDPAddr).AddrPort()
			for index := range 64 {
				_, err = peer.WriteToUDPAddrPort(kernelPayload(1000, uint32(index+1)), target)
				if err != nil {
					test.Fatal(err)
				}
			}
			time.Sleep(200 * time.Millisecond)
			storage := make([]byte, 2000)
			received := 0
			for {
				socket.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				n, _, readErr := socket.ReadFromUDPAddrPort(storage)
				if readErr != nil {
					if !errors.Is(readErr, os.ErrDeadlineExceeded) {
						test.Fatal(readErr)
					}
					break
				}
				if !bytes.Equal(storage[:n], kernelPayload(1000, uint32(received+1))) {
					test.Fatalf("datagram %d out of order or corrupted", received)
				}
				received++
			}
			if received == 0 || received*1000 > 8192 {
				test.Fatalf("queued %d datagrams of 1000 bytes with an 8192 byte read buffer", received)
			}
			payload := kernelPayload(1000, 99)
			_, err = peer.WriteToUDPAddrPort(payload, target)
			if err != nil {
				test.Fatal(err)
			}
			socket.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, source, err := socket.ReadFromUDPAddrPort(storage)
			if err != nil {
				test.Fatal("after draining the queue:", err)
			}
			if !bytes.Equal(storage[:n], payload) {
				test.Fatalf("datagram after draining carried %d bytes with corrupted payload", n)
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
