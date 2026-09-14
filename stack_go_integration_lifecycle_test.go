//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

func TestGoKernelHandshake(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, action := range []string{"accept", "reject", "close"} {
			t.Run(fmt.Sprintf("ipv6=%v/action=%s", ipv6, action), func(test *testing.T) {
				test.Parallel()
				observed := make(chan *GoConn, 1)
				var observe sync.Once
				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				fixture := newKernelStackFixture(test, kernelStackConfig{mtu: 1500, dialer: net.Dialer{Timeout: 5 * time.Second}, handshake: func(conn *GoConn) error {
					observe.Do(func() { observed <- conn })
					test.Cleanup(func() { conn.Close() })
					<-release
					switch action {
					case "reject":
						return conn.HandshakeFailure(kernelConnectionRefused)
					case "close":
						return conn.Close()
					default:
						return conn.HandshakeSuccess()
					}
				}})
				test.Cleanup(unblock)
				port := uint16(20000 + fixture.port.Add(1))
				fixture.access.Lock()
				fixture.tcp[port] = make(chan kernelAccept, 8)
				fixture.access.Unlock()
				type dialResult struct {
					conn net.Conn
					err  error
				}
				dialed := make(chan dialResult, 1)
				go func() {
					conn, err := fixture.dialer.Dial("tcp", fixture.address(ipv6, port))
					dialed <- dialResult{conn: conn, err: err}
				}()
				var server *GoConn
				select {
				case server = <-observed:
				case <-time.After(time.Second):
					test.Fatal("connection did not reach the application")
				}
				select {
				case result := <-dialed:
					if result.conn != nil {
						result.conn.Close()
					}
					test.Fatalf("dial completed before application decision: %v", result.err)
				case <-time.After(80 * time.Millisecond):
				}
				unblock()
				select {
				case result := <-dialed:
					if action != "accept" {
						if result.conn != nil {
							result.conn.Close()
						}
						if !errors.Is(result.err, kernelConnectionRefused) {
							test.Fatalf("application %s: %v", action, result.err)
						}
						return
					}
					if result.err != nil {
						test.Fatal(result.err)
					}
					defer result.conn.Close()
					result.conn.SetDeadline(time.Now().Add(3 * time.Second))
					err := kernelTransfer(server, result.conn, kernelPayload(32769, 157), true)
					if err != nil {
						test.Fatal("accepted stream:", err)
					}
				case <-time.After(6 * time.Second):
					test.Fatal("application decision did not complete the dial")
				}
			})
		}
	}
}

func TestGoKernelHalfClose(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v/close_read", ipv6), func(test *testing.T) {
			test.Parallel()
			client, server := fixture.pair(test, ipv6)
			completed := make(chan kernelIOResult, 1)
			go func() {
				n, err := server.Read(make([]byte, 1))
				completed <- kernelIOResult{n: n, err: err}
			}()
			select {
			case result := <-completed:
				test.Fatalf("read did not wait: %+v", result)
			case <-time.After(40 * time.Millisecond):
			}
			err := server.CloseRead()
			if err != nil {
				test.Fatal(err)
			}
			select {
			case result := <-completed:
				if result.n != 0 || result.err != io.EOF {
					test.Fatalf("CloseRead: %+v", result)
				}
			case <-time.After(time.Second):
				test.Fatal("CloseRead did not wake reader")
			}
			uploaded := make(chan error, 1)
			go func() {
				_, writeErr := client.Write(kernelPayload(1<<20, 173))
				if writeErr == nil {
					writeErr = client.CloseWrite()
				}
				uploaded <- writeErr
			}()
			err = kernelTransfer(server, client, kernelPayload(256<<10, 179), true)
			if err != nil {
				test.Fatal("write after CloseRead:", err)
			}
			select {
			case err = <-uploaded:
				if err != nil {
					test.Fatal("peer upload after CloseRead:", err)
				}
			case <-time.After(time.Second):
				test.Fatal("discarded input blocked the peer")
			}
		})
		t.Run(fmt.Sprintf("ipv6=%v/upstream_reset", ipv6), func(test *testing.T) {
			test.Parallel()
			client, upstream, _, _ := fixture.splicePair(test, ipv6)
			marker := kernelPayload(1024, 181)
			_, err := upstream.Write(marker)
			if err != nil {
				test.Fatal(err)
			}
			data := make([]byte, len(marker))
			_, err = io.ReadFull(client, data)
			if err != nil || !bytes.Equal(data, marker) {
				test.Fatal("upstream data before reset:", err)
			}
			upstream.SetLinger(0)
			upstream.Close()
			client.SetReadDeadline(time.Now().Add(time.Second))
			_, err = client.Read(data[:1])
			if !errors.Is(err, kernelConnectionReset) {
				test.Fatalf("upstream reset: %v", err)
			}
		})
	}
}

func TestGoKernelClose(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	t.Run("reset", func(scenarioTest *testing.T) {
		fixture := newKernelStackFixture(scenarioTest, kernelStackConfig{mtu: 1500})
		for _, ipv6 := range []bool{false, true} {
			client, conn := fixture.pair(scenarioTest, ipv6)
			client.SetLinger(0)
			client.Close()
			_, err := conn.Read(make([]byte, 1))
			if !errors.Is(err, syscall.ECONNRESET) {
				scenarioTest.Errorf("reset ipv6=%v: %v", ipv6, err)
			}
		}
	})
	t.Run("drain_after_fin", func(scenarioTest *testing.T) {
		fixture := newKernelStackFixture(scenarioTest, kernelStackConfig{mtu: 1500})
		for _, ipv6 := range []bool{false, true} {
			client, conn := fixture.pair(scenarioTest, ipv6)
			payload := kernelPayload(32769, 41)
			_, err := client.Write(payload)
			if err != nil {
				scenarioTest.Fatal(err)
			}
			client.CloseWrite()
			conn.CloseWrite()
			_, err = io.ReadAll(client)
			if err != nil {
				scenarioTest.Fatal(err)
			}
			data, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(data, payload) {
				scenarioTest.Fatalf("drain ipv6=%v bytes=%d: %v", ipv6, len(data), err)
			}
		}
	})
	for _, splice := range []bool{false, true} {
		t.Run(fmt.Sprintf("busy_shutdown/splice=%v", splice), func(scenarioTest *testing.T) {
			fixture := newKernelStackFixture(scenarioTest, kernelStackConfig{
				mtu: 1500, multiQueue: runtime.GOOS == "linux",
				upstreamSocketBuffer: 4096,
				dialer: net.Dialer{Control: func(_, _ string, rawConn syscall.RawConn) error {
					var optionErr error
					err := rawConn.Control(func(descriptor uintptr) {
						optionErr = kernelSetSocketBuffers(descriptor, 4096)
					})
					return E.Errors(err, optionErr)
				}},
			})
			payload := kernelPayload(32749, 33)
			type pendingResult struct {
				connection int
				operation  string
				kernelIOResult
			}
			completed := make(chan pendingResult, 32)
			reading := make(chan kernelIOResult, 16)
			var progress [16]atomic.Int64
			for index := range 16 {
				var client, conn net.Conn
				if splice {
					client, conn, _, _ = fixture.splicePair(scenarioTest, index%2 != 0)
				} else {
					client, conn = fixture.pair(scenarioTest, index%2 != 0)
				}
				client.SetDeadline(time.Now().Add(2 * time.Second))
				conn.SetDeadline(time.Time{})
				go func() {
					for {
						n, err := conn.Write(payload)
						progress[index].Add(int64(n))
						if err != nil {
							completed <- pendingResult{connection: index, operation: "write", kernelIOResult: kernelIOResult{n: n, err: err}}
							return
						}
					}
				}()
				go func() {
					var probe [1]byte
					n, err := io.ReadFull(conn, probe[:])
					if err == nil && probe[0] != 0x71 {
						err = E.New("shutdown read probe corrupted")
					}
					reading <- kernelIOResult{n: n, err: err}
					n, err = conn.Read(probe[:])
					completed <- pendingResult{connection: index, operation: "read", kernelIOResult: kernelIOResult{n: n, err: err}}
				}()
				_, err := client.Write([]byte{0x71})
				if err != nil {
					scenarioTest.Fatal("start blocked reader:", err)
				}
				var probe [1]byte
				_, err = io.ReadFull(client, probe[:])
				if err != nil || probe[0] != payload[0] {
					scenarioTest.Fatalf("start blocked writer: byte=%x error=%v", probe[0], err)
				}
			}
			for range 16 {
				select {
				case result := <-reading:
					if result.n != 1 || result.err != nil {
						scenarioTest.Fatalf("start blocked reader: %+v", result)
					}
				case <-time.After(time.Second):
					scenarioTest.Fatal("reader did not consume peer probe")
				}
			}
			var previousProgress [16]int64
			stalledAt := time.Now()
			backpressureDeadline := time.NewTimer(time.Second)
			defer backpressureDeadline.Stop()
			observations := time.NewTicker(10 * time.Millisecond)
			defer observations.Stop()
			for time.Since(stalledAt) < 40*time.Millisecond {
				select {
				case result := <-completed:
					scenarioTest.Fatalf("I/O completed before stack shutdown: %+v", result)
				case <-observations.C:
					for index := range progress {
						accepted := progress[index].Load()
						if accepted != previousProgress[index] {
							previousProgress[index] = accepted
							stalledAt = time.Now()
						}
					}
				case <-backpressureDeadline.C:
					scenarioTest.Fatal("writers did not encounter backpressure within 1 second")
				}
			}
			closed := make(chan error, 1)
			go func() { closed <- fixture.stack.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					scenarioTest.Fatal(err)
				}
			case <-time.After(time.Second):
				scenarioTest.Fatal("stack close did not complete within 1 second")
			}
			deadline := time.NewTimer(2 * time.Second)
			defer deadline.Stop()
			for range 32 {
				select {
				case result := <-completed:
					if !(E.IsClosed(result.err) || errors.Is(result.err, kernelConnectionReset)) || E.IsTimeout(result.err) ||
						result.operation == "read" && result.n != 0 ||
						result.operation == "write" && result.n >= len(payload) {
						scenarioTest.Errorf("pending I/O after stack shutdown: %+v", result)
					}
				case <-deadline.C:
					scenarioTest.Fatal("pending I/O did not unblock after stack shutdown")
				}
			}
		})
	}
}

type kernelIOResult struct {
	n   int
	err error
}

func kernelCommand(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.WaitDelay = time.Second
	return command.CombinedOutput()
}

func TestGoKernelDeadline(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 9000})
	for _, ipv6 := range []bool{false, true} {
		for _, operation := range []string{"read", "wait_read", "write"} {
			for _, change := range []string{"advance", "extend", "clear", "close"} {
				t.Run(fmt.Sprintf("ipv6=%v/operation=%s/change=%s", ipv6, operation, change), func(test *testing.T) {
					test.Parallel()
					client, server := fixture.pair(test, ipv6)
					writing := operation == "write"
					payload := []byte{0x71}
					setDeadline := server.SetReadDeadline
					if writing {
						payload = kernelPayload(8<<20, 151)
						setDeadline = server.SetWriteDeadline
						err := client.SetReadBuffer(4096)
						if err != nil {
							test.Fatal(err)
						}
					}
					var waiter N.ReadWaiter
					if operation == "wait_read" {
						var created bool
						waiter, created = bufio.CreateReadWaiter(server)
						if !created {
							test.Fatal("missing read waiter")
						}
						waiter.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 91, RearHeadroom: 73})
					}
					read := func() kernelIOResult {
						if waiter != nil {
							buffer, err := waiter.WaitReadBuffer()
							result := kernelIOResult{err: err}
							if buffer != nil {
								result.n = buffer.Len()
								if !bytes.Equal(buffer.Bytes(), payload) {
									result.err = E.New("read waiter payload mismatch")
								}
								buffer.ExtendHeader(91)
								buffer.Extend(73)
								buffer.Release()
							}
							return result
						}
						data := make([]byte, len(payload))
						n, err := io.ReadFull(server, data)
						if err == nil && !bytes.Equal(data, payload) {
							err = E.New("read payload mismatch")
						}
						return kernelIOResult{n: n, err: err}
					}
					original := time.Now().Add(300 * time.Millisecond)
					if change == "advance" || change == "close" {
						original = time.Now().Add(4 * time.Second)
					}
					setDeadline(original)
					completed := make(chan kernelIOResult, 1)
					go func() {
						if writing {
							n, err := server.Write(payload)
							completed <- kernelIOResult{n: n, err: err}
						} else {
							completed <- read()
						}
					}()
					select {
					case result := <-completed:
						test.Fatalf("I/O did not wait: %+v", result)
					case <-time.After(40 * time.Millisecond):
					}
					switch change {
					case "advance":
						setDeadline(time.Now())
					case "extend":
						setDeadline(time.Now().Add(4 * time.Second))
					case "clear":
						setDeadline(time.Time{})
					case "close":
						server.Close()
					}
					accepted := 0
					if change == "advance" || change == "close" {
						select {
						case result := <-completed:
							accepted = result.n
							if accepted < 0 || accepted >= len(payload) {
								test.Fatalf("blocked I/O accepted %d/%d bytes", accepted, len(payload))
							}
							if change == "advance" && !errors.Is(result.err, os.ErrDeadlineExceeded) {
								test.Fatalf("updated deadline: %v", result.err)
							}
							if change == "close" && (!E.IsClosed(result.err) || E.IsTimeout(result.err)) {
								test.Fatalf("close pending I/O: %v", result.err)
							}
						case <-time.After(time.Second):
							test.Fatal("pending I/O did not react to deadline/close")
						}
						if change == "close" {
							return
						}
						setDeadline(time.Now().Add(4 * time.Second))
						go func() {
							if writing {
								n, err := server.Write(payload[accepted:])
								completed <- kernelIOResult{n: n + accepted, err: err}
							} else {
								completed <- read()
							}
						}()
					} else {
						select {
						case result := <-completed:
							test.Fatalf("old deadline still affected I/O: %+v", result)
						case <-time.After(time.Until(original.Add(40 * time.Millisecond))):
						}
					}
					if writing {
						client.SetReadBuffer(4 << 20)
						data := make([]byte, len(payload))
						n, err := io.ReadFull(client, data)
						if err != nil || !bytes.Equal(data, payload) {
							select {
							case result := <-completed:
								test.Logf("writer after deadline change: accepted=%d: %v", result.n, result.err)
							default:
							}
							test.Fatalf("write after deadline change: received=%d/%d accepted_before_change=%d: %v", n, len(payload), accepted, err)
						}
					} else {
						_, err := client.Write(payload)
						if err != nil {
							test.Fatal(err)
						}
					}
					select {
					case result := <-completed:
						if result.err != nil || result.n != len(payload) {
							test.Fatalf("completed I/O: %+v", result)
						}
					case <-time.After(time.Second):
						test.Fatal("I/O remained blocked after peer resumed")
					}
				})
			}
		}
	}
}
