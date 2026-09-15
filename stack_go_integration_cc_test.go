//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"net"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func kernelTCPResult[T any](t *testing.T, result <-chan T, description string) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(kernelTCPTimeout):
		t.Fatalf("%s timed out", description)
		var value T
		return value
	}
}

func kernelTCPWrite(conn net.Conn, payload []byte, buffered bool) error {
	if buffered {
		buffer := buf.NewSize(len(payload))
		copy(buffer.Extend(len(payload)), payload)
		return conn.(N.ExtendedWriter).WriteBuffer(buffer)
	}
	n, err := conn.Write(payload)
	if err == nil && n != len(payload) {
		return io.ErrShortWrite
	}
	return err
}

func TestGoKernelTCPLifecycle(t *testing.T) {
	for _, congestion := range slices.Sorted(maps.Keys(goCongestionRegistry)) {
		t.Run(congestion, func(algorithmTest *testing.T) {
			fixture, traffic := newKernelTCPFixture(algorithmTest, kernelStackConfig{mtu: 1500, congestion: congestion}, kernelTCPConfig{})
			for _, ipv6 := range []bool{false, true} {
				for _, writer := range []string{"write", "buffer", "splice"} {
					for _, scenario := range []struct {
						name      string
						size      int
						peerFirst bool
						drain     bool
					}{
						{name: "empty"},
						{name: "empty_peer_first", peerFirst: true},
						{name: "pending_data", size: 16385},
						{name: "acknowledged_data", size: 16385, drain: true},
						{name: "peer_first", size: 16385, peerFirst: true},
					} {
						algorithmTest.Run(fmt.Sprintf("ipv6=%v/%s/%s", ipv6, writer, scenario.name), func(test *testing.T) {
							test.Parallel()
							client, server, conn := traffic.pair(test, fixture, ipv6, writer)
							if scenario.peerFirst {
								err := kernelTransfer(client, server, kernelPayload(37, 11), false)
								if err != nil {
									test.Fatal(err)
								}
							}
							payload := kernelPayload(scenario.size, 13)
							if scenario.drain {
								written := make(chan error, 1)
								go func() { written <- kernelTCPWrite(server, payload, writer == "buffer") }()
								received := make([]byte, len(payload))
								_, err := io.ReadFull(client, received)
								if err != nil || !bytes.Equal(received, payload) {
									test.Fatalf("stream before close: %v", err)
								}
								err = kernelTCPResult(test, written, "write before close")
								if err != nil {
									test.Fatal(err)
								}
								traffic.await(test, conn, "drain before close", func(flow kernelTCPFlow) bool {
									return flow.acked >= uint64(len(payload)+1) && conn.sendUnacked.Load() == conn.sentTail.Load()
								})
								payload = nil
							}
							err := kernelTransfer(server, client, payload, writer == "buffer")
							if err != nil {
								test.Fatal("server half-close:", err)
							}
							if !scenario.peerFirst {
								err = kernelTransfer(client, server, kernelPayload(37, 17), false)
								if err != nil {
									test.Fatal("reply after half-close:", err)
								}
							}
							traffic.await(test, conn, "graceful close", func(flow kernelTCPFlow) bool {
								return flow.fin != 0 && flow.acked >= flow.fin && flow.peerFIN && conn.closed()
							})
						})
					}
				}
			}
		})
	}
}

func TestGoKernelTCPSendBudget(t *testing.T) {
	for _, congestion := range slices.Sorted(maps.Keys(goCongestionRegistry)) {
		for _, phase := range []string{"ack", "control"} {
			for _, overlap := range []int{0, goInitialWindow / 2, goInitialWindow - 1} {
				for _, buffered := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/overlap=%d/buffer=%v", congestion, phase, overlap, buffered), func(test *testing.T) {
						test.Parallel()
						var stage atomic.Int32
						var window atomic.Uint32
						entered := make(chan struct{})
						resume := make(chan struct{})
						idle := make(chan struct{})
						release := make(chan struct{})
						checkpoint := func(current string, conn *GoConn) {
							if current == phase && stage.CompareAndSwap(0, 1) {
								close(entered)
								<-resume
							}
							if current == "controlled" && stage.CompareAndSwap(1, 2) {
								window.Store(conn.congestionWindow)
							}
							if (current == "idle" || current == "receive") && stage.CompareAndSwap(2, 3) {
								close(idle)
								<-release
							}
						}
						fixture, traffic := newKernelTCPFixture(test, kernelStackConfig{mtu: 1500, congestion: congestion}, kernelTCPConfig{checkpoint: checkpoint})
						resumeOnce := sync.OnceFunc(func() { close(resume) })
						releaseOnce := sync.OnceFunc(func() { close(release) })
						test.Cleanup(resumeOnce)
						test.Cleanup(releaseOnce)
						client, server := fixture.pair(test, false)
						mss := int(server.effectiveMSS.Load())
						err := kernelTCPWrite(server, kernelPayload(mss, 19), buffered)
						if err != nil {
							test.Fatal(err)
						}
						_, err = io.ReadFull(client, make([]byte, mss))
						if err != nil {
							test.Fatal(err)
						}
						kernelTCPResult(test, entered, "ACK checkpoint")
						overlapping := kernelPayload(overlap*mss, 23)
						err = kernelTCPWrite(server, overlapping, buffered)
						resumeOnce()
						if err != nil {
							test.Fatal(err)
						}
						kernelTCPResult(test, idle, "ACK completion")
						allowance := int(window.Load()) * mss
						payload := kernelPayload(2*allowance, 29)
						err = kernelTCPWrite(server, payload, buffered)
						if err != nil {
							test.Fatal(err)
						}
						flow := traffic.snapshot(server.key)
						if flow.failure != "" || flow.sent-flow.acked > uint64(allowance) {
							test.Fatalf("send budget: window=%d bytes, unacknowledged wire data=%d bytes, failure=%q; recent TCP events: %+v", allowance, flow.sent-flow.acked, flow.failure, flow.events)
						}
						releaseOnce()
						expected := slices.Concat(overlapping, payload)
						received := make([]byte, len(expected))
						_, err = io.ReadFull(client, received)
						if err != nil || !bytes.Equal(received, expected) {
							test.Fatalf("stream after ACK backpressure: %v", err)
						}
						traffic.await(test, server, "send budget stream ACK processing", func(flow kernelTCPFlow) bool {
							return flow.processed >= uint64(1+mss+len(expected))
						})
					})
				}
			}
		}
	}
}

func TestGoKernelTCPWaiting(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previous)
	for _, congestion := range slices.Sorted(maps.Keys(goCongestionRegistry)) {
		for _, buffered := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/buffer=%v", congestion, buffered), func(test *testing.T) {
				var stage atomic.Int32
				ready := make(chan struct{})
				checkpoint := func(phase string, _ *GoConn) {
					if phase == "controlled" {
						stage.CompareAndSwap(0, 1)
					}
					if phase == "idle" && stage.CompareAndSwap(1, 2) {
						close(ready)
					}
				}
				fixture, traffic := newKernelTCPFixture(test, kernelStackConfig{mtu: 1500, congestion: congestion}, kernelTCPConfig{receiveDelay: 100 * time.Millisecond, checkpoint: checkpoint})
				client, server := fixture.pair(test, false)
				size := goInitialWindow * int(server.effectiveMSS.Load())
				warmup := kernelPayload(size, 31)
				payload := kernelPayload(2*size, 37)
				readResult := make(chan error, 1)
				go func() {
					received := make([]byte, len(warmup)+len(payload))
					_, readErr := io.ReadFull(client, received)
					if readErr == nil && !bytes.Equal(received, slices.Concat(warmup, payload)) {
						readErr = io.ErrUnexpectedEOF
					}
					readResult <- readErr
				}()
				err := kernelTCPWrite(server, warmup, buffered)
				if err != nil {
					test.Fatal(err)
				}
				traffic.await(test, server, "warmup ACK", func(flow kernelTCPFlow) bool { return flow.acked >= uint64(size+1) })
				kernelTCPResult(test, ready, "warmup congestion update")
				cpuStart := kernelProcessCPU(test)
				start := time.Now()
				err = kernelTCPWrite(server, payload, buffered)
				if err != nil {
					test.Fatal(err)
				}
				err = kernelTCPResult(test, readResult, "paced stream delivery")
				if err != nil {
					test.Fatal(err)
				}
				if server.congestion.pacing {
					flow := traffic.snapshot(server.key)
					var first, last time.Duration
					var delivered, rate uint64
					for _, event := range flow.events {
						if !event.outgoing || event.sequence < uint64(size+1) || event.end == event.sequence {
							continue
						}
						if delivered == 0 {
							first = event.at
						}
						last = event.at
						delivered += event.end - event.sequence
						rate = max(rate, event.rate)
					}
					allowed := rate*uint64(last-first+2*time.Millisecond)/uint64(time.Second) + 2*uint64(server.effectiveMSS.Load())
					if delivered == 0 || delivered > allowed {
						test.Errorf("pacing envelope: sent=%d bytes over %s at up to %d bytes/s, allowed=%d; recent TCP events: %+v", delivered, last-first, rate, allowed, flow.events)
					}
				}
				traffic.await(test, server, "paced stream ACK processing", func(flow kernelTCPFlow) bool { return flow.processed >= uint64(3*size+1) })
				elapsed := time.Since(start)
				cpu := kernelProcessCPU(test) - cpuStart
				if cpu > max(20*time.Millisecond, elapsed/3) {
					test.Errorf("transfer waiting consumed CPU: stream=%d bytes elapsed=%s CPU=%s", len(payload), elapsed, cpu)
				}
			})
		}
	}
}

func kernelTCPRecoveryFilter(pattern string, start, end uint64, mss, round int) func(kernelTCPEvent) kernelTCPAction {
	attempts := make(map[uint64]int)
	highestACK := start
	ackDropped := false
	return func(event kernelTCPEvent) kernelTCPAction {
		if !event.outgoing {
			if event.flags != header.TCPFlagAck {
				return kernelTCPAction{}
			}
			duplicate := event.ack == highestACK
			highestACK = max(highestACK, event.ack)
			if pattern == "duplicate_ack" && duplicate {
				return kernelTCPAction{copies: 1 << (round + 1)}
			}
			if pattern == "ack_loss" && !ackDropped {
				ackDropped = true
				return kernelTCPAction{drop: true}
			}
			return kernelTCPAction{}
		}
		if event.sequence < start || event.sequence >= end || event.end <= event.sequence {
			return kernelTCPAction{}
		}
		attempts[event.sequence]++
		if attempts[event.sequence] != 1 {
			return kernelTCPAction{}
		}
		segment := (event.sequence - start) / uint64(mss)
		switch pattern {
		case "tail":
			return kernelTCPAction{drop: event.end == end}
		case "head":
			return kernelTCPAction{drop: segment == 0}
		case "burst", "duplicate_ack":
			return kernelTCPAction{drop: segment < 2}
		case "holes":
			return kernelTCPAction{drop: segment%3 == 0}
		case "reorder":
			if segment%3 == 0 {
				return kernelTCPAction{delay: 10 * time.Millisecond}
			}
		}
		return kernelTCPAction{}
	}
}

func TestGoKernelTCPRecovery(t *testing.T) {
	for _, congestion := range slices.Sorted(maps.Keys(goCongestionRegistry)) {
		for _, negotiation := range []struct {
			name   string
			config kernelTCPConfig
		}{
			{name: "sack_timestamps"},
			{name: "sack", config: kernelTCPConfig{disableTimestamps: true}},
			{name: "legacy", config: kernelTCPConfig{disableSACK: true, disableTimestamps: true}},
		} {
			t.Run(congestion+"/"+negotiation.name, func(configTest *testing.T) {
				configTest.Parallel()
				fixture, traffic := newKernelTCPFixture(configTest, kernelStackConfig{mtu: 1500, congestion: congestion}, negotiation.config)
				for _, ipv6 := range []bool{false, true} {
					for _, writer := range []string{"write", "buffer", "splice"} {
						for _, pattern := range []string{"tail", "head", "burst", "holes", "reorder", "duplicate_ack", "ack_loss", "fin"} {
							configTest.Run(fmt.Sprintf("ipv6=%v/%s/%s", ipv6, writer, pattern), func(test *testing.T) {
								test.Parallel()
								client, sender, conn := traffic.pair(test, fixture, ipv6, writer)
								mss := int(conn.effectiveMSS.Load())
								start := uint64(1)
								for round := range 4 {
									segments := 8
									if pattern == "tail" && round > 0 {
										segments = 1
									}
									length := segments*mss - max(round-1, 0)*mss/3
									end := start + uint64(length)
									if round > 0 {
										traffic.setFilter(conn, kernelTCPRecoveryFilter(pattern, start, end, mss, round))
									}
									payload := kernelPayload(length, uint32(61+round))
									client.SetReadDeadline(time.Now().Add(15 * time.Second))
									sender.SetWriteDeadline(time.Now().Add(15 * time.Second))
									err := kernelTCPWrite(sender, payload, writer == "buffer")
									if err != nil {
										test.Fatal("write:", err)
									}
									received := make([]byte, length)
									n, readErr := io.ReadFull(client, received)
									if readErr != nil || !bytes.Equal(received, payload) {
										flow := traffic.snapshot(conn.key)
										test.Fatalf("round %d: delivered %d/%d bytes: %v; invariant=%q; recent TCP events: %+v", round, n, length, readErr, flow.failure, flow.events[max(0, len(flow.events)-16):])
									}
									traffic.await(test, conn, "transfer acknowledgement", func(flow kernelTCPFlow) bool { return flow.processed >= end })
									traffic.setFilter(conn, nil)
									start = end
								}
								if pattern == "fin" {
									dropped := false
									traffic.setFilter(conn, func(event kernelTCPEvent) kernelTCPAction {
										if event.outgoing && event.flags&header.TCPFlagFin != 0 && !dropped {
											dropped = true
											return kernelTCPAction{drop: true}
										}
										return kernelTCPAction{}
									})
								}
								client.SetReadDeadline(time.Now().Add(kernelTCPTimeout))
								err := N.CloseWrite(sender)
								if err != nil {
									test.Fatal(err)
								}
								var extra [1]byte
								_, err = client.Read(extra[:])
								if err != io.EOF {
									test.Fatalf("stream end: %v", err)
								}
								flow := traffic.await(test, conn, "FIN acknowledgement", func(flow kernelTCPFlow) bool { return flow.fin != 0 && flow.acked >= flow.fin })
								if flow.faults == 0 {
									test.Fatal("transfer completed without exercising the network fault")
								}
							})
						}
					}
				}
			})
		}
	}
}

func TestGoKernelTCPTransmitLifetime(t *testing.T) {
	devices := make(chan struct{}, 8)
	for _, congestion := range slices.Sorted(maps.Keys(goCongestionRegistry)) {
		for _, ipv6 := range []bool{false, true} {
			for _, writer := range []string{"write", "buffer", "splice"} {
				for _, shutdown := range []string{"peer_reset", "stack_close"} {
					for _, shape := range []string{"first", "short", "partial", "multiple"} {
						t.Run(fmt.Sprintf("%s/ipv6=%v/%s/%s/%s", congestion, ipv6, writer, shutdown, shape), func(test *testing.T) {
							test.Parallel()
							devices <- struct{}{}
							test.Cleanup(func() { <-devices })
							fixture, traffic := newKernelTCPFixture(test, kernelStackConfig{mtu: 1500, congestion: congestion}, kernelTCPConfig{})
							client, sender, conn := traffic.pair(test, fixture, ipv6, writer)
							barrier := newKernelTCPBarrier(test)
							mss := int(conn.effectiveMSS.Load())
							prefix := mss
							length := 1
							switch shape {
							case "first":
								prefix = 0
							case "partial":
								length = mss - 1
							case "multiple":
								length = 2*mss + 1
							}
							paused := false
							traffic.setFilter(conn, func(event kernelTCPEvent) kernelTCPAction {
								if !event.outgoing && event.flags == header.TCPFlagAck {
									return kernelTCPAction{drop: true}
								}
								if event.outgoing && event.end > event.sequence && event.sequence >= uint64(1+prefix) && !paused {
									paused = true
									return kernelTCPAction{pause: barrier}
								}
								return kernelTCPAction{}
							})
							if prefix > 0 {
								err := kernelTCPWrite(sender, kernelPayload(prefix, 71), writer == "buffer")
								if err != nil {
									test.Fatal(err)
								}
								_, err = io.ReadFull(client, make([]byte, prefix))
								if err != nil {
									test.Fatal(err)
								}
							}
							written := make(chan error, 1)
							go func() { written <- kernelTCPWrite(sender, kernelPayload(length, 73), writer == "buffer") }()
							kernelTCPResult(test, barrier.entered, "device write")
							closed := make(chan error, 1)
							go func() {
								if shutdown == "stack_close" {
									closed <- fixture.stack.Close()
									return
								}
								closeErr := client.SetLinger(0)
								if closeErr == nil {
									closeErr = client.Close()
								}
								closed <- closeErr
							}()
							if shutdown == "stack_close" {
								traffic.await(test, conn, "stack shutdown started", func(kernelTCPFlow) bool { return fixture.stack.closed.Load() })
							} else {
								err := kernelTCPResult(test, closed, "peer socket reset")
								if err != nil {
									test.Fatal(err)
								}
							}
							flow := traffic.snapshot(conn.key)
							if flow.writes == 0 || flow.released || flow.failure != "" {
								test.Fatalf("shutdown did not overlap an active device write: writes=%d released=%v failure=%q", flow.writes, flow.released, flow.failure)
							}
							barrier.once.Do(func() { close(barrier.resume) })
							kernelTCPResult(test, written, "write cancellation")
							if shutdown == "stack_close" {
								err := kernelTCPResult(test, closed, "stack shutdown")
								if err != nil {
									test.Fatal(err)
								}
							}
							traffic.await(test, conn, "connection reclamation", func(flow kernelTCPFlow) bool { return flow.released })
						})
					}
				}
			}
		}
	}
}
