//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestGoKernelPacketFragments(t *testing.T) {
	configs := []kernelStackConfig{{mtu: 1500}}
	if runtime.GOOS == "linux" {
		configs = append(configs, kernelStackConfig{mtu: 1500, multiQueue: true}, kernelStackConfig{mtu: 1500, gso: true, multiQueue: true})
	}
	for _, config := range configs {
		t.Run(fmt.Sprintf("gso=%v/mq=%v", config.gso, config.multiQueue), func(configTest *testing.T) {
			fixture := newKernelStackFixture(configTest, config)
			for _, ipv6 := range []bool{false, true} {
				configTest.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
					test.Parallel()
					const sessions = 4
					for phase := range 4 {
						start := make(chan struct{})
						var workers sync.WaitGroup
						for index := range sessions {
							client, conn, destination := fixture.packetPair(test, ipv6)
							payload := kernelPayload(16385, uint32(phase*sessions+index+1))
							workers.Go(func() {
								defer client.Close()
								defer conn.Close()
								select {
								case <-start:
								case <-conn.doneChan:
									return
								}
								client.SetReadDeadline(time.Now().Add(time.Second))
								options := N.NewReadWaitOptions(nil, conn)
								buffer := options.NewBufferSize(len(payload))
								_, _ = buffer.Write(payload)
								options.PostReturn(buffer)
								err := conn.WritePacket(buffer, destination)
								if err != nil {
									test.Error(err)
									return
								}
								storage := make([]byte, 65535)
								n, err := client.Read(storage)
								if err != nil || !bytes.Equal(storage[:n], payload) {
									test.Errorf("phase=%d session=%d: reassembled %d/%d bytes: %v", phase, index, n, len(payload), err)
								}
							})
						}
						close(start)
						workers.Wait()
						if test.Failed() {
							return
						}
					}
				})
			}
		})
	}
}

func TestGoKernelPacketRead(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	for _, ipv6 := range []bool{false, true} {
		for _, batch := range []bool{false, true} {
			t.Run(fmt.Sprintf("ipv6=%v/batch=%v", ipv6, batch), func(test *testing.T) {
				test.Parallel()
				client, conn, destination := fixture.packetPair(test, ipv6)
				waiter, created := bufio.CreatePacketReadWaiter(conn)
				if !created {
					test.Fatal("missing packet read waiter")
				}
				batchWaiter, batchCreated := bufio.CreatePacketBatchReadWaiter(conn)
				if !batchCreated {
					test.Fatal("missing packet batch read waiter")
				}
				for phase, options := range []N.ReadWaitOptions{
					{BatchSize: 4},
					{FrontHeadroom: 91, RearHeadroom: 73, BatchSize: 4},
					{FrontHeadroom: 17, RearHeadroom: 127, BatchSize: 3},
				} {
					expected := make(map[string]bool)
					sizes := []int{0, 1, 1452, 1473, 8193, 1024, 13, 64}
					for index, size := range sizes {
						payload := kernelPayload(size, uint32(193+phase*17+index))
						expected[string(payload)] = true
						_, err := client.Write(payload)
						if err != nil {
							test.Fatal(err)
						}
					}
					time.Sleep(40 * time.Millisecond)
					waiter.InitializeReadWaiter(options)
					largestBatch := 0
					for received := 0; received < len(sizes); {
						var buffers []*buf.Buffer
						var destinations []M.Socksaddr
						var err error
						if batch {
							buffers, destinations, err = batchWaiter.WaitReadPackets()
						} else {
							var buffer *buf.Buffer
							var packetDestination M.Socksaddr
							buffer, packetDestination, err = waiter.WaitReadPacket()
							if buffer != nil {
								buffers = []*buf.Buffer{buffer}
								destinations = []M.Socksaddr{packetDestination}
							}
						}
						if err != nil {
							buf.ReleaseMulti(buffers)
							test.Fatal(err)
						}
						largestBatch = max(largestBatch, len(buffers))
						if len(buffers) == 0 || len(buffers) != len(destinations) || len(buffers) > options.BatchSize {
							buf.ReleaseMulti(buffers)
							test.Fatal("incorrect packet batch size")
						}
						for index, buffer := range buffers {
							if !expected[string(buffer.Bytes())] || destinations[index] != destination {
								buf.ReleaseMulti(buffers[index:])
								test.Fatalf("phase %d: unexpected/duplicate packet or destination", phase)
							}
							delete(expected, string(buffer.Bytes()))
							buffer.ExtendHeader(options.FrontHeadroom)
							buffer.Extend(options.RearHeadroom)
							buffer.Release()
						}
						received += len(buffers)
					}
					if batch && largestBatch <= 1 {
						test.Fatal("queued datagrams were never read as a batch")
					}
				}
				options := N.NewReadWaitOptions(nil, conn)
				writer := bufio.NewPacketBatchWriter(conn)
				var buffers []*buf.Buffer
				var destinations []M.Socksaddr
				expected := make(map[string]bool)
				for index, size := range []int{0, 1, 1453, 8193} {
					payload := kernelPayload(size, uint32(211+index))
					expected[string(payload)] = true
					buffer := options.NewBufferSize(len(payload))
					_, _ = buffer.Write(payload)
					options.PostReturn(buffer)
					buffers = append(buffers, buffer)
					destinations = append(destinations, destination)
				}
				err := writer.WritePacketBatch(buffers, destinations)
				if err != nil {
					test.Fatal(err)
				}
				storage := make([]byte, 65535)
				for len(expected) > 0 {
					n, readErr := client.Read(storage)
					if readErr != nil || !expected[string(storage[:n])] {
						var missing []int
						for packet := range expected {
							missing = append(missing, len(packet))
						}
						test.Fatalf("batch write data: length=%d missing=%v: %v", n, missing, readErr)
					}
					delete(expected, string(storage[:n]))
				}
			})
		}
	}
}

func TestGoKernelPacketMapping(t *testing.T) {
	queues := []bool{false}
	if runtime.GOOS == "linux" {
		queues = append(queues, true)
	}
	for _, multiQueue := range queues {
		for _, mapping := range []NATMapping{NATMappingEndpointIndependent, NATMappingAddressDependent, NATMappingAddressAndPortDependent} {
			for _, filtering := range []NATFiltering{NATFilteringEndpointIndependent, NATFilteringAddressDependent, NATFilteringAddressAndPortDependent} {
				t.Run(fmt.Sprintf("mq=%v/mapping=%d/filtering=%d", multiQueue, mapping, filtering), func(configTest *testing.T) {
					fixture := newKernelStackFixture(configTest, kernelStackConfig{mtu: 1500, multiQueue: multiQueue, udpMapping: mapping, udpFiltering: filtering})
					for _, ipv6 := range []bool{false, true} {
						configTest.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
							test.Parallel()
							address := fixture.options.Inet4Address[0].Addr()
							if ipv6 {
								address = fixture.options.Inet6Address[0].Addr()
							}
							client, err := net.ListenUDP("udp", &net.UDPAddr{IP: address.AsSlice()})
							if err != nil {
								test.Fatal(err)
							}
							test.Cleanup(func() { client.Close() })
							client.SetDeadline(time.Now().Add(3 * time.Second))
							port := uint16(20000 + 8*fixture.port.Add(1))
							peers := []M.Socksaddr{
								M.SocksaddrFromNetIP(netip.AddrPortFrom(address.Next(), port)),
								M.SocksaddrFromNetIP(netip.AddrPortFrom(address.Next(), port+1)),
								M.SocksaddrFromNetIP(netip.AddrPortFrom(address.Next().Next(), port+2)),
								M.SocksaddrFromNetIP(netip.AddrPortFrom(address.Next(), port+3)),
								M.SocksaddrFromNetIP(netip.AddrPortFrom(address.Next().Next().Next(), port+4)),
							}
							accepted := make(chan N.PacketConn, 4)
							fixture.access.Lock()
							for _, peer := range peers {
								fixture.udp[peer.Port] = accepted
							}
							fixture.access.Unlock()
							var first N.PacketConn
							for index, peer := range peers[:3] {
								payload := []byte{byte(index + 1)}
								_, err = client.WriteToUDPAddrPort(payload, peer.AddrPort())
								if err != nil {
									test.Fatal(err)
								}
								conn := first
								if index == 0 || mapping == NATMappingAddressAndPortDependent || (mapping == NATMappingAddressDependent && index == 2) {
									select {
									case conn = <-accepted:
										test.Cleanup(func() { conn.Close() })
									case <-time.After(time.Second):
										test.Fatal("missing independent UDP session")
									}
								}
								if index == 0 {
									first = conn
								}
								conn.SetReadDeadline(time.Now().Add(time.Second))
								buffer := buf.NewPacket()
								destination, readErr := conn.ReadPacket(buffer)
								matches := bytes.Equal(buffer.Bytes(), payload)
								buffer.Release()
								if readErr != nil || !matches || destination != peer {
									test.Fatalf("mapping peer %d: destination=%v: %v", index, destination, readErr)
								}
							}
							for index, peer := range peers {
								allowed := filtering == NATFilteringEndpointIndependent || index == 0
								if filtering == NATFilteringAddressDependent && (index == 1 || index == 3) {
									allowed = true
								}
								if index == 1 && mapping != NATMappingAddressAndPortDependent {
									allowed = true
								}
								if index == 2 && mapping == NATMappingEndpointIndependent {
									allowed = true
								}
								payload := []byte{byte(index + 31)}
								options := N.NewReadWaitOptions(nil, first)
								buffer := options.NewBufferSize(len(payload))
								_, _ = buffer.Write(payload)
								options.PostReturn(buffer)
								err = first.WritePacket(buffer, peer)
								if err != nil {
									test.Fatal(err)
								}
								client.SetReadDeadline(time.Now().Add(75 * time.Millisecond))
								if allowed {
									client.SetReadDeadline(time.Now().Add(time.Second))
								}
								data := make([]byte, 16)
								n, source, readErr := client.ReadFromUDPAddrPort(data)
								if allowed {
									if readErr != nil || !bytes.Equal(data[:n], payload) || source != peer.AddrPort() {
										test.Fatalf("allowed return peer %d: source=%v: %v", index, source, readErr)
									}
								} else {
									var timeout net.Error
									if !errors.As(readErr, &timeout) || !timeout.Timeout() {
										test.Fatalf("uncontacted return peer %d was not filtered: source=%v: %v", index, source, readErr)
									}
								}
							}
						})
					}
				})
			}
		}
	}
}

func TestGoKernelPacketLifetime(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			test.Parallel()
			_, idle, _ := fixture.packetPair(test, ipv6)
			client, active, _ := fixture.packetPair(test, ipv6)
			for _, conn := range []*UDPNatConn{idle, active} {
				if !conn.SetTimeout(180 * time.Millisecond) {
					test.Fatal("cannot set UDP timeout")
				}
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			}
			idleClosed := make(chan error, 1)
			go func() {
				buffer, _, err := idle.WaitReadPacket()
				if buffer != nil {
					buffer.Release()
				}
				idleClosed <- err
			}()
			buffer := buf.NewPacket()
			defer buffer.Release()
			for index := range 8 {
				time.Sleep(50 * time.Millisecond)
				payload := []byte{byte(index + 1)}
				_, err := client.Write(payload)
				if err != nil {
					test.Fatal(err)
				}
				buffer.Reset()
				_, err = active.ReadPacket(buffer)
				if err != nil || !bytes.Equal(buffer.Bytes(), payload) {
					test.Fatalf("active UDP session expired: %v", err)
				}
			}
			select {
			case err := <-idleClosed:
				if !errors.Is(err, io.ErrClosedPipe) {
					test.Fatalf("independent idle session: %v", err)
				}
			case <-time.After(300 * time.Millisecond):
				test.Fatal("traffic on another session kept idle session alive")
			}
			active.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
			_, err := active.ReadPacket(buffer)
			if !errors.Is(err, io.ErrClosedPipe) {
				test.Fatalf("UDP session did not expire after traffic stopped: %v", err)
			}
		})
	}
}
