//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	std_bufio "bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func TestGoKernelPacketTimeout(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			client, conn, destination := fixture.packetPair(test, ipv6)
			if !conn.SetTimeout(100 * time.Millisecond) {
				test.Fatal("cannot set live UDP session timeout")
			}
			buffer, _, err := conn.WaitReadPacket()
			if buffer != nil {
				buffer.Release()
			}
			if !errors.Is(err, io.ErrClosedPipe) {
				test.Fatalf("idle UDP session did not close: %v", err)
			}
			payload := kernelPayload(1200, 103)
			_, err = client.Write(payload)
			if err != nil {
				test.Fatal(err)
			}
			fixture.access.Lock()
			accepted := fixture.udp[destination.Port]
			fixture.access.Unlock()
			select {
			case replacement := <-accepted:
				defer replacement.Close()
				replacement.SetReadDeadline(time.Now().Add(time.Second))
				options := N.NewReadWaitOptions(nil, replacement)
				packet := options.NewBufferSize(1500)
				_, err = replacement.ReadPacket(packet)
				if err != nil || !bytes.Equal(packet.Bytes(), payload) {
					packet.Release()
					test.Fatalf("UDP session renewal lost its first packet: %v", err)
				}
				options.PostReturn(packet)
				err = replacement.WritePacket(packet, destination)
				if err != nil {
					test.Fatal(err)
				}
				response := make([]byte, 1500)
				n, readErr := client.Read(response)
				if readErr != nil || !bytes.Equal(response[:n], payload) {
					test.Fatalf("renewed UDP session response: %v", readErr)
				}
			case <-time.After(time.Second):
				test.Fatal("next UDP packet did not create a new session")
			}
		})
	}
}

func TestGoKernelPacketBuffer(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(addressTest *testing.T) {
			client, conn, destination := fixture.packetPair(addressTest, ipv6)
			for _, size := range []int{0, 1, 1473} {
				for _, capacity := range []int{0, 1, 1024, 2048} {
					addressTest.Run(fmt.Sprintf("size=%d/capacity=%d", size, capacity), func(packetTest *testing.T) {
						payload := kernelPayload(size, uint32(size+71))
						_, err := client.Write(payload)
						if err != nil {
							packetTest.Fatal(err)
						}
						prefix := []byte("prefix")
						buffer := buf.With(make([]byte, 16+len(prefix)+capacity+32))
						buffer.Resize(16, len(prefix))
						buffer.Reserve(32)
						copy(buffer.Bytes(), prefix)
						actualDestination, readErr := conn.ReadPacket(buffer)
						if capacity == 0 {
							if !errors.Is(readErr, io.ErrShortBuffer) {
								packetTest.Fatalf("full buffer: %v", readErr)
							}
						} else if readErr != nil {
							packetTest.Fatal(readErr)
						}
						if actualDestination != destination {
							packetTest.Fatalf("destination: %v, want %v", actualDestination, destination)
						}
						if buffer.Start() != 16 || !bytes.Equal(buffer.Bytes(), append(prefix, payload[:min(size, capacity)]...)) {
							packetTest.Fatalf("packet buffer: %x", buffer.Bytes())
						}
						marker := kernelPayload(7, 83)
						_, err = client.Write(marker)
						if err != nil {
							packetTest.Fatal(err)
						}
						buffer.Reset()
						_, err = conn.ReadPacket(buffer)
						if err != nil || !bytes.Equal(buffer.Bytes(), marker) {
							packetTest.Fatalf("next datagram: %x: %v", buffer.Bytes(), err)
						}
					})
				}
			}
		})
	}
}

func (f *kernelStackFixture) packetPair(t *testing.T, ipv6 bool) (*net.UDPConn, *UDPNatConn, M.Socksaddr) {
	t.Helper()
	port := uint16(20000 + f.port.Add(1))
	accepted := make(chan N.PacketConn, 1)
	f.access.Lock()
	f.udp[port] = accepted
	f.access.Unlock()
	destination := M.ParseSocksaddr(f.address(ipv6, port))
	client, err := net.DialUDP("udp", nil, destination.UDPAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	err = client.SetWriteBuffer(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = client.Write([]byte("ready"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case conn := <-accepted:
		t.Cleanup(func() { conn.Close() })
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buffer := buf.NewPacket()
		_, err = conn.ReadPacket(buffer)
		buffer.Release()
		if err != nil {
			t.Fatal(err)
		}
		return client, conn.(*UDPNatConn), destination
	case <-time.After(3 * time.Second):
		t.Fatal("UDP flow not accepted")
		return nil, nil, M.Socksaddr{}
	}
}

type kernelPacketSocket struct {
	*net.UDPConn
	access sync.Mutex
	owner  io.Closer
	closed bool
}

func (s *kernelPacketSocket) Attach(owner io.Closer) (io.Closer, bool) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed || s.owner != nil {
		return nil, false
	}
	s.owner = owner
	return s.UDPConn, true
}

func (s *kernelPacketSocket) Detach() {
	s.access.Lock()
	s.owner = nil
	closed := s.closed
	s.access.Unlock()
	if closed {
		s.UDPConn.Close()
	}
}

func (s *kernelPacketSocket) Close() error {
	s.access.Lock()
	s.closed = true
	owner := s.owner
	s.access.Unlock()
	if owner != nil {
		return owner.Close()
	}
	return s.UDPConn.Close()
}

func TestGoKernelPacket(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	configs := []kernelStackConfig{{mtu: 1500}, {mtu: 65535}}
	if runtime.GOOS == "linux" {
		configs = append(configs, kernelStackConfig{mtu: 1500, gso: true, multiQueue: true})
	}
	for _, config := range configs {
		t.Run(fmt.Sprintf("mtu=%d/gso=%v/mq=%v", config.mtu, config.gso, config.multiQueue), func(configurationTest *testing.T) {
			fixture := newKernelStackFixture(configurationTest, config)
			for _, ipv6 := range []bool{false, true} {
				configurationTest.Run(fmt.Sprintf("ipv6=%v", ipv6), func(addressTest *testing.T) {
					for _, splice := range []string{"none", "direct", "socks", "socks-fqdn"} {
						addressTest.Run("splice="+splice, func(scenarioTest *testing.T) {
							client, conn, destination := fixture.packetPair(scenarioTest, ipv6)
							network := "udp4"
							address := net.IPv4(127, 0, 0, 1)
							maximumPayload := 65535 - header.IPv4MinimumSize - header.UDPMinimumSize
							if ipv6 {
								network = "udp6"
								address = net.IPv6loopback
								maximumPayload = 65535 - header.UDPMinimumSize
							}
							var (
								peer             *net.UDPConn
								socksPackets     chan kernelSocksPacket
								socksDestination M.Socksaddr
								headerLength     int
							)
							switch splice {
							case "direct":
								var err error
								peer, err = net.ListenUDP(network, &net.UDPAddr{IP: address})
								if err != nil {
									scenarioTest.Fatal(err)
								}
								scenarioTest.Cleanup(func() { peer.Close() })
								upstream, err := net.DialUDP(network, nil, peer.LocalAddr().(*net.UDPAddr))
								if err != nil {
									scenarioTest.Fatal(err)
								}
								scenarioTest.Cleanup(func() { upstream.Close() })
								peer.SetWriteBuffer(1 << 20)
								upstream.SetWriteBuffer(1 << 20)
								peer.SetDeadline(time.Now().Add(3 * time.Second))
								accepted := conn.Splice(&kernelPacketSocket{UDPConn: upstream}, SplicePacketOptions{
									NAT:           PacketNAT{Origin: destination, Destination: M.SocksaddrFromNet(peer.LocalAddr())},
									SpliceOptions: SpliceOptions{OnClose: func(error) { upstream.Close() }},
								})
								if !accepted {
									scenarioTest.Fatal("UDP splice refused")
								}
							case "socks", "socks-fqdn":
								if splice == "socks" {
									socksDestination = M.ParseSocksaddrHostPort("192.0.2.1", 53)
									if ipv6 {
										socksDestination = M.ParseSocksaddrHostPort("2001:db8::1", 53)
									}
								} else {
									socksDestination = M.ParseSocksaddrHostPort(strings.Repeat(strings.Repeat("a", 63)+".", 3)+strings.Repeat("b", 61), 53)
								}
								var serverAddress M.Socksaddr
								serverAddress, socksPackets = newKernelSocksEchoServer(scenarioTest, address)
								socksClient := socks.NewClient(N.SystemDialer, serverAddress, socks.Version5, "", "")
								associateConn, err := socksClient.ListenPacket(context.Background(), socksDestination)
								if err != nil {
									scenarioTest.Fatal(err)
								}
								scenarioTest.Cleanup(func() { associateConn.Close() })
								terminal, offload := N.UnwrapPacketOffload(associateConn)
								upstream, isUDPConn := terminal.(*net.UDPConn)
								if !isUDPConn || offload == nil {
									scenarioTest.Fatalf("SOCKS UDP not unwrapped: %T", terminal)
								}
								upstream.SetWriteBuffer(1 << 20)
								_, err = client.Write([]byte("cached"))
								if err != nil {
									scenarioTest.Fatal(err)
								}
								cached := N.NewPacketBuffer()
								cached.Buffer, cached.Destination, err = conn.WaitReadPacket()
								if err != nil {
									N.PutPacketBuffer(cached)
									scenarioTest.Fatal(err)
								}
								if !config.multiQueue {
									offload = &kernelSocksOffload{
										PacketOffload: offload,
										engine:        conn.writer.(*GoPacketConn).engine,
										cached:        2,
										test:          scenarioTest,
									}
								}
								accepted := conn.Splice(&kernelPacketSocket{UDPConn: upstream}, SplicePacketOptions{
									NAT:           PacketNAT{Origin: destination, Destination: socksDestination},
									Cached:        []*N.PacketBuffer{cached},
									Offload:       offload,
									FrontHeadroom: N.CalculateFrontHeadroom(associateConn),
									RearHeadroom:  N.CalculateRearHeadroom(associateConn),
									SpliceOptions: SpliceOptions{OnClose: func(error) { associateConn.Close() }},
								})
								if !accepted {
									scenarioTest.Fatal("UDP splice refused")
								}
								headerLength = 3 + M.SocksaddrSerializer.AddrPortLen(socksDestination)
								_, err = client.Write([]byte("ready"))
								if err != nil {
									scenarioTest.Fatal(err)
								}
								for _, expected := range []string{"cached", "ready"} {
									select {
									case packet := <-socksPackets:
										if string(packet.payload) != expected || packet.destination != socksDestination {
											scenarioTest.Fatalf("SOCKS initial packet: %q to %v", packet.payload, packet.destination)
										}
									case <-time.After(3 * time.Second):
										scenarioTest.Fatal("SOCKS UDP session not established")
									}
									response := make([]byte, 16)
									n, readErr := client.Read(response)
									if readErr != nil || string(response[:n]) != expected {
										scenarioTest.Fatalf("SOCKS initial response: %q: %v", response[:n], readErr)
									}
								}
							}
							sizes := []int{0, 1, 1472, 1473, 8193, 65507}
							if ipv6 {
								sizes = append(sizes, 1452, 1453, 65527)
							}
							if headerLength > 0 {
								sizes = append(sizes, maximumPayload-headerLength)
							}
							for _, size := range sizes {
								if headerLength+size > maximumPayload {
									continue
								}
								scenarioTest.Run(fmt.Sprintf("size=%d", size), func(packetTest *testing.T) {
									payload := kernelPayload(size, uint32(size+37))
									_, err := client.Write(payload)
									if err != nil {
										packetTest.Fatal("kernel upload:", err)
									}
									var received []byte
									switch splice {
									case "none":
										options := N.NewReadWaitOptions(nil, conn)
										buffer := options.NewBufferSize(65535)
										_, err = conn.ReadPacket(buffer)
										received = bytes.Clone(buffer.Bytes())
										if err != nil {
											buffer.Release()
											packetTest.Fatal("Go upload:", err)
										}
										options.PostReturn(buffer)
										err = conn.WritePacket(buffer, destination)
									case "direct":
										data := make([]byte, 65535)
										n, source, readErr := peer.ReadFromUDP(data)
										if readErr != nil {
											packetTest.Fatal("spliced upload:", readErr)
										}
										received = data[:n]
										_, err = peer.WriteToUDP(payload, source)
									default:
										select {
										case packet := <-socksPackets:
											if packet.destination != socksDestination {
												packetTest.Fatalf("SOCKS destination: %v, want %v", packet.destination, socksDestination)
											}
											received = packet.payload
										case <-time.After(3 * time.Second):
											packetTest.Fatal("spliced SOCKS upload timed out")
										}
									}
									if !bytes.Equal(received, payload) {
										packetTest.Fatalf("upload bytes=%d want=%d", len(received), size)
									}
									if err != nil {
										packetTest.Fatal("download write:", err)
									}
									response := make([]byte, 65535)
									n, readErr := client.Read(response)
									if readErr != nil {
										packetTest.Fatal("kernel download:", readErr)
									}
									if !bytes.Equal(response[:n], payload) {
										packetTest.Fatalf("download bytes=%d want=%d", n, size)
									}
								})
							}
						})
					}
					addressTest.Run("tcp_after_udp", func(streamTest *testing.T) {
						client, server := fixture.pair(streamTest, ipv6)
						err := kernelTransfer(client, server, kernelPayload(64<<10, 41), false)
						if err != nil {
							streamTest.Fatal("TCP upload after UDP headroom negotiation:", err)
						}
						err = kernelTransfer(server, client, kernelPayload(64<<10, 43), true)
						if err != nil {
							streamTest.Fatal("TCP download after UDP headroom negotiation:", err)
						}
					})
				})
			}
		})
	}
}

type kernelSocksOffload struct {
	N.PacketOffload
	engine *goEngine
	cached int
	test   *testing.T
}

func (o *kernelSocksOffload) EncodePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if o.cached > 0 {
		o.cached--
	} else {
		borrowed := false
		for _, frame := range o.engine.frames {
			if buffer == frame.buffer {
				borrowed = true
				break
			}
		}
		if !borrowed {
			for _, entry := range o.engine.reassemblyEntries {
				if buffer == entry.buffer {
					borrowed = true
					break
				}
			}
		}
		if !borrowed {
			err := E.New("SOCKS splice copied the TUN payload before encoding")
			o.test.Error(err)
			return err
		}
	}
	return o.PacketOffload.EncodePacket(buffer, destination)
}

type kernelSocksPacket struct {
	payload     []byte
	destination M.Socksaddr
}

type kernelSocksEchoServer struct {
	packets chan kernelSocksPacket
}

func newKernelSocksEchoServer(t *testing.T, address net.IP) (M.Socksaddr, chan kernelSocksPacket) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: address})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	server := &kernelSocksEchoServer{packets: make(chan kernelSocksPacket, 16)}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				handleErr := socks.HandleConnectionEx(context.Background(), conn, std_bufio.NewReader(conn), nil, server, server, 0, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
				if handleErr != nil {
					conn.Close()
				}
			}()
		}
	}()
	return M.SocksaddrFromNet(listener.Addr()), server.packets
}

func (s *kernelSocksEchoServer) ListenPacket(listenConfig net.ListenConfig, ctx context.Context, network string, address string) (net.PacketConn, error) {
	conn, err := listenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	udpConn := conn.(*net.UDPConn)
	udpConn.SetReadBuffer(1 << 20)
	udpConn.SetWriteBuffer(1 << 20)
	return conn, nil
}

func (s *kernelSocksEchoServer) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
}

func (s *kernelSocksEchoServer) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		frontHeadroom := N.CalculateFrontHeadroom(conn)
		for {
			buffer := buf.NewSize(frontHeadroom + 65535)
			buffer.Resize(frontHeadroom, 0)
			packetDestination, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			s.packets <- kernelSocksPacket{payload: bytes.Clone(buffer.Bytes()), destination: packetDestination}
			err = conn.WritePacket(buffer, packetDestination)
			if err != nil {
				return
			}
		}
	}()
}

var (
	_ SpliceSocket         = (*kernelPacketSocket)(nil)
	_ socks.HandlerEx      = (*kernelSocksEchoServer)(nil)
	_ socks.PacketListener = (*kernelSocksEchoServer)(nil)
)

type kernelPacketAllocator struct {
	buf.Allocator
	active atomic.Int64
}

func (a *kernelPacketAllocator) Get(size int) []byte {
	buffer := a.Allocator.Get(size)
	if buffer != nil {
		a.active.Add(1)
	}
	return buffer
}

func (a *kernelPacketAllocator) Put(buffer []byte) error {
	err := a.Allocator.Put(buffer)
	if err == nil {
		a.active.Add(-1)
	}
	return err
}

func (a *kernelPacketAllocator) waitIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for a.active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active := a.active.Load(); active != 0 {
		t.Fatalf("idle connections retain %d pooled buffers", active)
	}
}

func TestGoKernelPacketBatchIdle(t *testing.T) {
	allocator := &kernelPacketAllocator{Allocator: buf.DefaultAllocator}
	buf.DefaultAllocator = allocator
	t.Cleanup(func() { buf.DefaultAllocator = allocator.Allocator })
	configs := []kernelStackConfig{{mtu: 1500}, {mtu: 65535}}
	if runtime.GOOS == "linux" {
		configs = append(configs, kernelStackConfig{mtu: 1500, gso: true, multiQueue: true})
	}
	for _, config := range configs {
		t.Run(fmt.Sprintf("mtu=%d/gso=%v/mq=%v", config.mtu, config.gso, config.multiQueue), func(configurationTest *testing.T) {
			fixture := newKernelStackFixture(configurationTest, config)
			for _, ipv6 := range []bool{false, true} {
				for _, mode := range []string{"batch", "connected", "unconnected", "socks-fqdn"} {
					configurationTest.Run(fmt.Sprintf("ipv6=%v/%s", ipv6, mode), func(scenarioTest *testing.T) {
						client, conn, destination := fixture.packetPair(scenarioTest, ipv6)
						var peer *net.UDPConn
						var source *net.UDPAddr
						var prefix []byte
						if mode != "batch" {
							network := "udp4"
							address := net.IPv4(127, 0, 0, 1)
							if ipv6 {
								network = "udp6"
								address = net.IPv6loopback
							}
							var err error
							peer, err = net.ListenUDP(network, &net.UDPAddr{IP: address})
							if err != nil {
								scenarioTest.Fatal(err)
							}
							defer peer.Close()
							peer.SetReadBuffer(1 << 20)
							peer.SetWriteBuffer(1 << 20)
							peer.SetDeadline(time.Now().Add(5 * time.Second))
							var upstream *net.UDPConn
							if mode != "unconnected" {
								upstream, err = net.DialUDP(network, nil, peer.LocalAddr().(*net.UDPAddr))
							} else {
								upstream, err = net.ListenUDP(network, &net.UDPAddr{IP: address})
							}
							if err != nil {
								scenarioTest.Fatal(err)
							}
							defer upstream.Close()
							upstream.SetReadBuffer(1 << 20)
							spliceOptions := SplicePacketOptions{
								NAT: PacketNAT{Origin: destination, Destination: M.SocksaddrFromNet(peer.LocalAddr())},
							}
							if mode == "socks-fqdn" {
								domain := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 61)
								target := M.ParseSocksaddrHostPort(domain, 53)
								prefix = append([]byte{0, 0, 0, 3, byte(len(domain))}, domain...)
								prefix = append(prefix, 0, 53)
								associate := socks.NewAssociatePacketConn(upstream, target, upstream)
								spliceOptions.Offload, _ = associate.CreatePacketOffload()
								spliceOptions.FrontHeadroom = associate.FrontHeadroom()
								spliceOptions.NAT.Destination = target
							}
							accepted := conn.Splice(&kernelPacketSocket{UDPConn: upstream}, spliceOptions)
							if !accepted {
								scenarioTest.Fatal("UDP splice refused")
							}
						}
						for cycle := range 3 {
							payloads := make([][]byte, 24)
							for index := range payloads {
								size := 1200
								if index >= 16 {
									size = []int{1, 0, 1453, 8193, 1201, 0, 3, 1200}[index-16]
								}
								payloads[index] = kernelPayload(size, uint32(cycle*31+index+1))
								_, err := client.Write(payloads[index])
								if err != nil {
									scenarioTest.Fatal(err)
								}
							}
							uploaded := make([]bool, len(payloads))
							for index := range payloads {
								var actual []byte
								if peer != nil {
									data := make([]byte, 65535)
									length, sender, err := peer.ReadFromUDP(data)
									if err != nil {
										scenarioTest.Fatalf("upload packet %d: %v", index, err)
									}
									source = sender
									if length < len(prefix) || !bytes.Equal(data[:len(prefix)], prefix) {
										scenarioTest.Fatal("SOCKS packet header corrupted")
									}
									actual = data[len(prefix):length]
								} else {
									buffer, _, err := conn.WaitReadPacket()
									if err != nil {
										scenarioTest.Fatal(err)
									}
									actual = bytes.Clone(buffer.Bytes())
									buffer.Release()
								}
								kernelCheckBatchPacket(scenarioTest, actual, payloads, uploaded, index, !config.multiQueue)
							}
							if peer != nil {
								for _, payload := range payloads {
									_, err := peer.WriteToUDP(append(bytes.Clone(prefix), payload...), source)
									if err != nil {
										scenarioTest.Fatal(err)
									}
								}
							} else {
								options := N.NewReadWaitOptions(nil, conn)
								buffers := make([]*buf.Buffer, len(payloads))
								destinations := make([]M.Socksaddr, len(payloads))
								for index, payload := range payloads {
									buffers[index] = options.NewBufferSize(len(payload))
									copy(buffers[index].Extend(len(payload)), payload)
									options.PostReturn(buffers[index])
									destinations[index] = destination
								}
								err := bufio.NewPacketBatchWriter(conn).WritePacketBatch(buffers, destinations)
								if err != nil {
									scenarioTest.Fatal(err)
								}
							}
							downloaded := make([]bool, len(payloads))
							for index := range payloads {
								data := make([]byte, 65535)
								length, err := client.Read(data)
								if err != nil {
									scenarioTest.Fatalf("download packet %d: %v", index, err)
								}
								kernelCheckBatchPacket(scenarioTest, data[:length], payloads, downloaded, index, !config.multiQueue)
							}
							allocator.waitIdle(scenarioTest)
							if conn.isClosed() {
								scenarioTest.Fatal("idle test closed the UDP session")
							}
							time.Sleep(10 * time.Millisecond)
						}
					})
				}
			}
		})
	}
}

func kernelCheckBatchPacket(t *testing.T, packet []byte, expected [][]byte, received []bool, index int, ordered bool) {
	t.Helper()
	if ordered {
		if !bytes.Equal(packet, expected[index]) {
			t.Fatalf("packet %d corrupted or reordered: received %d bytes, expected %d", index, len(packet), len(expected[index]))
		}
		return
	}
	for candidate, payload := range expected {
		if !received[candidate] && bytes.Equal(packet, payload) {
			received[candidate] = true
			return
		}
	}
	t.Fatalf("packet %d corrupted or duplicated: received %d bytes", index, len(packet))
}
