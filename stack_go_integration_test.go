//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type kernelStackConfig struct {
	stackFactory         func(StackOptions) (Stack, error)
	mtu                  uint32
	gso                  bool
	multiQueue           bool
	prepare              func(*testing.T, *Options)
	configure            func(*testing.T, Options)
	pressure             func() MemoryPressure
	ctx                  context.Context
	handshake            func(*GoConn) error
	udpMapping           NATMapping
	udpFiltering         NATFiltering
	dialer               net.Dialer
	socketBuffer         int
	upstreamSocketBuffer int
}

type kernelAccept struct {
	conn *GoConn
	err  error
}

type kernelStackFixture struct {
	stack                *Go
	options              Options
	access               sync.Mutex
	tcp                  map[uint16]chan kernelAccept
	udp                  map[uint16]chan N.PacketConn
	port                 atomic.Uint32
	dialer               net.Dialer
	socketBuffer         int
	upstreamSocketBuffer int
	handshake            func(*GoConn) error
}

var kernelInterfaceSequence atomic.Uint32

func newKernelStackFixture(t *testing.T, config kernelStackConfig) *kernelStackFixture {
	t.Helper()
	index := kernelInterfaceSequence.Add(1)
	fixture := &kernelStackFixture{
		tcp:                  make(map[uint16]chan kernelAccept),
		udp:                  make(map[uint16]chan N.PacketConn),
		dialer:               config.dialer,
		socketBuffer:         config.socketBuffer,
		upstreamSocketBuffer: config.upstreamSocketBuffer,
		handshake:            config.handshake,
		options: Options{
			Name:                      fmt.Sprintf("gotest%d", index),
			MTU:                       config.mtu,
			GSO:                       config.gso,
			MultiQueue:                config.multiQueue,
			Inet4Address:              []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("198.19.%d.1/24", 200+index%50))},
			Inet6Address:              []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("fd73:ab91:%x::1/64", index))},
			EXP_ExternalConfiguration: true,
			EXP_MultiPendingPackets:   true,
			Logger:                    logger.NOP(),
		},
	}
	if fixture.dialer.Timeout == 0 {
		fixture.dialer.Timeout = 3 * time.Second
	}
	if runtime.GOOS == "darwin" {
		fixture.options.Name = fmt.Sprintf("utun%d", 200+index)
	}
	if config.prepare != nil {
		config.prepare(t, &fixture.options)
	}
	device, err := New(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { device.Close() })
	configureKernelInterface(t, device, fixture.options)
	if config.configure != nil {
		config.configure(t, fixture.options)
	}
	err = device.Start()
	if err != nil {
		t.Fatal(err)
	}
	if config.ctx == nil {
		config.ctx = context.Background()
	}
	stackOptions := StackOptions{
		Context: config.ctx, Tun: device, TunOptions: fixture.options,
		Handler: fixture, Logger: logger.NOP(), UDPTimeout: time.Minute, ICMPTimeout: time.Minute,
		MemoryPressure: config.pressure,
		UDPMapping:     config.udpMapping, UDPFiltering: config.udpFiltering,
	}
	var stack Stack
	if config.stackFactory != nil {
		stack, err = config.stackFactory(stackOptions)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		fixture.stack = NewGo(stackOptions)
		stack = fixture.stack
	}
	err = stack.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stack.Close() })
	return fixture
}

func (f *kernelStackFixture) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	return FlowVerdict{Action: ActionAccept}
}

func (f *kernelStackFixture) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {}

func (f *kernelStackFixture) NewConnectionEx(_ context.Context, conn net.Conn, _, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	f.access.Lock()
	accepted := f.tcp[destination.Port]
	f.access.Unlock()
	if accepted == nil {
		conn.Close()
		return
	}
	goConn := conn.(*GoConn)
	goConn.SetDeadline(time.Now().Add(10 * time.Second))
	var err error
	if f.handshake != nil {
		err = f.handshake(goConn)
	} else {
		err = goConn.HandshakeSuccess()
	}
	accepted <- kernelAccept{conn: goConn, err: err}
}

func (f *kernelStackFixture) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	f.access.Lock()
	accepted := f.udp[destination.Port]
	f.access.Unlock()
	if accepted == nil {
		conn.Close()
		return
	}
	accepted <- conn
}

func (f *kernelStackFixture) address(ipv6 bool, port uint16) string {
	address := f.options.Inet4Address[0].Addr().Next()
	if ipv6 {
		address = f.options.Inet6Address[0].Addr().Next()
	}
	return netip.AddrPortFrom(address, port).String()
}

func (f *kernelStackFixture) pair(t *testing.T, ipv6 bool) (*net.TCPConn, *GoConn) {
	t.Helper()
	port := uint16(20000 + f.port.Add(1))
	accepted := make(chan kernelAccept, 1)
	f.access.Lock()
	f.tcp[port] = accepted
	f.access.Unlock()
	conn, err := f.dialer.Dial("tcp", f.address(ipv6, port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if f.socketBuffer > 0 {
		err = conn.(*net.TCPConn).SetReadBuffer(f.socketBuffer)
		if err != nil {
			t.Fatal(err)
		}
		err = conn.(*net.TCPConn).SetWriteBuffer(f.socketBuffer)
		if err != nil {
			t.Fatal(err)
		}
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatal(result.err)
		}
		t.Cleanup(func() { result.conn.Close() })
		return conn.(*net.TCPConn), result.conn
	case <-time.After(3 * time.Second):
		t.Fatal("Go connection handshake did not complete")
		return nil, nil
	}
}

type kernelSocket struct {
	*net.TCPConn
	access sync.Mutex
	owner  io.Closer
	closed bool
}

func (s *kernelSocket) Attach(owner io.Closer) (io.Closer, bool) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed || s.owner != nil {
		return nil, false
	}
	s.owner = owner
	return s.TCPConn, true
}

func (s *kernelSocket) Detach() {
	s.access.Lock()
	s.owner = nil
	closed := s.closed
	s.access.Unlock()
	if closed {
		s.TCPConn.Close()
	}
}

func (s *kernelSocket) Close() error {
	s.access.Lock()
	s.closed = true
	owner := s.owner
	s.access.Unlock()
	if owner != nil {
		return owner.Close()
	}
	return s.TCPConn.Close()
}

func (f *kernelStackFixture) splicePair(t *testing.T, ipv6 bool) (*net.TCPConn, *net.TCPConn, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	client, goConn := f.pair(t, ipv6)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	remote, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { remote.Close() })
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	if f.upstreamSocketBuffer > 0 {
		for _, socket := range []*net.TCPConn{remote, peer} {
			err = socket.SetReadBuffer(f.upstreamSocketBuffer)
			if err != nil {
				t.Fatal(err)
			}
			err = socket.SetWriteBuffer(f.upstreamSocketBuffer)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	peer.SetDeadline(time.Now().Add(10 * time.Second))
	upload := new(atomic.Int64)
	download := new(atomic.Int64)
	spliced := goConn.Splice(&kernelSocket{TCPConn: remote}, SpliceOptions{
		ReadCounters:  []N.CountFunc{func(n int64) { upload.Add(n) }},
		WriteCounters: []N.CountFunc{func(n int64) { download.Add(n) }},
		OnClose:       func(error) { remote.Close() },
	})
	if !spliced {
		t.Fatal("splice refused")
	}
	return client, peer, upload, download
}

func kernelPayload(size int, seed uint32) []byte {
	data := make([]byte, size)
	for index := range data {
		seed ^= seed << 13
		seed ^= seed >> 17
		seed ^= seed << 5
		data[index] = byte(seed)
	}
	return data
}

func kernelTransfer(sender net.Conn, receiver net.Conn, payload []byte, buffered bool) error {
	written := make(chan error, 1)
	go func() {
		var err error
		if buffered {
			writer := sender.(N.ExtendedWriter)
			for offset := 0; offset < len(payload); {
				length := min(len(payload)-offset, 32749)
				buffer := buf.NewSize(length + 128)
				buffer.Resize(128, 0)
				common.Must1(buffer.Write(payload[offset : offset+length]))
				err = writer.WriteBuffer(buffer)
				if err != nil {
					break
				}
				offset += length
			}
		} else {
			_, err = sender.Write(payload)
		}
		if err == nil {
			err = N.CloseWrite(sender)
		}
		written <- err
	}()
	data, err := io.ReadAll(io.LimitReader(receiver, int64(len(payload)+1)))
	if err != nil {
		return err
	}
	if !bytes.Equal(data, payload) {
		return E.New("payload mismatch: received ", len(data), " bytes, wanted ", len(payload))
	}
	return <-written
}

func TestGoKernelStream(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	configs := []kernelStackConfig{{mtu: 1500}, {mtu: 9000}, {mtu: 65535}}
	if runtime.GOOS == "linux" {
		configs = append(configs, kernelStackConfig{mtu: 1500, gso: true}, kernelStackConfig{mtu: 1500, multiQueue: true}, kernelStackConfig{mtu: 1500, gso: true, multiQueue: true})
	}
	for _, config := range configs {
		t.Run(fmt.Sprintf("mtu=%d/gso=%v/mq=%v", config.mtu, config.gso, config.multiQueue), func(configurationTest *testing.T) {
			fixture := newKernelStackFixture(configurationTest, config)
			for _, ipv6 := range []bool{false, true} {
				configurationTest.Run(fmt.Sprintf("ipv6=%v", ipv6), func(addressTest *testing.T) {
					for _, splice := range []bool{false, true} {
						addressTest.Run(fmt.Sprintf("duplex/splice=%v", splice), func(scenarioTest *testing.T) {
							var client, server net.Conn
							var upload, download *atomic.Int64
							if splice {
								client, server, upload, download = fixture.splicePair(scenarioTest, ipv6)
							} else {
								client, server = fixture.pair(scenarioTest, ipv6)
							}
							payload := kernelPayload(4<<20, 71)
							response := kernelPayload(4<<20, 97)
							result := make(chan error, 1)
							go func() { result <- kernelTransfer(client, server, payload, false) }()
							err := kernelTransfer(server, client, response, !splice)
							if err != nil {
								scenarioTest.Error("download:", err)
							}
							err = <-result
							if err != nil {
								scenarioTest.Error("upload:", err)
							}
							if splice && (upload.Load() != int64(len(payload)) || download.Load() != int64(len(response))) {
								scenarioTest.Errorf("counts upload=%d download=%d", upload.Load(), download.Load())
							}
						})
					}
					addressTest.Run("read_deadline_recovery", func(scenarioTest *testing.T) {
						client, server := fixture.pair(scenarioTest, ipv6)
						server.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
						data := make([]byte, 7)
						_, err := server.Read(data)
						if !errors.Is(err, os.ErrDeadlineExceeded) {
							scenarioTest.Fatalf("read deadline: %v", err)
						}
						server.SetReadDeadline(time.Now().Add(time.Second))
						_, err = client.Write([]byte("resumed"))
						if err != nil {
							scenarioTest.Fatal(err)
						}
						_, err = io.ReadFull(server, data)
						if err != nil || string(data) != "resumed" {
							scenarioTest.Fatalf("recovery: %q %v", data, err)
						}
					})
					addressTest.Run("write_deadline_recovery", func(scenarioTest *testing.T) {
						client, server := fixture.pair(scenarioTest, ipv6)
						client.SetReadBuffer(4096)
						server.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
						payload := kernelPayload(8<<20, 31)
						n, err := server.Write(payload)
						if !errors.Is(err, os.ErrDeadlineExceeded) {
							scenarioTest.Fatalf("write %d/%d deadline: %v", n, len(payload), err)
						}
						server.SetWriteDeadline(time.Now().Add(8 * time.Second))
						client.SetReadBuffer(4 << 20)
						written := make(chan error, 1)
						go func() {
							_, writeErr := server.Write(payload[n:])
							if writeErr == nil {
								writeErr = server.CloseWrite()
							}
							written <- writeErr
						}()
						data, readErr := io.ReadAll(client)
						if readErr != nil {
							scenarioTest.Fatalf("initial accepted=%d received=%d: %v; buffered=%d sent=%d transmitted=%d unacked=%d permit=%d", n, len(data), readErr, server.bufferedTail.Load(), server.sentTail.Load(), server.transmittedTail.Load(), server.sendUnacked.Load(), server.sendPermit.Load())
						}
						if !bytes.Equal(data, payload) {
							scenarioTest.Fatalf("deadline recovery: received %d/%d", len(data), len(payload))
						}
						writeErr := <-written
						if writeErr != nil {
							scenarioTest.Fatal(writeErr)
						}
					})
					addressTest.Run("wait_read_buffer", func(scenarioTest *testing.T) {
						client, server := fixture.pair(scenarioTest, ipv6)
						server.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 91, RearHeadroom: 73})
						payload := kernelPayload(256<<10, 17)
						written := make(chan error, 1)
						go func() {
							_, writeErr := client.Write(payload)
							if writeErr == nil {
								writeErr = client.CloseWrite()
							}
							written <- writeErr
						}()
						var data []byte
						for {
							buffer, readErr := server.WaitReadBuffer()
							if readErr == io.EOF {
								break
							}
							if readErr != nil {
								scenarioTest.Fatal(readErr)
							}
							data = append(data, buffer.Bytes()...)
							buffer.ExtendHeader(91)
							buffer.Extend(73)
							buffer.Release()
						}
						if !bytes.Equal(data, payload) {
							scenarioTest.Fatalf("read waiter received %d/%d", len(data), len(payload))
						}
						writeErr := <-written
						if writeErr != nil {
							scenarioTest.Fatal(writeErr)
						}
					})
				})
			}
		})
	}
}

var (
	_ Handler      = (*kernelStackFixture)(nil)
	_ SpliceSocket = (*kernelSocket)(nil)
)

func TestGoKernelFlowControl(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	configs := []kernelStackConfig{{mtu: 1500}, {mtu: 9000}, {mtu: 65535}}
	if runtime.GOOS == "linux" {
		configs = append(configs, kernelStackConfig{mtu: 1500, gso: true, multiQueue: true}, kernelStackConfig{mtu: 9000, gso: true, multiQueue: true})
	}
	for _, config := range configs {
		t.Run(fmt.Sprintf("mtu=%d/gso=%v/mq=%v", config.mtu, config.gso, config.multiQueue), func(configTest *testing.T) {
			config.socketBuffer = 128 << 10
			config.upstreamSocketBuffer = 128 << 10
			fixture := newKernelStackFixture(configTest, config)
			for _, ipv6 := range []bool{false, true} {
				for _, mode := range []string{"write", "buffer", "splice"} {
					configTest.Run(fmt.Sprintf("ipv6=%v/mode=%s", ipv6, mode), func(test *testing.T) {
						test.Parallel()
						size := 4 << 20
						if runtime.GOOS == "windows" && mode == "splice" {
							size = 16 << 20
						}
						kernelBackpressure(test, fixture, ipv6, mode, size)
					})
				}
			}
		})
	}
}

func kernelBackpressure(t *testing.T, fixture *kernelStackFixture, ipv6 bool, mode string, size int) {
	t.Helper()
	var client, server net.Conn
	if mode == "splice" {
		client, server, _, _ = fixture.splicePair(t, ipv6)
	} else {
		client, server = fixture.pair(t, ipv6)
	}
	err := client.(*net.TCPConn).SetReadBuffer(4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("flow %s -> %s", client.LocalAddr(), client.RemoteAddr())
	deadline := time.Now().Add(10 * time.Second)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	upload := kernelPayload(size, 113)
	download := kernelPayload(size, 127)
	var uploadAccepted, downloadAccepted atomic.Int64
	written := make(chan error, 2)
	go func() { written <- kernelFlowWrite(client, upload, false, &uploadAccepted) }()
	go func() { written <- kernelFlowWrite(server, download, mode == "buffer", &downloadAccepted) }()
	time.Sleep(100 * time.Millisecond)
	if uploadAccepted.Load() == int64(len(upload)) || downloadAccepted.Load() == int64(len(download)) {
		t.Fatalf("stalled readers did not backpressure both writers: upload=%d download=%d", uploadAccepted.Load(), downloadAccepted.Load())
	}
	read := make(chan error, 2)
	go func() { read <- kernelFlowRead(server, upload, mode == "buffer") }()
	go func() { read <- kernelFlowRead(client, download, false) }()
	for range 2 {
		err = <-read
		if err != nil {
			t.Error(err)
		}
	}
	for range 2 {
		err = <-written
		if err != nil {
			t.Error(err)
		}
	}
}

func kernelFlowWrite(conn net.Conn, payload []byte, buffered bool, accepted *atomic.Int64) error {
	for offset := 0; offset < len(payload); {
		length := min(32749, len(payload)-offset)
		var n int
		var err error
		if buffered {
			buffer := buf.NewSize(length + 128)
			buffer.Resize(128, 0)
			common.Must1(buffer.Write(payload[offset : offset+length]))
			err = conn.(N.ExtendedWriter).WriteBuffer(buffer)
			if err == nil {
				n = length
			}
		} else {
			n, err = conn.Write(payload[offset : offset+length])
		}
		offset += n
		accepted.Add(int64(n))
		if err != nil {
			return E.Cause(err, "write flow after ", offset, " bytes")
		}
	}
	return N.CloseWrite(conn)
}

func kernelFlowRead(conn net.Conn, payload []byte, buffered bool) error {
	var waiter N.ReadWaiter
	if buffered {
		var created bool
		waiter, created = bufio.CreateReadWaiter(conn)
		if !created {
			return E.New("flow connection has no read waiter")
		}
		waiter.InitializeReadWaiter(N.ReadWaitOptions{MTU: 4093, FrontHeadroom: 91, RearHeadroom: 73})
	}
	storage := make([]byte, 16381)
	sizes := [...]int{1, 127, 4093, len(storage)}
	paused := 0
	for offset, index := 0, 0; ; index++ {
		if offset/65536 > paused && paused < 4 && offset < len(payload) {
			paused = offset / 65536
			time.Sleep(25 * time.Millisecond)
		}
		var data []byte
		var buffer *buf.Buffer
		var err error
		if buffered {
			buffer, err = waiter.WaitReadBuffer()
			if buffer != nil {
				data = buffer.Bytes()
			}
		} else {
			var n int
			n, err = conn.Read(storage[:sizes[index%len(sizes)]])
			data = storage[:n]
		}
		end := offset + len(data)
		matches := end <= len(payload) && bytes.Equal(data, payload[offset:min(end, len(payload))])
		if buffer != nil {
			buffer.ExtendHeader(91)
			buffer.Extend(73)
			buffer.Release()
		}
		if !matches {
			return E.New("flow mismatch at byte ", offset)
		}
		offset = end
		if err == io.EOF && offset == len(payload) {
			return nil
		}
		if err != nil {
			return E.Cause(err, "read flow after ", offset, "/", len(payload), " bytes")
		}
	}
}

func TestGoKernelSequenceWrap(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, gso: runtime.GOOS == "linux"})
	for _, ipv6 := range []bool{false, true} {
		for _, mode := range []string{"write", "buffer", "splice"} {
			t.Run(fmt.Sprintf("ipv6=%v/mode=%s", ipv6, mode), func(test *testing.T) {
				test.Parallel()
				var client, server net.Conn
				if mode == "splice" {
					client, server, _, _ = fixture.splicePair(test, ipv6)
				} else {
					client, server = fixture.pair(test, ipv6)
				}
				deadline := time.Now().Add(60 * time.Second)
				client.SetDeadline(deadline)
				server.SetDeadline(deadline)
				completed := make(chan error, 1)
				go func() { completed <- kernelWrapTransfer(client, server, false) }()
				err := kernelWrapTransfer(server, client, mode == "buffer")
				if err != nil {
					test.Error("download:", err)
				}
				err = <-completed
				if err != nil {
					test.Error("upload:", err)
				}
			})
		}
	}
}

func kernelWrapTransfer(sender net.Conn, receiver net.Conn, buffered bool) error {
	const total = uint64(1)<<32 | 123
	const blockSize = 32768
	pattern := kernelPayload(blockSize, 53)
	completed := make(chan error, 1)
	go func() {
		block := bytes.Clone(pattern)
		for offset := uint64(0); offset < total; {
			length := min(uint64(blockSize), total-offset)
			binary.BigEndian.PutUint64(block, offset)
			var err error
			if buffered {
				buffer := buf.NewSize(int(length) + 128)
				buffer.Resize(128, 0)
				common.Must1(buffer.Write(block[:length]))
				err = sender.(N.ExtendedWriter).WriteBuffer(buffer)
			} else {
				_, err = sender.Write(block[:length])
			}
			if err != nil {
				completed <- err
				return
			}
			offset += length
		}
		completed <- N.CloseWrite(sender)
	}()
	block := make([]byte, blockSize)
	for offset := uint64(0); offset < total; {
		length := min(uint64(blockSize), total-offset)
		_, err := io.ReadFull(receiver, block[:length])
		if err != nil {
			return E.Cause(err, "read sequence offset ", offset)
		}
		if binary.BigEndian.Uint64(block) != offset || !bytes.Equal(block[8:length], pattern[8:length]) {
			return E.New("sequence data mismatch at ", offset)
		}
		offset += length
	}
	_, err := receiver.Read(block[:1])
	if err != io.EOF {
		return E.New("sequence stream end: ", err)
	}
	return <-completed
}
