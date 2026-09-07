//go:build darwin && !ios

package tun

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	kernelConnectionRefused = unix.ECONNREFUSED
	kernelConnectionReset   = unix.ECONNRESET
)

func TestGoKernelMemoryPressure(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	configs := []kernelStackConfig{{mtu: 1500}, {mtu: 1500, prepare: prepareKernelNetif}, {mtu: 9000, prepare: prepareKernelNetif}}
	for _, config := range configs {
		t.Run(fmt.Sprintf("mtu=%d/netif=%v", config.mtu, config.prepare != nil), func(configTest *testing.T) {
			var pressure atomic.Uint32
			config.pressure = func() MemoryPressure { return MemoryPressure(pressure.Load()) }
			fixture := newKernelStackFixture(configTest, config)
			configTest.Logf("utun netif mode: %v", fixture.stack.engines[0].platformIO.(*goDarwinIO).netif)
			for _, level := range []MemoryPressure{MemoryPressureWarning, MemoryPressureCritical, MemoryPressureNone} {
				configTest.Run(fmt.Sprintf("level=%d", level), func(test *testing.T) {
					pressure.Store(uint32(level))
					for _, splice := range []bool{false, true} {
						test.Run(fmt.Sprintf("splice=%v", splice), func(flowTest *testing.T) {
							var client, server net.Conn
							if splice {
								client, server, _, _ = fixture.splicePair(flowTest, true)
							} else {
								client, server = fixture.pair(flowTest, true)
							}
							payload := kernelPayload(8<<20, 79)
							response := kernelPayload(8<<20, 83)
							result := make(chan error, 1)
							go func() { result <- kernelTransfer(client, server, payload, false) }()
							err := kernelTransfer(server, client, response, !splice)
							if err != nil {
								flowTest.Error("download:", err)
							}
							err = <-result
							if err != nil {
								flowTest.Error("upload:", err)
							}
						})
					}
				})
			}
		})
	}
}

func prepareKernelNetif(t *testing.T, options *Options) {
	t.Helper()
	socketFD, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		t.Fatal(err)
	}
	transferred := false
	defer func() {
		if !transferred {
			unix.Close(socketFD)
		}
	}()
	var controlInfo unix.CtlInfo
	copy(controlInfo.Name[:], utunControlName)
	err = unix.IoctlCtlInfo(socketFD, &controlInfo)
	if err != nil {
		t.Fatal(err)
	}
	var index int
	_, err = fmt.Sscanf(options.Name, "utun%d", &index)
	if err != nil {
		t.Fatal(err)
	}
	address := &unix.SockaddrCtl{ID: controlInfo.Id, Unit: uint32(index + 1)}
	err = unix.Bind(socketFD, address)
	if err != nil {
		t.Fatal(err)
	}
	err = unix.SetsockoptInt(socketFD, sysprotoControl, utunOptionEnableNetif, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = unix.Connect(socketFD, address)
	if err != nil {
		t.Fatal(err)
	}
	options.FileDescriptor = socketFD
	transferred = true
}

func configureKernelInterface(t *testing.T, device Tun, options Options) {
	t.Helper()
	ipv4 := options.Inet4Address[0]
	ipv6 := options.Inet6Address[0]
	commands := [][]string{
		{"/sbin/ifconfig", options.Name, "mtu", fmt.Sprint(options.MTU)},
		{"/sbin/ifconfig", options.Name, "inet", ipv4.Addr().String(), ipv4.Addr().String(), "netmask", "255.255.255.0", "up"},
		{"/sbin/ifconfig", options.Name, "inet6", ipv6.String(), "-dad"},
		{"/sbin/route", "-n", "add", "-net", ipv4.Masked().String(), "-interface", options.Name},
	}
	for _, command := range commands {
		output, err := exec.Command(command[0], command[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s: %v", command, output, err)
		}
	}
}

func TestGoKernelDeviceBackpressure(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	for _, mtu := range []uint32{1500, 9000} {
		for _, shutdown := range []bool{false, true} {
			t.Run(fmt.Sprintf("mtu=%d/shutdown=%v", mtu, shutdown), func(test *testing.T) {
				fixture := newKernelStackFixture(test, kernelStackConfig{mtu: mtu, prepare: prepareKernelNetif})
				platform := fixture.stack.engines[0].platformIO.(*goDarwinIO)
				if !platform.netif {
					test.Fatal("utun netif was not enabled")
				}
				observed := make(chan struct{}, 1)
				stop := make(chan struct{})
				defer close(stop)
				go func() {
					ticker := time.NewTicker(50 * time.Microsecond)
					defer ticker.Stop()
					for {
						select {
						case <-ticker.C:
							if platform.gateBlocked.Load() {
								observed <- struct{}{}
								return
							}
						case <-stop:
							return
						}
					}
				}()
				payload := kernelPayload(32<<20, 223)
				written := make(chan error, 8)
				read := make(chan error, 8)
				start := make(chan struct{})
				var clients []net.Conn
				for index := range 8 {
					var client, server net.Conn
					splice := index%2 != 0
					if splice {
						client, server, _, _ = fixture.splicePair(test, index%4 >= 2)
					} else {
						client, server = fixture.pair(test, index%4 >= 2)
					}
					clients = append(clients, client)
					go func() {
						<-start
						var accepted atomic.Int64
						written <- kernelFlowWrite(server, payload, !splice, &accepted)
					}()
					go func() {
						<-start
						data, err := io.ReadAll(io.LimitReader(client, int64(len(payload)+1)))
						if err == nil && !bytes.Equal(data, payload) {
							err = E.New("device backpressure payload mismatch")
						}
						read <- err
					}()
				}
				close(start)
				select {
				case <-observed:
				case <-time.After(3 * time.Second):
					test.Fatal("real netif transmit gate never became blocked")
				}
				if shutdown {
					started := time.Now()
					err := fixture.stack.Close()
					if err != nil || time.Since(started) > time.Second {
						test.Fatalf("close during device backpressure: %v", err)
					}
				}
				interrupted := 0
				limit := time.After(12 * time.Second)
				if shutdown {
					limit = time.After(time.Second)
				}
				for range 8 {
					select {
					case err := <-written:
						if shutdown {
							if E.IsTimeout(err) {
								test.Error("device-blocked I/O timed out after close:", err)
							}
							if err != nil {
								interrupted++
							}
						} else if err != nil {
							test.Error("transfer after device backpressure:", err)
						}
					case <-limit:
						test.Fatal("device-blocked I/O did not complete")
					}
				}
				if shutdown && interrupted == 0 {
					test.Error("all writers finished before shutdown")
				}
				if shutdown {
					for _, client := range clients {
						client.Close()
					}
				}
				for range 8 {
					select {
					case err := <-read:
						if !shutdown && err != nil {
							test.Error("read after device backpressure:", err)
						}
					case <-limit:
						test.Fatal("device backpressure reader did not complete")
					}
				}
				if platform.leakedClusters.total.Load() != 0 {
					test.Fatal("utun reported ENOSPC while applying device backpressure")
				}
			})
		}
	}
}

func TestGoKernelMemoryPressureTransition(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	for _, netif := range []bool{false, true} {
		for _, ipv6 := range []bool{false, true} {
			for _, splice := range []bool{false, true} {
				t.Run(fmt.Sprintf("netif=%v/ipv6=%v/splice=%v", netif, ipv6, splice), func(test *testing.T) {
					test.Parallel()
					var pressure, observed atomic.Uint32
					config := kernelStackConfig{mtu: 1500, socketBuffer: 128 << 10, upstreamSocketBuffer: 128 << 10}
					config.pressure = func() MemoryPressure {
						level := pressure.Load()
						observed.Or(1 << level)
						return MemoryPressure(level)
					}
					if netif {
						config.prepare = prepareKernelNetif
					}
					fixture := newKernelStackFixture(test, config)
					var client, server net.Conn
					if splice {
						client, server, _, _ = fixture.splicePair(test, ipv6)
					} else {
						client, server = fixture.pair(test, ipv6)
					}
					const phaseSize = 4 << 20
					upload := kernelPayload(3*phaseSize, 227)
					download := kernelPayload(3*phaseSize, 229)
					var uploadAccepted, downloadAccepted atomic.Int64
					written := make(chan error, 2)
					go func() { written <- kernelFlowWrite(client, upload, false, &uploadAccepted) }()
					go func() { written <- kernelFlowWrite(server, download, !splice, &downloadAccepted) }()
					time.Sleep(100 * time.Millisecond)
					if uploadAccepted.Load() == int64(len(upload)) || downloadAccepted.Load() == int64(len(download)) {
						test.Fatal("pressure transition requires both writers to be active")
					}
					for phase, level := range []MemoryPressure{MemoryPressureWarning, MemoryPressureCritical, MemoryPressureNone} {
						observed.And(^(1 << uint32(level)))
						pressure.Store(uint32(level))
						read := make(chan error, 2)
						for direction, conn := range []net.Conn{server, client} {
							expected := upload
							if direction == 1 {
								expected = download
							}
							go func() {
								data := make([]byte, phaseSize)
								_, err := io.ReadFull(conn, data)
								if err == nil && !bytes.Equal(data, expected[phase*phaseSize:(phase+1)*phaseSize]) {
									err = E.New("pressure transition payload mismatch")
								}
								read <- err
							}()
						}
						for range 2 {
							err := <-read
							if err != nil {
								test.Fatal("active stream pressure transition:", err)
							}
						}
						if observed.Load()&(1<<uint32(level)) == 0 {
							test.Fatalf("pressure level %d was not observed during transfer", level)
						}
					}
					for range 2 {
						err := <-written
						if err != nil {
							test.Fatal(err)
						}
					}
					for _, conn := range []net.Conn{server, client} {
						_, err := conn.Read(make([]byte, 1))
						if err != io.EOF {
							test.Fatalf("EOF after pressure transitions: %v", err)
						}
					}
				})
			}
		}
	}
}
