//go:build darwin && !ios

package tun

import (
	"bytes"
	"fmt"
	"io"
	"net"
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

func kernelSetSocketBuffers(descriptor uintptr, size int) error {
	return E.Errors(
		unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_RCVBUF, size),
		unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_SNDBUF, size),
	)
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
		{"/sbin/ifconfig", options.Name, "inet", ipv4.Addr().String(), ipv4.Addr().String(), "netmask", net.IP(net.CIDRMask(ipv4.Bits(), 32)).String(), "up"},
		{"/sbin/ifconfig", options.Name, "inet6", ipv6.String(), "-dad"},
		{"/sbin/route", "-n", "add", "-net", ipv4.Masked().String(), "-interface", options.Name},
	}
	for _, command := range commands {
		output, err := kernelCommand(command[0], command[1:]...)
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
					closed := make(chan error, 1)
					go func() { closed <- fixture.stack.Close() }()
					select {
					case err := <-closed:
						if err != nil {
							test.Fatal("close during device backpressure:", err)
						}
					case <-time.After(time.Second):
						test.Fatal("close during device backpressure exceeded 1 second")
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
