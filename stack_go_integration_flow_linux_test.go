//go:build linux && !android

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func TestGoKernelWindowClamp(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	cases := []struct {
		window int
		mss    int
		loss   bool
	}{
		{window: 2048},
		{window: 4096, mss: 512},
		{window: 16384, loss: true},
	}
	for _, scenario := range cases {
		t.Run(fmt.Sprintf("window=%d/mss=%d/loss=%v", scenario.window, scenario.mss, scenario.loss), func(configTest *testing.T) {
			size := 256 << 10
			config := kernelStackConfig{mtu: 9000, socketBuffer: 4096, upstreamSocketBuffer: 4096, gso: scenario.loss, multiQueue: scenario.loss}
			config.dialer = net.Dialer{Control: func(_, _ string, rawConn syscall.RawConn) error {
				var optionErr error
				err := rawConn.Control(func(descriptor uintptr) {
					optionErr = unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_RCVBUF, 4096)
					if optionErr != nil {
						return
					}
					optionErr = unix.SetsockoptInt(int(descriptor), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, scenario.window)
					if optionErr != nil || scenario.mss == 0 {
						return
					}
					optionErr = unix.SetsockoptInt(int(descriptor), unix.IPPROTO_TCP, unix.TCP_MAXSEG, scenario.mss)
				})
				return E.Errors(err, optionErr)
			}}
			if scenario.loss {
				size = 1 << 20
				config.upstreamSocketBuffer = 64 << 10
				config.configure = configureKernelLoss
			}
			fixture := newKernelStackFixture(configTest, config)
			for _, ipv6 := range []bool{false, true} {
				for _, mode := range []string{"write", "buffer", "splice"} {
					configTest.Run(fmt.Sprintf("ipv6=%v/mode=%s", ipv6, mode), func(test *testing.T) {
						test.Parallel()
						kernelBackpressure(test, fixture, ipv6, mode, size)
					})
				}
			}
		})
	}
}

func TestGoKernelReceiveWindowUpdateLoss(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, socketBuffer: 4096})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			client, server := fixture.pair(test, ipv6)
			payload := kernelPayload(512<<10, 131)
			written := make(chan error, 1)
			go func() {
				_, err := client.Write(payload)
				if err == nil {
					err = client.CloseWrite()
				}
				written <- err
			}()
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if server.sentEdge.Load()-server.receiveAvailable.Load() < 1<<server.localWindowShift {
					break
				}
				time.Sleep(time.Millisecond)
			}
			available := server.receiveAvailable.Load() - 1
			if available == 0 || server.sentEdge.Load()-server.receiveAvailable.Load() >= 1<<server.localWindowShift {
				test.Fatal("Go receive window did not close")
			}
			commands := [][]string{
				{"qdisc", "add", "dev", fixture.options.Name, "ingress"},
				{"filter", "add", "dev", fixture.options.Name, "parent", "ffff:", "protocol", "all", "u32", "match", "u32", "0", "0", "action", "drop"},
			}
			for _, command := range commands {
				output, err := exec.Command("tc", command...).CombinedOutput()
				if err != nil {
					test.Fatalf("tc %v: %s: %v", command, output, err)
				}
				if command[0] == "qdisc" {
					test.Cleanup(func() { exec.Command("tc", "qdisc", "del", "dev", fixture.options.Name, "ingress").Run() })
				}
			}
			data := make([]byte, len(payload))
			_, err := io.ReadFull(server, data[:available])
			if err != nil {
				test.Fatal(err)
			}
			time.Sleep(100 * time.Millisecond)
			output, err := exec.Command("tc", "qdisc", "del", "dev", fixture.options.Name, "ingress").CombinedOutput()
			if err != nil {
				test.Fatalf("remove ingress loss: %s: %v", output, err)
			}
			server.SetReadDeadline(time.Now().Add(4 * time.Second))
			_, err = io.ReadFull(server, data[available:])
			if err != nil {
				test.Fatal("recover Go receive window:", err)
			}
			if !bytes.Equal(data, payload) {
				test.Fatal("receive window recovery corrupted the stream")
			}
			_, err = server.Read(data[:1])
			if err != io.EOF {
				test.Fatalf("stream end: %v", err)
			}
			err = <-written
			if err != nil {
				test.Fatal(err)
			}
		})
	}
}

func TestGoKernelSACKReneging(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			client, server := fixture.pair(test, ipv6)
			runTC := func(args ...string) {
				test.Helper()
				output, err := exec.Command("tc", args...).CombinedOutput()
				if err != nil {
					test.Fatalf("tc %v: %s: %v", args, output, err)
				}
			}
			protocol := "ip"
			offset := "24"
			if ipv6 {
				protocol = "ipv6"
				offset = "44"
			}
			runTC("qdisc", "add", "dev", fixture.options.Name, "ingress")
			test.Cleanup(func() { exec.Command("tc", "qdisc", "del", "dev", fixture.options.Name, "ingress").Run() })
			runTC("filter", "add", "dev", fixture.options.Name, "parent", "ffff:", "protocol", protocol,
				"u32", "match", "u32", fmt.Sprintf("0x%08x", server.sendISN+1), "0xffffffff", "at", offset, "action", "drop")
			payload := kernelPayload(8*int(server.effectiveMSS), 137)
			_, err := server.Write(payload)
			if err != nil {
				test.Fatal(err)
			}
			rawConn, err := client.SyscallConn()
			if err != nil {
				test.Fatal(err)
			}
			var info *unix.TCPInfo
			var infoErr error
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				err = rawConn.Control(func(descriptor uintptr) {
					info, infoErr = unix.GetsockoptTCPInfo(int(descriptor), unix.IPPROTO_TCP, unix.TCP_INFO)
				})
				if err != nil || infoErr != nil {
					test.Fatal(E.Errors(err, infoErr))
				}
				if info.Rcv_ooopack >= 7 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if info == nil || info.Rcv_ooopack < 7 || server.sendUnacked.Load() != 1 {
				test.Fatalf("missing out-of-order kernel queue: info=%+v unacked=%d", info, server.sendUnacked.Load())
			}
			pruned := kernelTCPStatistic(test, "OfoPruned")
			err = client.SetReadBuffer(512)
			if err != nil {
				test.Fatal(err)
			}
			runTC("qdisc", "del", "dev", fixture.options.Name, "ingress")
			deadline = time.Now().Add(2 * time.Second)
			for kernelTCPStatistic(test, "OfoPruned") == pruned && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if kernelTCPStatistic(test, "OfoPruned") == pruned {
				test.Fatal("kernel did not discard SACKed data")
			}
			err = client.SetReadBuffer(64 << 10)
			if err != nil {
				test.Fatal(err)
			}
			client.SetReadDeadline(time.Now().Add(4 * time.Second))
			data := make([]byte, len(payload))
			n, err := io.ReadFull(client, data)
			if err != nil || !bytes.Equal(data, payload) {
				test.Fatalf("SACK reneging: received=%d/%d pruned=%d: %v", n, len(payload), kernelTCPStatistic(test, "OfoPruned")-pruned, err)
			}
			err = server.CloseWrite()
			if err != nil {
				test.Fatal(err)
			}
			_, err = client.Read(data[:1])
			if err != io.EOF {
				test.Fatalf("stream end after SACK reneging: %v", err)
			}
		})
	}
}

func TestGoKernelZeroWindowHalfClose(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			test.Parallel()
			config := kernelStackConfig{mtu: 9000, socketBuffer: 512}
			config.dialer = net.Dialer{Control: func(_, _ string, rawConn syscall.RawConn) error {
				var optionErr error
				err := rawConn.Control(func(descriptor uintptr) {
					optionErr = unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_RCVBUF, 512)
					if optionErr == nil {
						optionErr = unix.SetsockoptInt(int(descriptor), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, 1024)
					}
				})
				return E.Errors(err, optionErr)
			}}
			fixture := newKernelStackFixture(test, config)
			client, server := fixture.pair(test, ipv6)
			payload := kernelPayload(int(server.sendPermit.Load()-1), 139)
			_, err := server.Write(payload)
			if err != nil {
				test.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				if server.sendUnacked.Load() == uint64(len(payload)+1) && server.sendPermit.Load() == server.sendUnacked.Load() {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if server.sendUnacked.Load() != uint64(len(payload)+1) || server.sendPermit.Load() != server.sendUnacked.Load() {
				test.Fatalf("window did not close after acknowledging all data: length=%d unacked=%d permit=%d", len(payload), server.sendUnacked.Load(), server.sendPermit.Load())
			}
			output, err := exec.Command("tc", "qdisc", "add", "dev", fixture.options.Name, "root", "netem", "loss", "100%").CombinedOutput()
			if err != nil {
				test.Fatalf("drop FIN acknowledgment: %s: %v", output, err)
			}
			err = server.CloseWrite()
			if err != nil {
				test.Fatal(err)
			}
			time.Sleep(1600 * time.Millisecond)
			err = client.SetReadBuffer(64 << 10)
			if err != nil {
				test.Fatal(err)
			}
			data := make([]byte, len(payload))
			_, err = io.ReadFull(client, data)
			if err != nil || !bytes.Equal(data, payload) {
				test.Fatalf("half-close data: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			output, err = exec.Command("tc", "qdisc", "del", "dev", fixture.options.Name, "root").CombinedOutput()
			if err != nil {
				test.Fatalf("restore acknowledgments: %s: %v", output, err)
			}
			client.SetReadDeadline(time.Now().Add(4 * time.Second))
			_, err = client.Read(data[:1])
			if err != io.EOF {
				test.Fatalf("zero-window FIN: %v", err)
			}
			err = client.CloseWrite()
			if err != nil {
				test.Fatal(err)
			}
			_, err = server.Read(data[:1])
			if err != io.EOF {
				test.Fatalf("peer FIN: %v", err)
			}
		})
	}
}

func kernelTCPStatistic(t *testing.T, name string) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/net/netstat")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	for index := 0; index+1 < len(lines); index += 2 {
		fields := strings.Fields(lines[index])
		if len(fields) == 0 || fields[0] != "TcpExt:" {
			continue
		}
		values := strings.Fields(lines[index+1])
		for fieldIndex, field := range fields {
			if field == name {
				value, parseErr := strconv.ParseUint(values[fieldIndex], 10, 64)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				return value
			}
		}
	}
	t.Fatal("missing TCP statistic:", name)
	return 0
}

func TestGoKernelWindowLimitedRecovery(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			test.Parallel()
			fixture := newKernelStackFixture(test, kernelStackConfig{mtu: 9000})
			client, server := fixture.pair(test, ipv6)
			err := client.SetReadBuffer(4096)
			if err != nil {
				test.Fatal(err)
			}
			output, err := exec.Command("tc", "qdisc", "add", "dev", fixture.options.Name, "root", "netem", "delay", "50ms").CombinedOutput()
			if err != nil {
				test.Fatalf("delay ACKs: %s: %v", output, err)
			}
			payload := kernelPayload(8<<20, 223)
			initial := 4 * int(server.effectiveMSS)
			_, err = server.Write(payload[:initial])
			if err != nil {
				test.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				if server.sendPermit.Load() == server.sendUnacked.Load() && server.sentTail.Load() > server.sendUnacked.Load()+2*uint64(server.effectiveMSS) {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if server.sendPermit.Load() != server.sendUnacked.Load() || server.sentTail.Load() <= server.sendUnacked.Load()+2*uint64(server.effectiveMSS) {
				test.Fatal("window did not shrink below outstanding data")
			}
			completed := make(chan kernelIOResult, 1)
			server.SetWriteDeadline(time.Now().Add(2 * time.Second))
			go func() {
				n, writeErr := server.Write(payload[initial:])
				completed <- kernelIOResult{n: n + initial, err: writeErr}
			}()
			deadline = time.Now().Add(time.Second)
			for !server.writerParked.Load() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !server.writerParked.Load() {
				test.Fatal("write did not block at the closed window")
			}
			server.SetWriteDeadline(time.Now())
			var accepted int
			select {
			case result := <-completed:
				if !errors.Is(result.err, os.ErrDeadlineExceeded) || result.n <= 0 || result.n >= len(payload) {
					test.Fatalf("interrupt blocked write: %+v", result)
				}
				accepted = result.n
			case <-time.After(time.Second):
				test.Fatal("write did not react to deadline")
			}
			output, err = exec.Command("tc", "qdisc", "del", "dev", fixture.options.Name, "root").CombinedOutput()
			if err != nil {
				test.Fatalf("restore ACKs: %s: %v", output, err)
			}
			err = client.SetReadBuffer(4 << 20)
			if err != nil {
				test.Fatal(err)
			}
			rawConn, err := client.SyscallConn()
			if err != nil {
				test.Fatal(err)
			}
			var optionErr error
			err = rawConn.Control(func(descriptor uintptr) {
				optionErr = unix.SetsockoptInt(int(descriptor), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, 6144)
			})
			if err != nil || optionErr != nil {
				test.Fatalf("limit receive window: %v %v", err, optionErr)
			}
			server.SetWriteDeadline(time.Now().Add(4 * time.Second))
			client.SetReadDeadline(time.Now().Add(4 * time.Second))
			go func() {
				n, writeErr := server.Write(payload[accepted:])
				if writeErr == nil {
					writeErr = server.CloseWrite()
				}
				completed <- kernelIOResult{n: n + accepted, err: writeErr}
			}()
			data, err := io.ReadAll(client)
			if err != nil || !bytes.Equal(data, payload) {
				test.Fatalf("window-limited recovery: received=%d/%d accepted=%d: %v", len(data), len(payload), accepted, err)
			}
			select {
			case result := <-completed:
				if result.err != nil || result.n != len(payload) {
					test.Fatalf("resume blocked write: %+v", result)
				}
			case <-time.After(time.Second):
				test.Fatal("write remained blocked after recovery")
			}
		})
	}
}

func TestGoKernelZeroWindow(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 9000})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			client, server := fixture.pair(test, ipv6)
			err := client.SetReadBuffer(4096)
			if err != nil {
				test.Fatal(err)
			}
			runTC := func(args ...string) {
				test.Helper()
				output, commandErr := exec.Command("tc", args...).CombinedOutput()
				if commandErr != nil {
					test.Fatalf("tc %v: %s: %v", args, output, commandErr)
				}
			}
			runTC("qdisc", "replace", "dev", fixture.options.Name, "root", "netem", "delay", "50ms")
			payload := kernelPayload(32768, 107)
			_, err = server.Write(payload)
			if err != nil {
				test.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				if server.sendPermit.Load() == server.sendUnacked.Load() && server.sentTail.Load() == server.bufferedTail.Load() {
					break
				}
				time.Sleep(time.Millisecond)
			}
			unacked := server.sendUnacked.Load()
			if server.sendPermit.Load() != unacked || server.sentTail.Load() != uint64(len(payload)+1) || unacked <= 1 || unacked >= server.sentTail.Load() {
				test.Fatalf("window did not close with only outstanding data: unacked=%d sent=%d buffered=%d permit=%d", unacked, server.sentTail.Load(), server.bufferedTail.Load(), server.sendPermit.Load())
			}
			runTC("qdisc", "replace", "dev", fixture.options.Name, "root", "netem", "loss", "100%")
			err = client.SetReadBuffer(4 << 20)
			if err != nil {
				test.Fatal(err)
			}
			data := make([]byte, len(payload))
			_, err = io.ReadFull(client, data[:unacked-1])
			if err != nil {
				test.Fatal(err)
			}
			time.Sleep(100 * time.Millisecond)
			runTC("qdisc", "del", "dev", fixture.options.Name, "root")
			client.SetReadDeadline(time.Now().Add(4 * time.Second))
			_, err = io.ReadFull(client, data[unacked-1:])
			if err != nil {
				test.Fatal("recover lost window update:", err)
			}
			if !bytes.Equal(data, payload) {
				test.Fatal("zero-window recovery corrupted the stream")
			}
		})
	}
}
