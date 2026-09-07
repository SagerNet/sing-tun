//go:build linux && !android

package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

func TestGoKernelHandshakeLoss(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, phase := range []string{"syn_ack", "final_ack"} {
			for _, cancelHandshake := range []bool{false, true} {
				t.Run(fmt.Sprintf("ipv6=%v/phase=%s/cancel=%v", ipv6, phase, cancelHandshake), func(test *testing.T) {
					test.Parallel()
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					observed := make(chan *GoConn, 1)
					fixture := newKernelStackFixture(test, kernelStackConfig{mtu: 1500, ctx: ctx, handshake: func(conn *GoConn) error {
						observed <- conn
						return conn.HandshakeSuccess()
					}})
					direction, parent, flags := "ingress", "ffff:", "0x12"
					if phase == "final_ack" {
						direction, parent, flags = "root", "1:", "0x10"
					}
					protocol, offset := "ip", "33"
					if ipv6 {
						protocol, offset = "ipv6", "53"
					}
					command := []string{"qdisc", "add", "dev", fixture.options.Name, direction}
					if direction == "root" {
						command = append(command, "handle", "1:", "prio")
					}
					output, err := exec.Command("tc", command...).CombinedOutput()
					if err != nil {
						test.Fatalf("handshake qdisc: %s: %v", output, err)
					}
					test.Cleanup(func() { exec.Command("tc", "qdisc", "del", "dev", fixture.options.Name, direction).Run() })
					output, err = exec.Command("tc", "filter", "add", "dev", fixture.options.Name, "parent", parent, "protocol", protocol,
						"u32", "match", "u8", flags, "0x12", "at", offset, "action", "drop").CombinedOutput()
					if err != nil {
						test.Fatalf("handshake filter: %s: %v", output, err)
					}
					port := uint16(20000 + fixture.port.Add(1))
					accepted := make(chan kernelAccept, 1)
					fixture.access.Lock()
					fixture.tcp[port] = accepted
					fixture.access.Unlock()
					type dialResult struct {
						conn net.Conn
						err  error
					}
					dialed := make(chan dialResult, 1)
					go func() {
						conn, dialErr := fixture.dialer.DialContext(ctx, "tcp", fixture.address(ipv6, port))
						dialed <- dialResult{conn: conn, err: dialErr}
					}()
					select {
					case conn := <-observed:
						test.Cleanup(func() { conn.Close() })
					case <-time.After(time.Second):
						test.Fatal("SYN did not reach the application")
					}
					select {
					case result := <-accepted:
						test.Fatalf("handshake completed while packets were dropped: %v", result.err)
					case <-time.After(250 * time.Millisecond):
					}
					output, err = exec.Command("tc", "-s", "filter", "show", "dev", fixture.options.Name, "parent", parent).CombinedOutput()
					if err != nil || !regexp.MustCompile(`dropped [1-9][0-9]*`).Match(output) {
						test.Fatalf("no handshake packet was dropped: %s: %v", output, err)
					}
					if cancelHandshake {
						cancel()
					} else {
						output, err = exec.Command("tc", "qdisc", "del", "dev", fixture.options.Name, direction).CombinedOutput()
						if err != nil {
							test.Fatalf("restore handshake traffic: %s: %v", output, err)
						}
					}
					var result kernelAccept
					select {
					case result = <-accepted:
						if cancelHandshake {
							if !errors.Is(result.err, context.Canceled) {
								test.Fatalf("cancel pending handshake: %v", result.err)
							}
						} else if result.err != nil {
							test.Fatal("recover handshake:", result.err)
						}
					case <-time.After(2 * time.Second):
						test.Fatal("handshake did not react to recovery/cancellation")
					}
					select {
					case peer := <-dialed:
						if peer.conn != nil {
							defer peer.conn.Close()
						}
						if !cancelHandshake {
							if peer.err != nil {
								test.Fatal(peer.err)
							}
							peer.conn.SetDeadline(time.Now().Add(3 * time.Second))
							err = kernelTransfer(result.conn, peer.conn, kernelPayload(32769, 233), true)
							if err != nil {
								test.Fatal("stream after handshake loss:", err)
							}
						}
					case <-time.After(time.Second):
						test.Fatal("native dial remained pending")
					}
				})
			}
		}
	}
}

func TestGoKernelLinkInterruption(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, mode := range []string{"write", "buffer", "splice"} {
			t.Run(fmt.Sprintf("ipv6=%v/mode=%s", ipv6, mode), func(test *testing.T) {
				test.Parallel()
				fixture := newKernelStackFixture(test, kernelStackConfig{mtu: 1500})
				var client, server net.Conn
				if mode == "splice" {
					client, server, _, _ = fixture.splicePair(test, ipv6)
				} else {
					client, server = fixture.pair(test, ipv6)
				}
				runTC := func(args ...string) []byte {
					test.Helper()
					output, err := exec.Command("tc", args...).CombinedOutput()
					if err != nil {
						test.Fatalf("tc %v: %s: %v", args, output, err)
					}
					return output
				}
				for phase := range 3 {
					runTC("qdisc", "add", "dev", fixture.options.Name, "root", "netem", "loss", "100%")
					runTC("qdisc", "add", "dev", fixture.options.Name, "ingress")
					runTC("filter", "add", "dev", fixture.options.Name, "parent", "ffff:", "protocol", "all",
						"u32", "match", "u32", "0", "0", "action", "drop")
					written := make(chan error, 2)
					read := make(chan error, 2)
					for direction := range 2 {
						sender, receiver := client, server
						if direction == 1 {
							sender, receiver = server, client
						}
						payload := kernelPayload(256<<10|123, uint32(239+phase*7+direction))
						go func() {
							var err error
							if direction == 1 && mode == "buffer" {
								buffer := buf.NewSize(len(payload) + 128)
								buffer.Resize(128, 0)
								common.Must1(buffer.Write(payload))
								err = sender.(N.ExtendedWriter).WriteBuffer(buffer)
							} else {
								_, err = sender.Write(payload)
							}
							if err == nil && phase == 2 {
								err = N.CloseWrite(sender)
							}
							written <- err
						}()
						go func() {
							data := make([]byte, len(payload))
							_, err := io.ReadFull(receiver, data)
							if err == nil && !bytes.Equal(data, payload) {
								err = E.New("link recovery payload mismatch")
							}
							if err == nil && phase == 2 {
								_, err = receiver.Read(data[:1])
								if err == io.EOF {
									err = nil
								} else {
									err = E.New("link recovery stream end: ", err)
								}
							}
							read <- err
						}()
					}
					select {
					case err := <-read:
						test.Fatalf("phase %d: stream completed during link outage: %v", phase, err)
					case <-time.After(250 * time.Millisecond):
					}
					dropPattern := regexp.MustCompile(`dropped [1-9][0-9]*`)
					deadline := time.Now().Add(2 * time.Second)
					for {
						bothDropped := true
						for _, output := range [][]byte{
							runTC("-s", "qdisc", "show", "dev", fixture.options.Name),
							runTC("-s", "filter", "show", "dev", fixture.options.Name, "parent", "ffff:"),
						} {
							if dropPattern.Match(output) {
								continue
							}
							if time.Now().After(deadline) {
								test.Fatalf("phase %d: link outage did not drop traffic: %s", phase, output)
							}
							bothDropped = false
						}
						if bothDropped {
							break
						}
						select {
						case err := <-read:
							test.Fatalf("phase %d: stream completed during link outage: %v", phase, err)
						case <-time.After(20 * time.Millisecond):
						}
					}
					runTC("qdisc", "del", "dev", fixture.options.Name, "root")
					runTC("qdisc", "del", "dev", fixture.options.Name, "ingress")
					for range 2 {
						err := <-written
						if err != nil {
							test.Fatal("write through link outage:", err)
						}
						err = <-read
						if err != nil {
							test.Fatal("read after link recovery:", err)
						}
					}
				}
			})
		}
	}
}

func configureKernelLoss(t *testing.T, options Options) {
	t.Helper()
	ifbName := "ifb-" + options.Name
	commands := [][]string{
		{"ip", "link", "add", ifbName, "type", "ifb"},
		{"ip", "link", "set", ifbName, "up"},
		{"tc", "qdisc", "add", "dev", options.Name, "root", "netem", "delay", "2ms", "1ms", "loss", "1%", "reorder", "10%", "50%", "limit", "4096"},
		{"tc", "qdisc", "add", "dev", options.Name, "ingress"},
		{"tc", "filter", "add", "dev", options.Name, "parent", "ffff:", "protocol", "all", "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", ifbName},
		{"tc", "qdisc", "add", "dev", ifbName, "root", "netem", "delay", "2ms", "1ms", "loss", "1%", "reorder", "10%", "50%", "limit", "4096"},
	}
	for index, command := range commands {
		output, err := exec.Command(command[0], command[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s: %v", command, output, err)
		}
		if index == 0 {
			t.Cleanup(func() { exec.Command("ip", "link", "delete", ifbName).Run() })
		}
	}
}

func TestGoKernelBidirectionalLoss(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	for _, gso := range []bool{false, true} {
		for _, multiQueue := range []bool{false, true} {
			t.Run(fmt.Sprintf("gso=%v/mq=%v", gso, multiQueue), func(offloadTest *testing.T) {
				fixture := newKernelStackFixture(offloadTest, kernelStackConfig{mtu: 1500, gso: gso, multiQueue: multiQueue, configure: configureKernelLoss})
				for _, ipv6 := range []bool{false, true} {
					for _, splice := range []bool{false, true} {
						offloadTest.Run(fmt.Sprintf("ipv6=%v/splice=%v", ipv6, splice), func(flowTest *testing.T) {
							flowTest.Parallel()
							var client, server net.Conn
							if splice {
								client, server, _, _ = fixture.splicePair(flowTest, ipv6)
							} else {
								client, server = fixture.pair(flowTest, ipv6)
							}
							payload := kernelPayload(1<<20, 43)
							response := kernelPayload(1<<20, 47)
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
				}
			})
		}
	}
}
