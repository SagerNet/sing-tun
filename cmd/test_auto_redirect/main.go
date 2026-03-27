//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	autoClientModeArg = "client"
	autoTestTarget    = "198.18.0.1:65000"
)

type redirectEvent struct {
	source      string
	destination string
	processID   uint32
	processPath string
}

type testHandler struct {
	redirectEvents chan redirectEvent
}

func newTestHandler(bufferSize int) *testHandler {
	return &testHandler{
		redirectEvents: make(chan redirectEvent, bufferSize),
	}
}

func (h *testHandler) PrepareConnection(
	network string,
	source M.Socksaddr,
	destination M.Socksaddr,
	routeContext tun.DirectRouteContext,
	timeout time.Duration,
) (tun.DirectRouteDestination, error) {
	return nil, nil
}

func (h *testHandler) NewConnectionEx(
	ctx context.Context,
	conn net.Conn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	if metadata := tun.AutoRedirectMetadataFromContext(ctx); metadata != nil {
		fmt.Printf("[redirect] source=%s destination=%s pid=%d path=%s\n",
			source, destination, metadata.ProcessID, metadata.ProcessPath)
		h.redirectEvents <- redirectEvent{
			source:      source.String(),
			destination: destination.String(),
			processID:   metadata.ProcessID,
			processPath: metadata.ProcessPath,
		}
	} else {
		fmt.Printf("[redirect] source=%s destination=%s metadata=<nil>\n", source, destination)
		h.redirectEvents <- redirectEvent{
			source:      source.String(),
			destination: destination.String(),
		}
	}
	_, _ = conn.Write([]byte("AUTO REDIRECT OK\n"))
}

func (h *testHandler) NewPacketConnectionEx(
	ctx context.Context,
	conn N.PacketConn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	if onClose != nil {
		onClose(nil)
	}
	_ = conn.Close()
}

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == autoClientModeArg {
		err = runClient(autoTestTarget)
	} else {
		err = runAutoRedirect()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runAutoRedirect() error {
	iterations := envInt("WINREDIRECT_ITERATIONS", 3)
	concurrency := envInt("WINREDIRECT_CONCURRENCY", 3)

	options := tun.Options{
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.2/30")},
	}
	handler := newTestHandler(iterations*concurrency + 8)

	redirect, err := tun.NewAutoRedirect(tun.AutoRedirectOptions{
		TunOptions: &options,
		Context:    context.Background(),
		Handler:    handler,
	})
	if err != nil {
		return fmt.Errorf("new auto redirect: %w", err)
	}
	defer redirect.Close()

	if err = redirect.Start(); err != nil {
		return fmt.Errorf("start auto redirect: %w", err)
	}

	time.Sleep(500 * time.Millisecond)
	fmt.Printf("[1] AutoRedirect started iterations=%d concurrency=%d\n", iterations, concurrency)

	for iteration := 1; iteration <= iterations; iteration++ {
		fmt.Printf("[2.%d] Self-dialing %s (should bypass) ...\n", iteration, autoTestTarget)
		if err = expectBypass(autoTestTarget); err != nil {
			return fmt.Errorf("iteration %d self bypass check failed: %w", iteration, err)
		}
		fmt.Printf("[2.%d] Bypass confirmed\n", iteration)

		fmt.Printf("[3.%d] Launching %d child clients ...\n", iteration, concurrency)
		outputs, err := runExternalClients(concurrency)
		if err != nil {
			return fmt.Errorf("iteration %d child clients failed: %w\n%s", iteration, err, strings.Join(outputs, "\n"))
		}
		for _, output := range outputs {
			fmt.Print(output)
			if !strings.Contains(output, "AUTO REDIRECT OK") {
				return fmt.Errorf("iteration %d child client did not receive redirected response", iteration)
			}
		}

		if err = handler.expectRedirectEvents(concurrency, 5*time.Second); err != nil {
			return fmt.Errorf("iteration %d redirect validation failed: %w", iteration, err)
		}
		fmt.Printf("[3.%d] Redirect confirmed\n", iteration)
	}

	return nil
}

func runClient(target string) error {
	fmt.Printf("[client] Dialing %s ...\n", target)
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return fmt.Errorf("client dial: %w", err)
	}
	defer conn.Close()

	bufData := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(bufData)
	if err != nil {
		return fmt.Errorf("client read: %w", err)
	}
	fmt.Printf("[client] Response: %q\n", string(bufData[:n]))
	return nil
}

func runExternalClient() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(executable, autoClientModeArg)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func runExternalClients(concurrency int) ([]string, error) {
	outputs := make([]string, concurrency)
	errs := make([]error, concurrency)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			outputs[index], errs[index] = runExternalClient()
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return outputs, err
		}
	}

	return outputs, nil
}

func expectBypass(target string) error {
	conn, err := net.DialTimeout("tcp", target, 1200*time.Millisecond)
	if err == nil {
		defer conn.Close()
		bufData := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, readErr := conn.Read(bufData)
		if n > 0 && string(bufData[:n]) == "AUTO REDIRECT OK\n" {
			return fmt.Errorf("proxy process was redirected unexpectedly")
		}
		if readErr == nil {
			return fmt.Errorf("unexpected data from bypass connection: %q", string(bufData[:n]))
		}
	}
	return nil
}

func (h *testHandler) expectRedirectEvents(expected int, timeout time.Duration) error {
	deadline := time.After(timeout)
	for i := 0; i < expected; i++ {
		select {
		case event := <-h.redirectEvents:
			if event.destination != autoTestTarget {
				return fmt.Errorf("unexpected destination %s", event.destination)
			}
			if event.processID == 0 {
				return fmt.Errorf("missing process id for redirected connection")
			}
			if !strings.Contains(strings.ToLower(event.processPath), "test_auto_redirect.exe") {
				return fmt.Errorf("unexpected process path %q", event.processPath)
			}
		case <-deadline:
			return fmt.Errorf("timed out waiting for redirect events")
		}
	}
	return nil
}

func envInt(key string, defaultValue int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return defaultValue
	}
	return parsed
}

var _ tun.Handler = (*testHandler)(nil)
