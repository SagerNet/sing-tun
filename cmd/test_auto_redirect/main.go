//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/internal/winipcfg"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	autoClientModeArg = "client"
	autoTestTarget    = "198.18.0.1:65000"
	autoTestRoute     = "198.18.0.0/15"
	autoTestPrefix    = "198.18.0.2/30"
	autoTestMTU       = 1500
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
		err = runAutoRedirect(parseConfig(os.Args[1:]))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type testConfig struct {
	iterations  int
	concurrency int
}

func parseConfig(args []string) testConfig {
	fs := flag.NewFlagSet("test_auto_redirect", flag.ExitOnError)
	cfg := testConfig{}
	fs.IntVar(&cfg.iterations, "iterations", 3, "number of test rounds")
	fs.IntVar(&cfg.concurrency, "concurrency", 3, "number of child clients per round")
	_ = fs.Parse(args)
	if cfg.iterations <= 0 {
		cfg.iterations = 3
	}
	if cfg.concurrency <= 0 {
		cfg.concurrency = 3
	}
	return cfg
}

func runAutoRedirect(cfg testConfig) error {
	log := logger.NOP()
	interfaceFinder := control.NewDefaultInterfaceFinder()
	networkMonitor, err := tun.NewNetworkUpdateMonitor(log)
	if err != nil {
		return fmt.Errorf("create network monitor: %w", err)
	}
	defer networkMonitor.Close()
	if err = networkMonitor.Start(); err != nil {
		return fmt.Errorf("start network monitor: %w", err)
	}

	interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkMonitor, log, tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		return fmt.Errorf("create interface monitor: %w", err)
	}
	defer interfaceMonitor.Close()
	if err = interfaceMonitor.Start(); err != nil {
		return fmt.Errorf("start interface monitor: %w", err)
	}

	options := tun.Options{
		Name:              tun.CalculateInterfaceName("singtun-test"),
		MTU:               autoTestMTU,
		AutoRoute:         true,
		Inet4Address:      []netip.Prefix{netip.MustParsePrefix(autoTestPrefix)},
		Inet4RouteAddress: []netip.Prefix{netip.MustParsePrefix(autoTestRoute)},
		InterfaceFinder:   interfaceFinder,
		InterfaceMonitor:  interfaceMonitor,
		Logger:            log,
	}

	tunDevice, err := tun.New(options)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}
	defer tunDevice.Close()
	if err = tunDevice.Start(); err != nil {
		return fmt.Errorf("start tun: %w", err)
	}

	if err = ensureBestRoute(options.Name, netip.MustParseAddr("198.18.0.1")); err != nil {
		return fmt.Errorf("verify best route: %w", err)
	}

	handler := newTestHandler(cfg.iterations*cfg.concurrency + 8)

	redirect, err := tun.NewAutoRedirect(tun.AutoRedirectOptions{
		TunOptions:      &options,
		Context:         context.Background(),
		Handler:         handler,
		Logger:          log,
		NetworkMonitor:  networkMonitor,
		InterfaceFinder: interfaceFinder,
	})
	if err != nil {
		return fmt.Errorf("new auto redirect: %w", err)
	}
	defer redirect.Close()

	if err = redirect.Start(); err != nil {
		return fmt.Errorf("start auto redirect: %w", err)
	}

	time.Sleep(500 * time.Millisecond)
	fmt.Printf("[1] AutoRedirect started interface=%s iterations=%d concurrency=%d\n", options.Name, cfg.iterations, cfg.concurrency)

	for iteration := 1; iteration <= cfg.iterations; iteration++ {
		fmt.Printf("[2.%d] Self-dialing %s (should bypass) ...\n", iteration, autoTestTarget)
		if err = expectBypass(autoTestTarget); err != nil {
			return fmt.Errorf("iteration %d self bypass check failed: %w", iteration, err)
		}
		fmt.Printf("[2.%d] Bypass confirmed\n", iteration)

		fmt.Printf("[3.%d] Launching %d child clients ...\n", iteration, cfg.concurrency)
		outputs, err := runExternalClients(cfg.concurrency)
		if err != nil {
			return fmt.Errorf("iteration %d child clients failed: %w\n%s", iteration, err, strings.Join(outputs, "\n"))
		}
		for _, output := range outputs {
			fmt.Print(output)
			if !strings.Contains(output, "AUTO REDIRECT OK") {
				return fmt.Errorf("iteration %d child client did not receive redirected response", iteration)
			}
		}

		if err = handler.expectRedirectEvents(cfg.concurrency, 5*time.Second); err != nil {
			return fmt.Errorf("iteration %d redirect validation failed: %w", iteration, err)
		}
		fmt.Printf("[3.%d] Redirect confirmed\n", iteration)
	}

	return nil
}

func ensureBestRoute(interfaceName string, destination netip.Addr) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return err
	}
	var destinationAddress winipcfg.RawSockaddrInet
	if err = destinationAddress.SetAddr(destination); err != nil {
		return err
	}
	bestRoute, _, err := winipcfg.GetBestRoute2(nil, 0, nil, &destinationAddress, 0)
	if err != nil {
		return err
	}
	if bestRoute.InterfaceLUID != luid {
		return fmt.Errorf("destination %s routed via %v, want %v", destination, bestRoute.InterfaceLUID, luid)
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

var _ tun.Handler = (*testHandler)(nil)
