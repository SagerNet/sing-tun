//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	tun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	autoClientModeArg = "client"
	autoTestTarget    = "198.18.0.1:65000"
)

type testHandler struct{}

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
	} else {
		fmt.Printf("[redirect] source=%s destination=%s metadata=<nil>\n", source, destination)
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
	options := tun.Options{
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.2/30")},
	}

	redirect, err := tun.NewAutoRedirect(tun.AutoRedirectOptions{
		TunOptions: &options,
		Context:    context.Background(),
		Handler:    &testHandler{},
	})
	if err != nil {
		return fmt.Errorf("new auto redirect: %w", err)
	}
	defer redirect.Close()

	if err = redirect.Start(); err != nil {
		return fmt.Errorf("start auto redirect: %w", err)
	}

	time.Sleep(500 * time.Millisecond)
	fmt.Printf("[1] AutoRedirect started\n")

	fmt.Printf("[2] Self-dialing %s (should bypass) ...\n", autoTestTarget)
	if err = expectBypass(autoTestTarget); err != nil {
		return fmt.Errorf("self bypass check failed: %w", err)
	}
	fmt.Println("[2] Bypass confirmed")

	fmt.Printf("[3] Child client dialing %s (should redirect) ...\n", autoTestTarget)
	output, err := runExternalClient()
	if err != nil {
		return fmt.Errorf("child client failed: %w\n%s", err, output)
	}
	fmt.Print(output)
	if !strings.Contains(output, "AUTO REDIRECT OK") {
		return fmt.Errorf("child client did not receive redirected response")
	}
	fmt.Println("[3] Redirect confirmed")

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

var _ tun.Handler = (*testHandler)(nil)
