//go:build windows

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ioctlSetConfig  = 0x00120000 | (0x800 << 2)
	ioctlStart      = 0x00120000 | (0x801 << 2)
	ioctlStop       = 0x00120000 | (0x802 << 2)
	ioctlGetPending = 0x00120000 | (0x803 << 2)
	ioctlSetVerdict = 0x00120000 | (0x804 << 2)
)

type Config struct {
	RedirectPort uint16
	_            [2]byte
	ProxyPID     uint32
}

type PendingConn struct {
	ConnID        uint64
	AddressFamily uint8
	_pad0         [3]byte
	SrcAddr       [16]byte
	SrcPort       uint16
	_pad1         [2]byte
	DstAddr       [16]byte
	DstPort       uint16
	_pad2         [2]byte
	ProcessID     uint32
}

type VerdictMsg struct {
	ConnID  uint64
	Verdict uint32
	_pad    [4]byte
}

var (
	modkernel32    = windows.NewLazySystemDLL("kernel32.dll")
	procCancelIoEx = modkernel32.NewProc("CancelIoEx")
)

const (
	clientModeArg = "client"
	testTarget    = "198.18.0.1:65000"
)

var targetVerdict = strings.ToUpper(strings.TrimSpace(os.Getenv("WINREDIRECT_TARGET_VERDICT")))

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == clientModeArg {
		err = runClient(testTarget)
	} else {
		err = runProxy()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runProxy() error {
	// 1. Start redirect TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	fmt.Printf("[1] Redirect server on 127.0.0.1:%d\n", port)

	var wg sync.WaitGroup
	var acceptedCount atomic.Int32
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			acceptedCount.Add(1)
			fmt.Printf("[redirect] Accepted from %s\n", conn.RemoteAddr())
			conn.Write([]byte("REDIRECTED OK\n"))
			conn.Close()
		}
	}()

	// 2. Open driver
	device := openDevice()
	defer windows.CloseHandle(device)
	fmt.Println("[2] Device opened")

	// 3. Configure
	cfg := Config{RedirectPort: uint16(port), ProxyPID: uint32(os.Getpid())}
	err = devctl(device, ioctlSetConfig, unsafe.Pointer(&cfg), unsafe.Sizeof(cfg), nil, 0)
	if err != nil {
		return fmt.Errorf("SET_CONFIG: %w", err)
	}
	fmt.Printf("[3] Config: port=%d pid=%d\n", port, os.Getpid())

	// 4. Start
	err = devctl(device, ioctlStart, nil, 0, nil, 0)
	if err != nil {
		return fmt.Errorf("START: %w", err)
	}
	fmt.Println("[4] WFP started — all TCP connections will be intercepted")

	// 5. Pre-match worker
	stopCh := make(chan struct{})
	defer close(stopCh)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pendingWorker(device, stopCh, port)
	}()
	defer wg.Wait()
	defer devctl(device, ioctlStop, nil, 0, nil, 0)

	// 6. Proxy process should bypass its own outbound connect.
	time.Sleep(300 * time.Millisecond)
	fmt.Printf("\n[5] Proxy self-dialing %s (should bypass) ...\n", testTarget)
	err = expectBypass(testTarget, &acceptedCount)
	if err != nil {
		return fmt.Errorf("self-bypass check failed: %w", err)
	}
	fmt.Println("[5] Bypass confirmed")

	// 7. External client process should be redirected.
	fmt.Printf("\n[6] Child client dialing %s (should redirect) ...\n", testTarget)
	if targetVerdict == "BYPASS" {
		fmt.Println("[6] Target verdict override: BYPASS")
	}
	output, err := runExternalClient()
	if err != nil {
		return fmt.Errorf("child client failed: %w\n%s", err, output)
	}
	fmt.Print(output)
	if !strings.Contains(output, "REDIRECTED OK") {
		return fmt.Errorf("child client did not receive redirected response")
	}
	if acceptedCount.Load() != 1 {
		return fmt.Errorf("redirect server accepted %d connections, want 1", acceptedCount.Load())
	}
	fmt.Println("[6] Redirect confirmed")

	// 8. Cleanup
	time.Sleep(300 * time.Millisecond)
	fmt.Println("\n[7] Stopped")
	fmt.Println("[8] Done!")
	return nil
}

func runClient(target string) error {
	fmt.Printf("[client] Dialing %s ...\n", target)
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return fmt.Errorf("client dial: %w", err)
	}
	defer conn.Close()

	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("client read: %w", err)
	}
	fmt.Printf("[client] Response: %q\n", string(buf[:n]))
	return nil
}

func runExternalClient() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(executable, clientModeArg)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func expectBypass(target string, acceptedCount *atomic.Int32) error {
	initialAccepted := acceptedCount.Load()
	conn, err := net.DialTimeout("tcp", target, 1200*time.Millisecond)
	if err == nil {
		defer conn.Close()
		buf := make([]byte, 64)
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, readErr := conn.Read(buf)
		if n > 0 && string(buf[:n]) == "REDIRECTED OK\n" {
			return fmt.Errorf("proxy process was redirected unexpectedly")
		}
		if readErr == nil {
			return fmt.Errorf("unexpected data from bypass connection: %q", string(buf[:n]))
		}
	}
	time.Sleep(300 * time.Millisecond)
	if acceptedCount.Load() != initialAccepted {
		return fmt.Errorf("redirect server accepted proxy self-connection")
	}
	return nil
}

func pendingWorker(device windows.Handle, stop <-chan struct{}, redirectPort int) {
	for {
		select {
		case <-stop:
			return
		default:
		}

		var conn PendingConn
		err := devctlOverlapped(device, ioctlGetPending, nil, 0,
			unsafe.Pointer(&conn), unsafe.Sizeof(conn), 2*time.Second)
		if err != nil {
			continue
		}

		src := fmtAddr(conn.AddressFamily, conn.SrcAddr, conn.SrcPort)
		dst := fmtAddr(conn.AddressFamily, conn.DstAddr, conn.DstPort)
		proc := procName(conn.ProcessID)

		fmt.Printf("[>] connID=%d  %s -> %s  pid=%d (%s)\n",
			conn.ConnID, src, dst, conn.ProcessID, proc)

		verdict := uint32(1) // BYPASS
		verdictText := "BYPASS"
		if dst == testTarget && targetVerdict != "BYPASS" {
			verdict = 0 // REDIRECT
			verdictText = fmt.Sprintf("REDIRECT -> 127.0.0.1:%d", redirectPort)
		}

		v := VerdictMsg{ConnID: conn.ConnID, Verdict: verdict}
		err = devctl(device, ioctlSetVerdict, unsafe.Pointer(&v), unsafe.Sizeof(v), nil, 0)
		if err != nil {
			fmt.Printf("[!] verdict failed: %v\n", err)
		} else {
			fmt.Printf("[<] connID=%d  %s\n", conn.ConnID, verdictText)
		}
	}
}

func openDevice() windows.Handle {
	p, _ := windows.UTF16PtrFromString(`\\.\WinRedirect`)
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED, 0)
	fatal("CreateFile", err)
	return h
}

func devctl(h windows.Handle, code uint32, in unsafe.Pointer, inSz uintptr, out unsafe.Pointer, outSz uintptr) error {
	var ret uint32
	return windows.DeviceIoControl(h, code,
		(*byte)(in), uint32(inSz),
		(*byte)(out), uint32(outSz),
		&ret, nil)
}

func devctlOverlapped(h windows.Handle, code uint32, in unsafe.Pointer, inSz uintptr, out unsafe.Pointer, outSz uintptr, timeout time.Duration) error {
	ol := &windows.Overlapped{}
	var err error
	ol.HEvent, err = windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ol.HEvent)

	var ret uint32
	err = windows.DeviceIoControl(h, code,
		(*byte)(in), uint32(inSz),
		(*byte)(out), uint32(outSz),
		&ret, ol)
	if err == windows.ERROR_IO_PENDING {
		r, _ := windows.WaitForSingleObject(ol.HEvent, uint32(timeout.Milliseconds()))
		if r != windows.WAIT_OBJECT_0 {
			procCancelIoEx.Call(uintptr(h), uintptr(unsafe.Pointer(ol)))
			return fmt.Errorf("timeout")
		}
		err = windows.GetOverlappedResult(h, ol, &ret, false)
	}
	return err
}

func fmtAddr(af uint8, raw [16]byte, port uint16) string {
	var addr netip.Addr
	if af == 2 {
		addr = netip.AddrFrom4([4]byte(raw[:4]))
	} else {
		addr = netip.AddrFrom16(raw)
	}
	return netip.AddrPortFrom(addr, port).String()
}

func procName(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "?"
	}
	defer windows.CloseHandle(h)
	var buf [260]uint16
	n := uint32(260)
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return "?"
	}
	s := windows.UTF16ToString(buf[:n])
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '\\' {
			return s[i+1:]
		}
	}
	return s
}

func fatal(ctx string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", ctx, err)
		os.Exit(1)
	}
}
