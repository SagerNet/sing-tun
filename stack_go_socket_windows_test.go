package tun

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/internal/afd"

	"golang.org/x/sys/windows"
)

func TestSpliceSocketReadiness(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	socket, err := goSpliceSocket(server.(*net.TCPConn))
	if err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, 16)
	iovecs := goIovecsFromSegments(nil, [][]byte{buffer})
	started := time.Now()
	n, errno := socket.readVector(iovecs)
	if !goSocketWouldBlock(errno) {
		t.Fatalf("read on idle socket: n=%d errno=%v", n, errno)
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatalf("read on idle socket blocked for %v", time.Since(started))
	}

	iocp, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(iocp)
	device, err := afd.Open(iocp, "sing-tun-test")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	io := &goWindowsIO{iocp: iocp, afd: device, ringDrained: false}
	err = io.registerSocket(&socket, 7, goInterestRead)
	if err != nil {
		t.Fatal(err)
	}
	defer io.unregisterSocket(&socket)

	events := make([]goSocketEvent, 4)
	_, count, err := io.wait(100*time.Millisecond, events)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("poll completed without data: %+v", events[:count])
	}

	_, err = client.Write([]byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	_, count, err = io.wait(time.Second, events)
	if err != nil {
		t.Fatal(err)
	}
	latency := time.Since(started)
	if count != 1 || events[0].token != 7 || !events[0].readable {
		t.Fatalf("unexpected readiness events after write: %+v", events[:count])
	}
	t.Logf("readiness latency %v", latency)
	n, errno = socket.readVector(iovecs)
	if errno != 0 || n != 4 {
		t.Fatalf("read after readiness: n=%d errno=%v", n, errno)
	}
	n, errno = socket.readVector(iovecs)
	if !goSocketWouldBlock(errno) {
		t.Fatalf("second read: n=%d errno=%v", n, errno)
	}
	if latency > 50*time.Millisecond {
		t.Fatalf("readiness latency %v", latency)
	}
	_, err = client.Write([]byte("pong"))
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	for {
		_, count, err = io.wait(time.Second, events)
		if err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Fatal("no readiness after second write")
		}
		n, errno = socket.readVector(iovecs)
		if errno == 0 {
			break
		}
		if !goSocketWouldBlock(errno) {
			t.Fatalf("read after second readiness: errno=%v", errno)
		}
	}
	t.Logf("second readiness latency %v, read %d", time.Since(started), n)
}

func TestWaitCompletionPacketLatency(t *testing.T) {
	if !afd.WaitCompletionPacketSupported() {
		t.Skip("wait completion packets unsupported")
	}
	iocp, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(iocp)
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(event)
	packet, err := afd.NewWaitCompletionPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	var completions [4]afd.OverlappedEntry
	var total time.Duration
	const rounds = 2000
	for round := range rounds {
		signaled, associateErr := packet.Associate(iocp, event, goCompletionKeyTun)
		if associateErr != nil {
			t.Fatal(associateErr)
		}
		if signaled {
			t.Fatalf("round %d: event already signaled", round)
		}
		go windows.SetEvent(event)
		started := time.Now()
		var removed uint32
		waitErr := afd.GetQueuedCompletionStatusEx(iocp, &completions[0], uint32(len(completions)), &removed, 1000, false)
		if waitErr != nil {
			t.Fatalf("round %d: %v", round, waitErr)
		}
		total += time.Since(started)
		if removed != 1 || completions[0].CompletionKey != goCompletionKeyTun {
			t.Fatalf("round %d: removed %d key %d", round, removed, completions[0].CompletionKey)
		}
	}
	t.Logf("average wait completion latency %v", total/rounds)
	if total/rounds > 200*time.Microsecond {
		t.Fatalf("wait completion packets are slow: %v per round", total/rounds)
	}
}

func TestAFDPollWithPendingData(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	socket, err := goSpliceSocket(server.(*net.TCPConn))
	if err != nil {
		t.Fatal(err)
	}
	iocp, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(iocp)
	device, err := afd.Open(iocp, "sing-tun-test")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	io := &goWindowsIO{iocp: iocp, afd: device}
	_, err = client.Write([]byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	err = io.registerSocket(&socket, 7, goInterestRead)
	if err != nil {
		t.Fatal(err)
	}
	defer io.unregisterSocket(&socket)
	events := make([]goSocketEvent, 4)
	started := time.Now()
	_, count, err := io.wait(500*time.Millisecond, events)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || !events[0].readable {
		t.Fatalf("poll issued with pending data did not complete: %+v after %v", events[:count], time.Since(started))
	}
	t.Logf("pending-data poll completed after %v", time.Since(started))
	// stall: drop interest while the poll is armed, then restore it without new data
	err = io.updateSocket(&socket, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, count, err = io.wait(200*time.Millisecond, events)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("events after cancel: %d", count)
	err = io.updateSocket(&socket, goInterestRead)
	if err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	_, count, err = io.wait(500*time.Millisecond, events)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || !events[0].readable {
		t.Fatalf("poll after cancel/re-add did not complete: %+v after %v", events[:count], time.Since(started))
	}
	t.Logf("re-added poll completed after %v", time.Since(started))
}
