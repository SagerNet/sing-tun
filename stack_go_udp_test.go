package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type goUDPImmediateCloseHandler struct {
	Handler
	finished chan struct{}
	tracker  *goUDPCloseTracker
}

func (h *goUDPImmediateCloseHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	return FlowVerdict{Action: ActionFlow, Port: goUDPUnavailablePort{}, NewTracker: func() FlowTracker {
		select {
		case <-h.finished:
		case <-time.After(50 * time.Millisecond):
		}
		return h.tracker
	}}
}

func (h *goUDPImmediateCloseHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
	onClose(nil)
	close(h.finished)
}

type goUDPUnavailablePort struct{ Port }

func (goUDPUnavailablePort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.Addr{}, netip.Addr{}
}

type goUDPCloseTracker struct {
	attached atomic.Bool
	closed   chan bool
}

func (t *goUDPCloseTracker) AttachFlow(FlowHandle) { t.attached.Store(true) }
func (*goUDPCloseTracker) CountForward(int)        {}
func (*goUDPCloseTracker) CountReverse(int)        {}
func (*goUDPCloseTracker) FlowEstablished()        {}
func (t *goUDPCloseTracker) CloseFlow(FlowCloseReason) {
	t.closed <- t.attached.Load()
}

func TestGoUDPSessionImmediateClose(t *testing.T) {
	tracker := &goUDPCloseTracker{closed: make(chan bool, 1)}
	handler := &goUDPImmediateCloseHandler{finished: make(chan struct{}), tracker: tracker}
	device := NewMemoryTun(MemoryTunOptions{MTU: 1500})
	t.Cleanup(func() { device.Close() })
	stack, err := NewGo(StackOptions{
		Context: context.Background(), Tun: device, TunOptions: Options{MTU: 1500},
		Handler: handler, Logger: logger.NOP(), UDPTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = stack.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stack.Close() })
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+1)
	goEncodeUDPPacket(packet, 4, netip.MustParseAddrPort("198.18.0.2:12345"), netip.MustParseAddrPort("203.0.113.1:443"), []byte{1}, 1)
	_, err = device.Write(packet)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case attached := <-tracker.closed:
		if !attached {
			t.Fatal("packet session closed before its tracker was attached")
		}
	case <-time.After(time.Second):
		t.Fatal("packet session finished without closing its tracker")
	}
	select {
	case <-handler.finished:
	case <-time.After(time.Second):
		t.Fatal("packet handler did not finish")
	}
}

func TestGoUDPReceiveBudget(t *testing.T) {
	for _, payloadSize := range []int{0, 1} {
		t.Run(fmt.Sprintf("payload=%d", payloadSize), func(t *testing.T) {
			device := NewMemoryTun(MemoryTunOptions{MTU: 1500})
			t.Cleanup(func() { device.Close() })
			stack, err := NewGo(StackOptions{Context: context.Background(), Tun: device, TunOptions: Options{MTU: 1500}, Logger: logger.NOP()})
			if err != nil {
				t.Fatal(err)
			}
			err = stack.Start()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { stack.Close() })
			local := netip.MustParseAddrPort("198.18.0.2:12345")
			remote := netip.MustParseAddrPort("203.0.113.1:443")
			socket, err := stack.ListenUDP(local)
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			socket.SetReadBuffer(1)
			barrier, err := stack.ListenUDP(netip.AddrPortFrom(local.Addr(), local.Port()+1))
			if err != nil {
				t.Fatal(err)
			}
			defer barrier.Close()
			packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+payloadSize)
			goEncodeUDPPacket(packet, 4, remote, local, make([]byte, payloadSize), 1)
			const sent = 200
			packets := make([][]byte, sent+1)
			for index := range sent {
				packets[index] = packet
			}
			barrierPacket := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+1)
			goEncodeUDPPacket(barrierPacket, 4, remote, netip.AddrPortFrom(local.Addr(), local.Port()+1), []byte{1}, 1)
			packets[sent] = barrierPacket
			accepted, err := device.WritePackets(packets)
			if err != nil || accepted != len(packets) {
				t.Fatalf("inject receive burst: accepted %d/%d: %v", accepted, len(packets), err)
			}
			barrier.SetReadDeadline(time.Now().Add(time.Second))
			_, err = barrier.Read(make([]byte, 1))
			if err != nil {
				t.Fatal("receive burst did not finish:", err)
			}
			socket.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			received := 0
			for {
				buffer, source, readErr := socket.WaitReadPacket()
				if errors.Is(readErr, os.ErrDeadlineExceeded) {
					break
				}
				if readErr != nil {
					t.Fatal(readErr)
				}
				valid := buffer.Len() == payloadSize && source.AddrPort() == remote
				buffer.Release()
				if !valid {
					t.Fatal("receive burst payload or source changed")
				}
				received++
			}
			if received == 0 || received >= sent {
				t.Fatalf("receive buffer retained %d/%d datagrams despite its small budget", received, sent)
			}
			socket.SetReadDeadline(time.Now().Add(time.Second))
			payload := []byte("capacity restored after reading")
			packet = make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
			goEncodeUDPPacket(packet, 4, remote, local, payload, 2)
			_, err = device.Write(packet)
			if err != nil {
				t.Fatal(err)
			}
			buffer, source, err := socket.WaitReadPacket()
			if err != nil {
				t.Fatal("receive after draining:", err)
			}
			defer buffer.Release()
			if !bytes.Equal(buffer.Bytes(), payload) || source.AddrPort() != remote {
				t.Fatal("receive after draining changed the datagram")
			}
		})
	}
}
