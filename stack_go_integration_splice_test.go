//go:build (linux && !android) || (darwin && !ios)

package tun

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
)

func TestGoKernelSpliceOwnership(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	t.Run("tcp", func(streamTest *testing.T) {
		client, conn := fixture.pair(streamTest, false)
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			streamTest.Fatal(err)
		}
		defer listener.Close()
		upstream, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			streamTest.Fatal(err)
		}
		defer upstream.Close()
		peer, err := listener.AcceptTCP()
		if err != nil {
			streamTest.Fatal(err)
		}
		defer peer.Close()
		peer.SetDeadline(time.Now().Add(3 * time.Second))
		closed := make(chan error, 1)
		owner := &kernelSocket{TCPConn: upstream}
		accepted := conn.Splice(owner, SpliceOptions{
			OnClose: func(closeError error) { closed <- closeError },
		})
		if !accepted {
			streamTest.Fatal("TCP splice refused")
		}
		payload := kernelPayload(4097, 193)
		_, err = client.Write(payload)
		if err != nil {
			streamTest.Fatal(err)
		}
		data := make([]byte, len(payload))
		_, err = io.ReadFull(peer, data)
		if err != nil || !bytes.Equal(data, payload) {
			streamTest.Fatalf("spliced TCP upload: %v", err)
		}
		err = upstream.SetDeadline(time.Now().Add(-time.Second))
		if !errors.Is(err, net.ErrClosed) {
			streamTest.Fatalf("original TCP connection survived transfer: %v", err)
		}
		_, err = peer.Write(payload)
		if err != nil {
			streamTest.Fatal(err)
		}
		_, err = io.ReadFull(client, data)
		if err != nil || !bytes.Equal(data, payload) {
			streamTest.Fatalf("spliced TCP download after original connection closed: %v", err)
		}
		owner.Close()
		owner.Close()
		select {
		case <-closed:
		case <-time.After(time.Second):
			streamTest.Fatal("TCP splice did not close its socket")
		}
		_, err = peer.Read(data)
		var networkError net.Error
		if err == nil || errors.As(err, &networkError) && networkError.Timeout() {
			streamTest.Fatalf("TCP peer survived splice close: %v", err)
		}
	})
	t.Run("udp", func(packetTest *testing.T) {
		client, conn, destination := fixture.packetPair(packetTest, false)
		peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			packetTest.Fatal(err)
		}
		defer peer.Close()
		peer.SetDeadline(time.Now().Add(3 * time.Second))
		upstream, err := net.DialUDP("udp4", nil, peer.LocalAddr().(*net.UDPAddr))
		if err != nil {
			packetTest.Fatal(err)
		}
		defer upstream.Close()
		address := upstream.LocalAddr().(*net.UDPAddr)
		closed := make(chan error, 1)
		owner := &kernelPacketSocket{UDPConn: upstream}
		accepted := conn.Splice(owner, SplicePacketOptions{
			NAT:           PacketNAT{Origin: destination, Destination: M.SocksaddrFromNet(peer.LocalAddr())},
			SpliceOptions: SpliceOptions{OnClose: func(closeError error) { closed <- closeError }},
		})
		if !accepted {
			packetTest.Fatal("UDP splice refused")
		}
		payload := kernelPayload(1023, 197)
		_, err = client.Write(payload)
		if err != nil {
			packetTest.Fatal(err)
		}
		data := make([]byte, len(payload))
		n, source, err := peer.ReadFromUDP(data)
		if err != nil || !bytes.Equal(data[:n], payload) {
			packetTest.Fatalf("spliced UDP upload: %v", err)
		}
		err = upstream.SetDeadline(time.Now().Add(-time.Second))
		if !errors.Is(err, net.ErrClosed) {
			packetTest.Fatalf("original UDP connection survived transfer: %v", err)
		}
		_, err = peer.WriteToUDP(payload, source)
		if err != nil {
			packetTest.Fatal(err)
		}
		n, err = client.Read(data)
		if err != nil || !bytes.Equal(data[:n], payload) {
			packetTest.Fatalf("spliced UDP download after original connection closed: %v", err)
		}
		owner.Close()
		owner.Close()
		select {
		case <-closed:
		case <-time.After(time.Second):
			packetTest.Fatal("UDP splice did not close its socket")
		}
		rebound, err := net.ListenUDP("udp4", address)
		if err != nil {
			packetTest.Fatal("UDP endpoint survived splice close: ", err)
		}
		rebound.Close()
	})
	t.Run("fallback", func(fallbackTest *testing.T) {
		_, conn, _ := fixture.packetPair(fallbackTest, false)
		upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			fallbackTest.Fatal(err)
		}
		defer upstream.Close()
		address := upstream.LocalAddr().(*net.UDPAddr)
		peer, err := net.DialUDP("udp4", nil, upstream.LocalAddr().(*net.UDPAddr))
		if err != nil {
			fallbackTest.Fatal(err)
		}
		defer peer.Close()
		offload, _ := (&socks.AssociatePacketConn{}).CreatePacketOffload()
		accepted := conn.Splice(&kernelPacketSocket{UDPConn: upstream}, SplicePacketOptions{Offload: offload})
		if accepted {
			fallbackTest.Fatal("unconnected SOCKS socket unexpectedly accepted")
		}
		upstream.SetReadDeadline(time.Now().Add(time.Second))
		completed := make(chan error, 1)
		go func() {
			data := make([]byte, 1)
			_, readError := upstream.Read(data)
			completed <- readError
		}()
		select {
		case err = <-completed:
			fallbackTest.Fatalf("fallback reader did not wait: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		_, err = peer.Write([]byte{1})
		if err != nil {
			fallbackTest.Fatal(err)
		}
		select {
		case err = <-completed:
			if err != nil {
				fallbackTest.Fatal("runtime reader after splice rejection: ", err)
			}
		case <-time.After(2 * time.Second):
			fallbackTest.Fatal("runtime reader was not woken")
		}
		upstream.Close()
		rebound, err := net.ListenUDP("udp4", address)
		if err != nil {
			fallbackTest.Fatal("rejected splice retained a duplicate socket: ", err)
		}
		rebound.Close()
	})
}
