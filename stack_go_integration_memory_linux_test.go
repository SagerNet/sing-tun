//go:build linux && !android

package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

const kernelMaxDatagram = 60000

func kernelAddUnreachableRoute(t *testing.T, prefix netip.Prefix) bool {
	t.Helper()
	route := &netlink.Route{
		Dst:  &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())},
		Type: unix.RTN_UNREACHABLE,
	}
	err := netlink.RouteAdd(route)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netlink.RouteDel(route) })
	return true
}

var (
	ethernetGateway4 = netip.MustParsePrefix("198.18.0.1/24")
	ethernetGateway6 = netip.MustParsePrefix("fd73:5a1e::1/64")
	ethernetGuest4   = netip.MustParsePrefix("198.18.0.2/24")
	ethernetGuest6   = netip.MustParsePrefix("fd73:5a1e::2/64")
	ethernetRemote4  = netip.MustParseAddr("203.0.113.1")
	ethernetRemote6  = netip.MustParseAddr("2001:db8::1")
)

type kernelNamespace struct {
	tasks chan func()
}

func newKernelNamespace(t *testing.T) *kernelNamespace {
	t.Helper()
	namespace := &kernelNamespace{tasks: make(chan func())}
	entered := make(chan error)
	go func() {
		runtime.LockOSThread()
		err := unix.Unshare(unix.CLONE_NEWNET)
		entered <- err
		if err != nil {
			return
		}
		for task := range namespace.tasks {
			task()
		}
	}()
	err := <-entered
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(namespace.tasks) })
	return namespace
}

func (n *kernelNamespace) run(t *testing.T, task func() error) {
	t.Helper()
	result := make(chan error)
	n.tasks <- func() { result <- task() }
	err := <-result
	if err != nil {
		t.Fatal(err)
	}
}

type ethernetGuest struct {
	*kernelNamespace
	tap *os.File
}

func newEthernetGuest(t *testing.T, addresses ...netip.Prefix) *ethernetGuest {
	t.Helper()
	guest := &ethernetGuest{kernelNamespace: newKernelNamespace(t)}
	guest.run(t, func() error {
		descriptor, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		request, err := unix.NewIfreq("tap0")
		if err != nil {
			return err
		}
		request.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
		err = unix.IoctlIfreq(descriptor, unix.TUNSETIFF, request)
		if err != nil {
			return err
		}
		guest.tap = os.NewFile(uintptr(descriptor), "/dev/net/tun")
		for _, setting := range []string{"accept_dad", "router_solicitations"} {
			err = os.WriteFile("/proc/sys/net/ipv6/conf/tap0/"+setting, []byte("0"), 0)
			if err != nil {
				return err
			}
		}
		link, err := netlink.LinkByName("tap0")
		if err != nil {
			return err
		}
		for _, prefix := range addresses {
			err = netlink.AddrAdd(link, &netlink.Addr{
				IPNet: &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())},
				Flags: unix.IFA_F_NODAD,
			})
			if err != nil {
				return err
			}
		}
		loopback, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		err = netlink.LinkSetUp(loopback)
		if err != nil {
			return err
		}
		err = netlink.LinkSetUp(link)
		if err != nil {
			return err
		}
		return netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Gw: ethernetGateway4.Addr().AsSlice()})
	})
	t.Cleanup(func() { guest.tap.Close() })
	return guest
}

func (g *ethernetGuest) attach(t *testing.T) *kernelStackFixture {
	t.Helper()
	var queue *OutboundQueue
	memoryTun := NewMemoryTun(MemoryTunOptions{
		MTU:         1500,
		Ethernet:    true,
		Inet6Prefix: []netip.Prefix{ethernetGateway6.Masked()},
		Route:       func([]byte) *OutboundQueue { return queue },
	})
	t.Cleanup(func() { memoryTun.Close() })
	queue = memoryTun.NewOutboundQueue(func(frames []*buf.Buffer) {
		for _, frame := range frames {
			g.tap.Write(frame.Bytes())
		}
		buf.ReleaseMulti(frames)
	})
	t.Cleanup(func() { queue.Close() })
	go func() {
		storage := make([]byte, 65536)
		for {
			n, err := g.tap.Read(storage)
			if err != nil {
				return
			}
			frame := storage[:n]
			if n >= header.EthernetMinimumSize+header.IPv6MinimumSize &&
				header.Ethernet(frame).Type() == header.IPv6ProtocolNumber &&
				header.IPv6(frame[header.EthernetMinimumSize:]).NextHeader() == uint8(header.IPv6HopByHopOptionsExtHdrIdentifier) {
				continue
			}
			err = memoryTun.WaitWritePackets([][]byte{frame})
			if err != nil {
				return
			}
		}
	}()
	fixture := &kernelStackFixture{
		tcp: make(map[uint16]chan kernelAccept),
		udp: make(map[uint16]chan N.PacketConn),
	}
	stack, err := NewGo(StackOptions{
		Context:    context.Background(),
		Tun:        memoryTun,
		TunOptions: Options{MTU: 1500, Inet4Address: []netip.Prefix{ethernetGateway4}, Inet6Address: []netip.Prefix{ethernetGateway6}},
		Handler:    fixture,
		Logger:     logger.NOP(),
		UDPTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = stack.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stack.Close() })
	fixture.stack = stack
	return fixture
}

func (g *ethernetGuest) dial(t *testing.T, network string, address netip.AddrPort) net.Conn {
	t.Helper()
	var conn net.Conn
	g.run(t, func() error {
		var err error
		conn, err = net.DialTimeout(network, address.String(), 3*time.Second)
		return err
	})
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

func TestGoMemoryEthernet(t *testing.T) {
	t.Run("outbound", func(outboundTest *testing.T) {
		outboundTest.Parallel()
		guest := newEthernetGuest(outboundTest, ethernetGuest4)
		fixture := guest.attach(outboundTest)
		var route netlink.Route
		deadline := time.Now().Add(3 * time.Second)
		for route.Src == nil || !ethernetGateway6.Masked().Contains(M.AddrFromIP(route.Src.IP)) {
			if time.Now().After(deadline) {
				outboundTest.Fatalf("the router advertisement sent on attach did not configure the guest: %s via %s from %s", ethernetRemote6, route.Gw, route.Src)
			}
			guest.run(outboundTest, func() error {
				routes, err := netlink.RouteGet(ethernetRemote6.AsSlice())
				if errors.Is(err, unix.ENETUNREACH) {
					return nil
				}
				if err != nil {
					return err
				}
				route = routes[0]
				return nil
			})
			time.Sleep(10 * time.Millisecond)
		}
		for _, ipv6 := range []bool{false, true} {
			outboundTest.Run(fmt.Sprintf("ipv6=%v", ipv6), func(addressTest *testing.T) {
				remote := ethernetRemote4
				if ipv6 {
					remote = ethernetRemote6
				}
				addressTest.Run("tcp", func(test *testing.T) {
					port := uint16(20000 + fixture.port.Add(1))
					accepted := make(chan kernelAccept, 1)
					fixture.access.Lock()
					fixture.tcp[port] = accepted
					fixture.access.Unlock()
					client := guest.dial(test, "tcp", netip.AddrPortFrom(remote, port))
					var server *GoConn
					select {
					case accept := <-accepted:
						if accept.err != nil {
							test.Fatal(accept.err)
						}
						server = accept.conn
						test.Cleanup(func() { server.Close() })
					case <-time.After(3 * time.Second):
						test.Fatal("connection from the guest was not accepted")
					}
					result := make(chan error, 1)
					go func() { result <- kernelTransfer(client, server, kernelPayload(1<<20, 17), false) }()
					err := kernelTransfer(server, client, kernelPayload(1<<20, 19), false)
					if err != nil {
						test.Error("download:", err)
					}
					err = <-result
					if err != nil {
						test.Error("upload:", err)
					}
				})
				addressTest.Run("udp", func(test *testing.T) {
					port := uint16(20000 + fixture.port.Add(1))
					accepted := make(chan N.PacketConn, 1)
					fixture.access.Lock()
					fixture.udp[port] = accepted
					fixture.access.Unlock()
					client := guest.dial(test, "udp", netip.AddrPortFrom(remote, port))
					payload := kernelPayload(1200, 23)
					_, err := client.Write(payload)
					if err != nil {
						test.Fatal(err)
					}
					var conn N.PacketConn
					select {
					case conn = <-accepted:
						test.Cleanup(func() { conn.Close() })
					case <-time.After(3 * time.Second):
						test.Fatal("datagram from the guest was not accepted")
					}
					conn.SetReadDeadline(time.Now().Add(3 * time.Second))
					buffer := buf.NewPacket()
					destination, err := conn.ReadPacket(buffer)
					received := bytes.Clone(buffer.Bytes())
					buffer.Release()
					if err != nil {
						test.Fatal(err)
					}
					if !bytes.Equal(received, payload) || destination.AddrPort() != netip.AddrPortFrom(remote, port) {
						test.Fatalf("stack received %d bytes for %s", len(received), destination)
					}
					options := N.NewReadWaitOptions(nil, conn)
					reply := options.NewBufferSize(len(payload))
					common.Must1(reply.Write(payload))
					options.PostReturn(reply)
					err = conn.WritePacket(reply, destination)
					if err != nil {
						test.Fatal(err)
					}
					received = make([]byte, 1500)
					n, err := client.Read(received)
					if err != nil {
						test.Fatal(err)
					}
					if !bytes.Equal(received[:n], payload) {
						test.Fatalf("guest received %d bytes", n)
					}
				})
			})
		}
	})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("dial/ipv6=%v", ipv6), func(test *testing.T) {
			test.Parallel()
			guest := newEthernetGuest(test, ethernetGuest4, ethernetGuest6)
			address := ethernetGuest4.Addr()
			source := ethernetGateway4.Addr()
			if ipv6 {
				address = ethernetGuest6.Addr()
				source = ethernetGateway6.Addr()
			}
			var listener *net.TCPListener
			guest.run(test, func() error {
				var err error
				listener, err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(address, 0)))
				return err
			})
			test.Cleanup(func() { listener.Close() })
			fixture := guest.attach(test)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := fixture.stack.DialTCP(ctx, source, listener.Addr().(*net.TCPAddr).AddrPort())
			if err != nil {
				test.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			server := kernelAcceptTCP(test, listener)
			result := make(chan error, 1)
			go func() { result <- kernelTransfer(conn, server, kernelPayload(1<<20, 29), false) }()
			err = kernelTransfer(server, conn, kernelPayload(1<<20, 31), false)
			if err != nil {
				test.Error("download:", err)
			}
			err = <-result
			if err != nil {
				test.Error("upload:", err)
			}
		})
	}
}
