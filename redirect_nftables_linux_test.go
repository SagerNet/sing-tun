//go:build linux && !android

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sys/unix"
)

func TestNFTablesMarkModeInboundUDPReply(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	// The rules redirect TCP and mark UDP of the whole namespace, so they get a namespace of their own.
	// The goroutine stays locked: its thread, and with it the namespace, goes away when the test ends.
	runtime.LockOSThread()
	err := unix.Unshare(unix.CLONE_NEWNET)
	if err != nil {
		t.Skipf("create network namespace: %v", err)
	}

	// Stands in for the outside network.
	peerOptions := Options{
		Name:                      "gotest95",
		MTU:                       1500,
		Inet4Address:              []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("169.254.95.1/16")},
		EXP_ExternalConfiguration: true,
		Logger:                    logger.NOP(),
	}
	device, err := New(peerOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	configureKernelInterface(t, device, peerOptions)
	err = device.Start()
	if err != nil {
		t.Fatal(err)
	}

	redirect := &autoRedirect{
		tunOptions: &Options{
			Name:                   "gotest95r",
			AutoRedirectMarkMode:   true,
			AutoRedirectInputMark:  DefaultAutoRedirectInputMark,
			AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
			AutoRedirectResetMark:  DefaultAutoRedirectResetMark,
			AutoRedirectTProxyMark: DefaultAutoRedirectTProxyMark,
			// Not empty, so that setupNFTables leaves docker firewall rules alone.
			NetNs: fmt.Sprint("/proc/self/task/", unix.Gettid(), "/ns/net"),
		},
		logger:             logger.NOP(),
		tableName:          "sing-box",
		interfaceFinder:    control.NewDefaultInterfaceFinder(),
		customRedirectPort: 1,
		enableIPv4:         true,
		useNFTables:        true,
	}
	err = redirect.setupNFTables()
	if err != nil {
		t.Fatal(err)
	}
	defer redirect.cleanupNFTables()

	// Stands in for the TUN route table: whatever gets the input mark is dropped.
	rule := netlink.NewRule()
	rule.Priority = 9000
	rule.Mark = DefaultAutoRedirectInputMark
	rule.MarkSet = true
	rule.Mask = 0xffffffff
	rule.Table = 2022
	rule.Family = unix.AF_INET
	err = netlink.RuleAdd(rule)
	if err != nil {
		t.Fatal(err)
	}
	err = netlink.RouteAdd(&netlink.Route{
		Dst:   &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Table: 2022,
		Type:  unix.RTN_BLACKHOLE,
	})
	if err != nil {
		t.Fatal(err)
	}

	server, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, address, readErr := server.ReadFromUDPAddrPort(buffer)
			if readErr != nil {
				return
			}
			_, _ = server.WriteToUDPAddrPort(buffer[:n], address)
		}
	}()
	serverPort := uint16(server.LocalAddr().(*net.UDPAddr).Port)

	packets := make(chan []byte, 64)
	go func() {
		for {
			buffer := make([]byte, 1500)
			n, readErr := device.Read(buffer)
			if readErr != nil {
				return
			}
			packets <- buffer[:n]
		}
	}()

	for index, testCase := range []struct {
		name   string
		local  netip.Addr
		remote netip.Addr
	}{
		// In the local address set: the flow gets the output mark on the way in.
		{"global", netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
		// Not in the local address set: the prerouting nat chain gives the flow the input mark.
		{"link-local", netip.MustParseAddr("169.254.95.1"), netip.MustParseAddr("169.254.95.2")},
	} {
		local := netip.AddrPortFrom(testCase.local, serverPort)
		remote := netip.AddrPortFrom(testCase.remote, uint16(40000+index))
		_, err = device.Write(nftablesTestUDPPacket(remote, local, []byte(testCase.name)))
		if err != nil {
			t.Fatal(err)
		}
		if !nftablesTestWaitUDPPacket(packets, local, remote) {
			t.Errorf("%s: no reply from %s to %s", testCase.name, local, remote)
		}
	}
}

func nftablesTestUDPPacket(source netip.AddrPort, destination netip.AddrPort, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ipHdr := header.IPv4(packet)
	ipHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
	})
	ipHdr.SetSourceAddr(source.Addr())
	ipHdr.SetDestinationAddr(destination.Addr())
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	udpHdr := header.UDP(ipHdr.Payload())
	udpHdr.Encode(&header.UDPFields{
		SrcPort: source.Port(),
		DstPort: destination.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(udpHdr.Payload(), payload)
	udpHdr.SetChecksum(^checksum.Checksum(payload, udpHdr.CalculateChecksum(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, ipHdr.SourceAddressSlice(), ipHdr.DestinationAddressSlice(), udpHdr.Length()),
	)))
	return packet
}

func nftablesTestWaitUDPPacket(packets <-chan []byte, source netip.AddrPort, destination netip.AddrPort) bool {
	timeout := time.After(3 * time.Second)
	for {
		select {
		case packet := <-packets:
			if len(packet) < header.IPv4MinimumSize || header.IPVersion(packet) != header.IPv4Version {
				continue
			}
			ipHdr := header.IPv4(packet)
			if ipHdr.TransportProtocol() != header.UDPProtocolNumber || ipHdr.SourceAddr() != source.Addr() || ipHdr.DestinationAddr() != destination.Addr() {
				continue
			}
			udpHdr := header.UDP(ipHdr.Payload())
			if udpHdr.SourcePort() == source.Port() && udpHdr.DestinationPort() == destination.Port() {
				return true
			}
		case <-timeout:
			return false
		}
	}
}
