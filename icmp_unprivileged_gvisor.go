//go:build with_gvisor

package tun

import (
	"net/netip"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func (d *UnprivilegedICMPDestination) WritePacketBuffer(packetBuffer *stack.PacketBuffer) error {
	ipHdr := packetBuffer.Network()
	if !d.isIPv6 {
		d.localAddr.Store(netip.AddrFrom4(ipHdr.SourceAddress().As4()))
	} else {
		d.localAddr.Store(netip.AddrFrom16(ipHdr.SourceAddress().As16()))
	}
	packetSlice := packetBuffer.TransportHeader().Slice()
	packetSlice = append(packetSlice, packetBuffer.Data().AsRange().ToSlice()...)
	_, err := d.rawConn.Write(packetSlice)
	return err
}
