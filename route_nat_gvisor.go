//go:build with_gvisor

package tun

import (
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func (w *NatWriter) RewritePacketBuffer(packetBuffer *stack.PacketBuffer) {
	var bindAddr tcpip.Address
	if packetBuffer.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		bindAddr = AddressFromAddr(w.inet4Address)
	} else {
		bindAddr = AddressFromAddr(w.inet6Address)
	}
	/*var ipHdr header.Network
	switch packetBuffer.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		ipHdr = header.IPv4(packetBuffer.NetworkHeader().Slice())
	case header.IPv6ProtocolNumber:
		ipHdr = header.IPv6(packetBuffer.NetworkHeader().Slice())
	default:
		return
	}*/
	ipHdr := packetBuffer.Network()
	oldAddr := ipHdr.SourceAddress()
	if checksumHdr, needChecksum := ipHdr.(header.ChecksummableNetwork); needChecksum {
		checksumHdr.SetSourceAddressWithChecksumUpdate(bindAddr)
	} else {
		ipHdr.SetSourceAddress(bindAddr)
	}
	switch packetBuffer.TransportProtocolNumber {
	case header.TCPProtocolNumber:
		tcpHdr := header.TCP(packetBuffer.TransportHeader().Slice())
		tcpHdr.UpdateChecksumPseudoHeaderAddress(oldAddr, bindAddr, true)
	case header.UDPProtocolNumber:
		udpHdr := header.UDP(packetBuffer.TransportHeader().Slice())
		udpHdr.UpdateChecksumPseudoHeaderAddress(oldAddr, bindAddr, true)
	}
}
