package tun

import (
	"encoding/binary"

	"github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
)

type rewriteRule struct {
	sourceAddress          tcpip.Address
	sourcePort             uint16
	rewriteSourcePort      bool
	destinationAddress     tcpip.Address
	destinationPort        uint16
	rewriteDestinationPort bool
}

func applyRewrite(packet *forwardPacket, rule *rewriteRule) {
	var oldSource, oldDestination tcpip.Address
	if packet.ipVersion == 4 {
		ipHdr := header.IPv4(packet.network)
		oldSource = ipHdr.SourceAddress()
		oldDestination = ipHdr.DestinationAddress()
	} else {
		ipHdr := header.IPv6(packet.network)
		oldSource = ipHdr.SourceAddress()
		oldDestination = ipHdr.DestinationAddress()
	}
	newSource := oldSource
	newDestination := oldDestination
	if rule.sourceAddress.Len() > 0 {
		newSource = rule.sourceAddress
	}
	if rule.destinationAddress.Len() > 0 {
		newDestination = rule.destinationAddress
	}
	if packet.ipVersion == 4 {
		ipHdr := header.IPv4(packet.network)
		if newSource != oldSource {
			ipHdr.SetSourceAddressWithChecksumUpdate(newSource)
		}
		if newDestination != oldDestination {
			ipHdr.SetDestinationAddressWithChecksumUpdate(newDestination)
		}
	} else {
		ipHdr := header.IPv6(packet.network)
		if newSource != oldSource {
			ipHdr.SetSourceAddress(newSource)
		}
		if newDestination != oldDestination {
			ipHdr.SetDestinationAddress(newDestination)
		}
	}
	transport := packet.transport
	switch packet.protocol {
	case uint8(header.TCPProtocolNumber):
		if len(transport) < header.TCPMinimumSize {
			return
		}
		tcpHdr := header.TCP(transport)
		if newSource != oldSource {
			tcpHdr.UpdateChecksumPseudoHeaderAddress(oldSource, newSource, true)
		}
		if newDestination != oldDestination {
			tcpHdr.UpdateChecksumPseudoHeaderAddress(oldDestination, newDestination, true)
		}
		if rule.rewriteSourcePort {
			tcpHdr.SetSourcePortWithChecksumUpdate(rule.sourcePort)
		}
		if rule.rewriteDestinationPort {
			tcpHdr.SetDestinationPortWithChecksumUpdate(rule.destinationPort)
		}
	case uint8(header.UDPProtocolNumber):
		if len(transport) < header.UDPMinimumSize {
			return
		}
		udpHdr := header.UDP(transport)
		if packet.ipVersion == 4 && udpHdr.Checksum() == 0 {
			if rule.rewriteSourcePort {
				udpHdr.SetSourcePort(rule.sourcePort)
			}
			if rule.rewriteDestinationPort {
				udpHdr.SetDestinationPort(rule.destinationPort)
			}
			return
		}
		if newSource != oldSource {
			udpHdr.UpdateChecksumPseudoHeaderAddress(oldSource, newSource, true)
		}
		if newDestination != oldDestination {
			udpHdr.UpdateChecksumPseudoHeaderAddress(oldDestination, newDestination, true)
		}
		if rule.rewriteSourcePort {
			udpHdr.SetSourcePortWithChecksumUpdate(rule.sourcePort)
		}
		if rule.rewriteDestinationPort {
			udpHdr.SetDestinationPortWithChecksumUpdate(rule.destinationPort)
		}
	case uint8(header.ICMPv4ProtocolNumber):
		if len(transport) < header.ICMPv4MinimumSize {
			return
		}
		icmpHdr := header.ICMPv4(transport)
		if rule.rewriteSourcePort {
			icmpHdr.SetIdentWithChecksumUpdate(rule.sourcePort)
		} else if rule.rewriteDestinationPort {
			icmpHdr.SetIdentWithChecksumUpdate(rule.destinationPort)
		}
	case uint8(header.ICMPv6ProtocolNumber):
		if len(transport) < header.ICMPv6MinimumSize {
			return
		}
		icmpHdr := header.ICMPv6(transport)
		if newSource != oldSource {
			icmpHdr.UpdateChecksumPseudoHeaderAddress(oldSource, newSource)
		}
		if newDestination != oldDestination {
			icmpHdr.UpdateChecksumPseudoHeaderAddress(oldDestination, newDestination)
		}
		if rule.rewriteSourcePort {
			icmpHdr.SetIdentWithChecksumUpdate(rule.sourcePort)
		} else if rule.rewriteDestinationPort {
			icmpHdr.SetIdentWithChecksumUpdate(rule.destinationPort)
		}
	}
}

func applyRewriteRaw(packet *forwardPacket, rule *rewriteRule) {
	networkHeader := packet.networkHeader()
	if rule.sourceAddress.Len() > 0 {
		networkHeader.SetSourceAddress(rule.sourceAddress)
	}
	if rule.destinationAddress.Len() > 0 {
		networkHeader.SetDestinationAddress(rule.destinationAddress)
	}
	transport := packet.transport
	switch packet.protocol {
	case uint8(header.TCPProtocolNumber):
		if len(transport) < header.TCPMinimumSize {
			return
		}
		tcpHdr := header.TCP(transport)
		if rule.rewriteSourcePort {
			tcpHdr.SetSourcePort(rule.sourcePort)
		}
		if rule.rewriteDestinationPort {
			tcpHdr.SetDestinationPort(rule.destinationPort)
		}
	case uint8(header.UDPProtocolNumber):
		if len(transport) < header.UDPMinimumSize {
			return
		}
		udpHdr := header.UDP(transport)
		if rule.rewriteSourcePort {
			udpHdr.SetSourcePort(rule.sourcePort)
		}
		if rule.rewriteDestinationPort {
			udpHdr.SetDestinationPort(rule.destinationPort)
		}
	case uint8(header.ICMPv4ProtocolNumber):
		if len(transport) < header.ICMPv4MinimumSize {
			return
		}
		icmpHdr := header.ICMPv4(transport)
		if rule.rewriteSourcePort {
			icmpHdr.SetIdent(rule.sourcePort)
		} else if rule.rewriteDestinationPort {
			icmpHdr.SetIdent(rule.destinationPort)
		}
	case uint8(header.ICMPv6ProtocolNumber):
		if len(transport) < header.ICMPv6MinimumSize {
			return
		}
		icmpHdr := header.ICMPv6(transport)
		if rule.rewriteSourcePort {
			icmpHdr.SetIdent(rule.sourcePort)
		} else if rule.rewriteDestinationPort {
			icmpHdr.SetIdent(rule.destinationPort)
		}
	}
}

func recomputeChecksums(packet *forwardPacket) {
	networkHeader := packet.networkHeader()
	if packet.ipVersion == 4 {
		ipHdr := header.IPv4(packet.network)
		ipHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	}
	transport := packet.transport
	switch packet.protocol {
	case uint8(header.TCPProtocolNumber):
		if len(transport) < header.TCPMinimumSize {
			return
		}
		tcpHdr := header.TCP(transport)
		tcpHdr.SetChecksum(0)
		payloadChecksum := checksum.Checksum(tcpHdr.Payload(), 0)
		pseudoChecksum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, networkHeader.SourceAddressSlice(), networkHeader.DestinationAddressSlice(), uint16(len(transport)))
		tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(checksum.Combine(pseudoChecksum, payloadChecksum)))
	case uint8(header.UDPProtocolNumber):
		if len(transport) < header.UDPMinimumSize {
			return
		}
		udpHdr := header.UDP(transport)
		if packet.ipVersion == 4 && udpHdr.Checksum() == 0 {
			return
		}
		udpHdr.SetChecksum(0)
		payloadChecksum := checksum.Checksum(udpHdr.Payload(), 0)
		pseudoChecksum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, networkHeader.SourceAddressSlice(), networkHeader.DestinationAddressSlice(), udpHdr.Length())
		udpChecksum := ^udpHdr.CalculateChecksum(checksum.Combine(pseudoChecksum, payloadChecksum))
		if udpChecksum == 0 {
			udpChecksum = 0xffff
		}
		udpHdr.SetChecksum(udpChecksum)
	case uint8(header.ICMPv4ProtocolNumber):
		if len(transport) < header.ICMPv4MinimumSize {
			return
		}
		icmpHdr := header.ICMPv4(transport)
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	case uint8(header.ICMPv6ProtocolNumber):
		if len(transport) < header.ICMPv6MinimumSize {
			return
		}
		icmpHdr := header.ICMPv6(transport)
		icmpHdr.SetChecksum(0)
		icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: icmpHdr,
			Src:    networkHeader.SourceAddressSlice(),
			Dst:    networkHeader.DestinationAddressSlice(),
		}))
	}
}

func clampTCPMSS(packet *forwardPacket, effectiveMTU uint32) {
	if effectiveMTU == 0 || packet.protocol != uint8(header.TCPProtocolNumber) {
		return
	}
	transport := packet.transport
	if len(transport) < header.TCPMinimumSize {
		return
	}
	tcpHdr := header.TCP(transport)
	tcpHeaderLength := int(tcpHdr.DataOffset())
	if tcpHeaderLength < header.TCPMinimumSize || tcpHeaderLength > len(transport) {
		return
	}
	networkHeaderLength := len(packet.network) - len(transport)
	if effectiveMTU <= uint32(networkHeaderLength+header.TCPMinimumSize) {
		return
	}
	maxMSS := min(effectiveMTU-uint32(networkHeaderLength+header.TCPMinimumSize), header.TCPMaximumMSS)
	options := tcpHdr.Options()
	for i := 0; i < len(options); {
		switch options[i] {
		case header.TCPOptionEOL:
			return
		case header.TCPOptionNOP:
			i++
			continue
		case header.TCPOptionMSS:
			if i+header.TCPOptionMSSLength > len(options) || options[i+1] != header.TCPOptionMSSLength {
				return
			}
			currentMSS := binary.BigEndian.Uint16(options[i+2:])
			if uint32(currentMSS) <= maxMSS {
				return
			}
			binary.BigEndian.PutUint16(options[i+2:], uint16(maxMSS))
			return
		default:
			if i+2 > len(options) {
				return
			}
			optionLength := int(options[i+1])
			if optionLength < 2 || i+optionLength > len(options) {
				return
			}
			i += optionLength
		}
	}
}

func rewriteEmbeddedDestination(embedded *embeddedPacket, destination tcpip.Address, selector uint16, remapSelector bool) {
	oldDestination := embedded.network.DestinationAddress()
	if ipHdr, isIPv4 := embedded.network.(header.IPv4); isIPv4 {
		ipHdr.SetDestinationAddressWithChecksumUpdate(destination)
	} else {
		embedded.network.SetDestinationAddress(destination)
	}
	rewriteEmbeddedSelector(embedded, oldDestination, destination, selector, remapSelector, true)
}

func rewriteEmbeddedSource(embedded *embeddedPacket, source tcpip.Address, selector uint16, remapSelector bool) {
	oldSource := embedded.network.SourceAddress()
	if ipHdr, isIPv4 := embedded.network.(header.IPv4); isIPv4 {
		ipHdr.SetSourceAddressWithChecksumUpdate(source)
	} else {
		embedded.network.SetSourceAddress(source)
	}
	rewriteEmbeddedSelector(embedded, oldSource, source, selector, remapSelector, false)
}

func rewriteEmbeddedSelector(embedded *embeddedPacket, oldAddress, newAddress tcpip.Address, selector uint16, remapSelector bool, destinationSide bool) {
	if !remapSelector {
		return
	}
	payload := embedded.payload
	_, isIPv4 := embedded.network.(header.IPv4)
	switch embedded.protocol {
	case uint8(header.TCPProtocolNumber):
		if len(payload) >= 4 {
			if destinationSide {
				binary.BigEndian.PutUint16(payload[2:], selector)
			} else {
				binary.BigEndian.PutUint16(payload[0:], selector)
			}
		}
	case uint8(header.UDPProtocolNumber):
		if len(payload) >= header.UDPMinimumSize {
			udpHdr := header.UDP(payload)
			if isIPv4 && udpHdr.Checksum() == 0 {
				if destinationSide {
					udpHdr.SetDestinationPort(selector)
				} else {
					udpHdr.SetSourcePort(selector)
				}
			} else {
				if oldAddress != newAddress {
					udpHdr.UpdateChecksumPseudoHeaderAddress(oldAddress, newAddress, true)
				}
				if destinationSide {
					udpHdr.SetDestinationPortWithChecksumUpdate(selector)
				} else {
					udpHdr.SetSourcePortWithChecksumUpdate(selector)
				}
			}
		}
	case uint8(header.ICMPv4ProtocolNumber):
		if len(payload) >= header.ICMPv4MinimumSize {
			header.ICMPv4(payload).SetIdentWithChecksumUpdate(selector)
		}
	case uint8(header.ICMPv6ProtocolNumber):
		if len(payload) >= header.ICMPv6MinimumSize {
			icmpHdr := header.ICMPv6(payload)
			if oldAddress != newAddress {
				icmpHdr.UpdateChecksumPseudoHeaderAddress(oldAddress, newAddress)
			}
			icmpHdr.SetIdentWithChecksumUpdate(selector)
		}
	}
}
