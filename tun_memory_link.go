package tun

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	goVirtioHeaderLength      = 12
	goVirtioFlagNeedsChecksum = 1
	goVirtioFlagDataValid     = 2
	goVirtioGSOECN            = 0x80

	goEthernetTypeARP     = 0x0806
	goARPHardwareEthernet = 1
	goARPRequest          = 1
	goARPReply            = 2
	goARPPacketLength     = 28

	goNDPHopLimit                    = 255
	goNDPOptionSourceAddress         = 1
	goNDPOptionTargetAddress         = 2
	goNDPOptionPrefix                = 3
	goNDPOptionMTU                   = 5
	goNDPAdvertisementRouter         = 0x80
	goNDPAdvertisementSolicited      = 0x40
	goNDPAdvertisementOverride       = 0x20
	goNDPPrefixOnLink                = 0x80
	goNDPPrefixAutonomous            = 0x40
	goNDPNeighborAdvertisementLength = header.ICMPv6NeighborAdvertMinimumSize + 8
	goNDPNeighborSolicitationLength  = header.ICMPv6NeighborSolicitMinimumSize + 8
	goNDPRouterAdvertisementLength   = header.ICMPv6HeaderSize + header.NDPRAMinimumSize
	goNDPRouterHopLimit              = 64
	goNDPRouterLifetime              = 1800
	goNDPRouterAdvertisementInterval = goNDPRouterLifetime / 3 * time.Second
	goNDPValidLifetime               = 2592000
	goNDPPreferredLifetime           = 604800

	goPeerSolicitationInterval = 100 * time.Millisecond
)

var (
	goIPv6AllNodes      = netip.AddrFrom16(header.IPv6AllNodesMulticastAddress.As16())
	goEthernetBroadcast = [header.EthernetAddressSize]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

func goPackMAC(address []byte) uint64 {
	var packed [8]byte
	copy(packed[2:], address)
	return binary.BigEndian.Uint64(packed[:])
}

func (t *MemoryTun) linkDestination(packet []byte) ([header.EthernetAddressSize]byte, bool) {
	if header.IPVersion(packet) == header.IPv4Version {
		destination := header.IPv4(packet).DestinationAddressSlice()
		switch {
		case [header.IPv4AddressSize]byte(destination) == [header.IPv4AddressSize]byte{0xff, 0xff, 0xff, 0xff}:
			return goEthernetBroadcast, true
		case destination[0]&0xf0 == 0xe0:
			return [header.EthernetAddressSize]byte{0x01, 0x00, 0x5e, destination[1] & 0x7f, destination[2], destination[3]}, true
		}
	} else {
		destination := header.IPv6(packet).DestinationAddressSlice()
		if destination[0] == 0xff {
			return [header.EthernetAddressSize]byte{0x33, 0x33, destination[12], destination[13], destination[14], destination[15]}, true
		}
	}
	packed := t.peerMAC.Load()
	if packed == 0 {
		return [header.EthernetAddressSize]byte{}, false
	}
	var address [8]byte
	binary.BigEndian.PutUint64(address[:], packed)
	return [header.EthernetAddressSize]byte(address[2:]), true
}

func (t *MemoryTun) routerAddress() netip.Addr {
	return netip.AddrFrom16([16]byte{
		0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		t.gatewayMAC[0] ^ 0x02, t.gatewayMAC[1], t.gatewayMAC[2], 0xff, 0xfe, t.gatewayMAC[3], t.gatewayMAC[4], t.gatewayMAC[5],
	})
}

func (t *MemoryTun) outboundQueueForIPv4(destination [header.IPv4AddressSize]byte) *OutboundQueue {
	if t.route == nil {
		return t.outbound
	}
	var packet [header.IPv4MinimumSize]byte
	header.IPv4(packet[:]).Encode(&header.IPv4Fields{TotalLength: header.IPv4MinimumSize, DstAddr: netip.AddrFrom4(destination)})
	queue := t.route(packet[:])
	if queue == nil {
		return t.outbound
	}
	return queue
}

func (t *MemoryTun) learnPeer(source []byte) {
	if t.peerMACFixed || source[0]&1 != 0 {
		return
	}
	packed := goPackMAC(source)
	if packed != 0 && t.peerMAC.Load() != packed {
		t.peerMAC.Store(packed)
	}
}

func (t *MemoryTun) newOutboundFrame(length int) *buf.Buffer {
	frame := buf.NewSize(t.headroom + t.linkHeaderLength + length + t.rearSpace)
	frame.Resize(t.headroom, t.linkHeaderLength)
	return frame
}

func (t *MemoryTun) prependLinkHeader(packet *buf.Buffer) *buf.Buffer {
	if packet.Start() >= t.linkHeaderLength {
		packet.ExtendHeader(t.linkHeaderLength)
	} else {
		frame := t.newOutboundFrame(packet.Len())
		common.Must1(frame.Write(packet.Bytes()))
		packet.Release()
		packet = frame
	}
	t.encodeLinkHeader(packet.Bytes(), ForwardFrameMeta{})
	return packet
}

func goIPHeaderComplete(packet []byte) bool {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		return len(packet) >= header.IPv4MinimumSize
	case header.IPv6Version:
		return len(packet) >= header.IPv6MinimumSize
	default:
		return false
	}
}

func (t *MemoryTun) encodeLinkHeader(frame []byte, meta ForwardFrameMeta) {
	link := frame[:t.linkHeaderLength]
	packet := frame[t.linkHeaderLength:]
	if t.virtioHeader {
		t.encodeVirtioHeader(link, packet, meta)
		link = link[goVirtioHeaderLength:]
	}
	if !t.ethernet {
		return
	}
	destination, _ := t.linkDestination(packet)
	etherType := header.IPv6ProtocolNumber
	if header.IPVersion(packet) == header.IPv4Version {
		etherType = header.IPv4ProtocolNumber
	}
	t.encodeEthernetHeader(link, destination, uint16(etherType))
}

func (t *MemoryTun) encodeVirtioHeader(virtioHeader []byte, packet []byte, meta ForwardFrameMeta) {
	offset := uint16(t.linkHeaderLength - goVirtioHeaderLength)
	clear(virtioHeader[:goVirtioHeaderLength])
	if meta.needsChecksum {
		virtioHeader[0] = goVirtioFlagNeedsChecksum
		binary.LittleEndian.PutUint16(virtioHeader[6:], offset+meta.checksumStart)
		binary.LittleEndian.PutUint16(virtioHeader[8:], meta.checksumOffset)
	}
	if meta.gsoType != goGSONone {
		virtioHeader[1] = meta.gsoType
		binary.LittleEndian.PutUint16(virtioHeader[2:], offset+meta.segmentHeaderLength(packet))
		binary.LittleEndian.PutUint16(virtioHeader[4:], meta.gsoSize)
	}
	binary.LittleEndian.PutUint16(virtioHeader[10:], 1)
}

func (t *MemoryTun) encodeEthernetHeader(link []byte, destination [header.EthernetAddressSize]byte, etherType uint16) {
	copy(link[:header.EthernetAddressSize], destination[:])
	copy(link[header.EthernetAddressSize:], t.gatewayMAC[:])
	binary.BigEndian.PutUint16(link[2*header.EthernetAddressSize:], etherType)
}

func (t *MemoryTun) decodeVirtioHeader(virtioHeader []byte) (ForwardFrameMeta, bool) {
	options := GSOOptions{
		NeedsCsum:  virtioHeader[0]&goVirtioFlagNeedsChecksum != 0,
		GSOSize:    binary.LittleEndian.Uint16(virtioHeader[4:]),
		CsumStart:  binary.LittleEndian.Uint16(virtioHeader[6:]),
		CsumOffset: binary.LittleEndian.Uint16(virtioHeader[8:]),
	}
	switch virtioHeader[1] &^ goVirtioGSOECN {
	case goGSONone:
	case goGSOTypeIPv4:
		options.GSOType = GSOTCPv4
	case goGSOTypeIPv6:
		options.GSOType = GSOTCPv6
	case goUDPGSOType:
		options.GSOType = GSOUDPL4
	default:
		return ForwardFrameMeta{}, false
	}
	if options.GSOType != GSONone && (!options.NeedsCsum || options.GSOSize == 0) {
		return ForwardFrameMeta{}, false
	}
	if options.NeedsCsum {
		ethernetOffset := uint16(t.linkHeaderLength - goVirtioHeaderLength)
		if options.CsumStart < ethernetOffset {
			return ForwardFrameMeta{}, false
		}
		options.CsumStart -= ethernetOffset
	}
	meta := goFrameMeta(options)
	meta.dataValid = virtioHeader[0]&goVirtioFlagDataValid != 0
	return meta, true
}

func (o *goMemoryIO) receiveLink(buffer *buf.Buffer) (ForwardFrameMeta, bool) {
	var meta ForwardFrameMeta
	if o.tun.virtioHeader {
		if buffer.Len() < goVirtioHeaderLength {
			return meta, false
		}
		var valid bool
		meta, valid = o.tun.decodeVirtioHeader(buffer.To(goVirtioHeaderLength))
		if !valid {
			return meta, false
		}
		buffer.Advance(goVirtioHeaderLength)
	}
	if o.tun.ethernet {
		if buffer.Len() < header.EthernetMinimumSize {
			return meta, false
		}
		ethernet := header.Ethernet(buffer.To(header.EthernetMinimumSize))
		o.tun.learnPeer(ethernet[header.EthernetAddressSize : 2*header.EthernetAddressSize])
		etherType := ethernet.Type()
		buffer.Advance(header.EthernetMinimumSize)
		packet := buffer.Bytes()
		switch etherType {
		case header.IPv4ProtocolNumber:
			if meta.gsoType == goGSONone && len(packet) >= header.IPv4MinimumSize {
				totalLength := int(header.IPv4(packet).TotalLength())
				if totalLength >= header.IPv4MinimumSize && totalLength < len(packet) {
					buffer.Truncate(totalLength)
				}
			}
		case header.IPv6ProtocolNumber:
			if meta.gsoType == goGSONone && len(packet) >= header.IPv6MinimumSize {
				payloadLength := int(header.IPv6(packet).PayloadLength())
				if payloadLength > 0 && header.IPv6MinimumSize+payloadLength < len(packet) {
					buffer.Truncate(header.IPv6MinimumSize + payloadLength)
				}
			}
			if o.answerNDP(buffer.Bytes()) {
				return meta, false
			}
		case goEthernetTypeARP:
			o.answerARP(packet)
			return meta, false
		default:
			return meta, false
		}
	}
	packet := buffer.Bytes()
	if meta.needsChecksum && int(meta.checksumStart)+int(meta.checksumOffset)+2 > len(packet) {
		return meta, false
	}
	if meta.gsoType == goGSONone {
		return meta, true
	}
	var (
		ipHeaderLength int
		protocol       uint8
	)
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		if meta.gsoType == goGSOTypeIPv6 || len(packet) < header.IPv4MinimumSize {
			return meta, false
		}
		ipHeader := header.IPv4(packet)
		ipHeaderLength = int(ipHeader.HeaderLength())
		protocol = ipHeader.Protocol()
	case header.IPv6Version:
		if meta.gsoType == goGSOTypeIPv4 || len(packet) < header.IPv6MinimumSize {
			return meta, false
		}
		ipHeaderLength = header.IPv6MinimumSize
		protocol = header.IPv6(packet).NextHeader()
	default:
		return meta, false
	}
	if ipHeaderLength < header.IPv4MinimumSize || int(meta.checksumStart) != ipHeaderLength {
		return meta, false
	}
	switch meta.gsoType {
	case goGSOTypeIPv4, goGSOTypeIPv6:
		if protocol != uint8(header.TCPProtocolNumber) || meta.checksumOffset != header.TCPChecksumOffset || ipHeaderLength+header.TCPMinimumSize > len(packet) {
			return meta, false
		}
		tcpHeaderLength := int(header.TCP(packet[ipHeaderLength:]).DataOffset())
		return meta, tcpHeaderLength >= header.TCPMinimumSize && ipHeaderLength+tcpHeaderLength < len(packet)
	case goUDPGSOType:
		return meta, protocol == uint8(header.UDPProtocolNumber) && meta.checksumOffset == goUDPChecksumOffset && ipHeaderLength+header.UDPMinimumSize <= len(packet)
	default:
		return meta, false
	}
}

func (o *goMemoryIO) answerARP(packet []byte) {
	if len(packet) < goARPPacketLength ||
		binary.BigEndian.Uint16(packet[0:]) != goARPHardwareEthernet ||
		binary.BigEndian.Uint16(packet[2:]) != uint16(header.IPv4ProtocolNumber) ||
		packet[4] != header.EthernetAddressSize || packet[5] != header.IPv4AddressSize ||
		binary.BigEndian.Uint16(packet[6:]) != goARPRequest {
		return
	}
	senderAddress := [header.EthernetAddressSize]byte(packet[8:14])
	senderIP := [header.IPv4AddressSize]byte(packet[14:18])
	targetIP := [header.IPv4AddressSize]byte(packet[24:28])
	if senderIP == [header.IPv4AddressSize]byte{} || senderIP == targetIP {
		return
	}
	o.writeARP(goARPReply, senderAddress, targetIP, senderAddress, senderIP)
}

func (o *goMemoryIO) writeARP(operation uint16, destination [header.EthernetAddressSize]byte, senderIP [header.IPv4AddressSize]byte, targetAddress [header.EthernetAddressSize]byte, targetIP [header.IPv4AddressSize]byte) {
	frame := o.tun.newOutboundFrame(goARPPacketLength)
	packet := frame.Extend(goARPPacketLength)
	binary.BigEndian.PutUint16(packet[0:], goARPHardwareEthernet)
	binary.BigEndian.PutUint16(packet[2:], uint16(header.IPv4ProtocolNumber))
	packet[4] = header.EthernetAddressSize
	packet[5] = header.IPv4AddressSize
	binary.BigEndian.PutUint16(packet[6:], operation)
	copy(packet[8:14], o.tun.gatewayMAC[:])
	copy(packet[14:18], senderIP[:])
	copy(packet[18:24], targetAddress[:])
	copy(packet[24:28], targetIP[:])
	link := frame.To(o.tun.linkHeaderLength)
	if o.tun.virtioHeader {
		o.tun.encodeVirtioHeader(link, nil, ForwardFrameMeta{})
		link = link[goVirtioHeaderLength:]
	}
	o.tun.encodeEthernetHeader(link, destination, goEthernetTypeARP)
	err := o.tun.outboundQueueForIPv4(targetIP).enqueue(frame, nil, goOutboundControl, nil, 0)
	if err != nil {
		o.stack.logger.Trace(E.Cause(err, "go: write ARP"))
	}
}

func (o *goMemoryIO) solicitPeer(packet []byte) {
	now := int64(time.Since(o.epoch))
	deadline := o.solicitationDeadline.Load()
	if now < deadline || !o.solicitationDeadline.CompareAndSwap(deadline, now+int64(goPeerSolicitationInterval)) {
		return
	}
	if header.IPVersion(packet) == header.IPv4Version {
		var senderIP [header.IPv4AddressSize]byte
		if o.stack.inet4Address.Is4() {
			senderIP = o.stack.inet4Address.As4()
		}
		o.writeARP(goARPRequest, goEthernetBroadcast, senderIP, [header.EthernetAddressSize]byte{}, [header.IPv4AddressSize]byte(header.IPv4(packet).DestinationAddressSlice()))
		return
	}
	target := header.IPv6(packet).DestinationAddressSlice()
	var request [header.IPv6MinimumSize + goNDPNeighborSolicitationLength]byte
	message := header.ICMPv6(request[header.IPv6MinimumSize:])
	message.SetType(header.ICMPv6NeighborSolicit)
	copy(message[8:24], target)
	message[24] = goNDPOptionSourceAddress
	message[25] = 1
	copy(message[26:32], o.tun.gatewayMAC[:])
	solicitedNode := netip.AddrFrom16([16]byte{0xff, 0x02, 11: 0x01, 12: 0xff, 13: target[13], 14: target[14], 15: target[15]})
	o.writeNDP(request[:], o.tun.routerAddress(), solicitedNode)
}

func (o *goMemoryIO) answerNDP(packet []byte) bool {
	ipHeader := header.IPv6(packet)
	if !ipHeader.IsValid(len(packet)) || ipHeader.NextHeader() != uint8(header.ICMPv6ProtocolNumber) || ipHeader.HopLimit() != goNDPHopLimit {
		return false
	}
	message := header.ICMPv6(ipHeader.Payload())
	if len(message) < header.ICMPv6HeaderSize {
		return false
	}
	switch message.Type() {
	case header.ICMPv6NeighborSolicit:
		if len(message) >= header.ICMPv6NeighborSolicitMinimumSize {
			o.answerNeighborSolicitation(ipHeader.SourceAddr(), netip.AddrFrom16([16]byte(message[8:24])))
		}
		return true
	case header.ICMPv6RouterSolicit:
		if len(o.tun.inet6Prefix) > 0 {
			destination := ipHeader.SourceAddr()
			if destination.IsUnspecified() {
				destination = goIPv6AllNodes
			}
			o.advertiseRouter(destination)
		}
		return true
	default:
		return false
	}
}

func (o *goMemoryIO) answerNeighborSolicitation(source netip.Addr, target netip.Addr) {
	if source.IsUnspecified() || target == source || target.IsMulticast() {
		return
	}
	var reply [header.IPv6MinimumSize + goNDPNeighborAdvertisementLength]byte
	message := header.ICMPv6(reply[header.IPv6MinimumSize:])
	message.SetType(header.ICMPv6NeighborAdvert)
	message[4] = goNDPAdvertisementRouter | goNDPAdvertisementSolicited | goNDPAdvertisementOverride
	targetAddress := target.As16()
	copy(message[8:24], targetAddress[:])
	message[24] = goNDPOptionTargetAddress
	message[25] = 1
	copy(message[26:32], o.tun.gatewayMAC[:])
	o.writeNDP(reply[:], target, source)
}

func (o *goMemoryIO) loopRouterAdvertisement() {
	o.advertiseRouter(goIPv6AllNodes)
	ticker := time.NewTicker(goNDPRouterAdvertisementInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			o.advertiseRouter(goIPv6AllNodes)
		case <-o.closeSignal:
			return
		case <-o.tun.outbound.closeSignal:
			return
		}
	}
}

func (o *goMemoryIO) advertiseRouter(destination netip.Addr) {
	reply := make([]byte, header.IPv6MinimumSize+goNDPRouterAdvertisementLength+16+32*len(o.tun.inet6Prefix))
	message := header.ICMPv6(reply[header.IPv6MinimumSize:])
	message.SetType(header.ICMPv6RouterAdvert)
	message[4] = goNDPRouterHopLimit
	binary.BigEndian.PutUint16(message[6:], goNDPRouterLifetime)
	options := message[goNDPRouterAdvertisementLength:]
	options[0] = goNDPOptionSourceAddress
	options[1] = 1
	copy(options[2:8], o.tun.gatewayMAC[:])
	options[8] = goNDPOptionMTU
	options[9] = 1
	binary.BigEndian.PutUint32(options[12:], uint32(o.tun.MTU()))
	options = options[16:]
	for _, prefix := range o.tun.inet6Prefix {
		options[0] = goNDPOptionPrefix
		options[1] = 4
		options[2] = uint8(prefix.Bits())
		options[3] = goNDPPrefixOnLink
		if prefix.Bits() == 64 {
			options[3] |= goNDPPrefixAutonomous
		}
		binary.BigEndian.PutUint32(options[4:], goNDPValidLifetime)
		binary.BigEndian.PutUint32(options[8:], goNDPPreferredLifetime)
		prefixAddress := prefix.Masked().Addr().As16()
		copy(options[16:32], prefixAddress[:])
		options = options[32:]
	}
	o.writeNDP(reply, o.tun.routerAddress(), destination)
}

func (o *goMemoryIO) writeNDP(packet []byte, source netip.Addr, destination netip.Addr) {
	ipHeader := header.IPv6(packet)
	ipHeader.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(packet) - header.IPv6MinimumSize),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          goNDPHopLimit,
		SrcAddr:           source,
		DstAddr:           destination,
	})
	message := header.ICMPv6(ipHeader.Payload())
	message.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: message,
		Src:    ipHeader.SourceAddressSlice(),
		Dst:    ipHeader.DestinationAddressSlice(),
	}))
	segments := [1][]byte{packet}
	err := o.enqueue(segments[:], ForwardFrameMeta{}, goOutboundControl, nil, 0)
	if err != nil {
		o.stack.logger.Trace(E.Cause(err, "go: write NDP"))
	}
}
