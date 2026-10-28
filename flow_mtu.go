package tun

import (
	"encoding/binary"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

// segmentRetainCount bounds how many segment buffers survive a Flush; the pool
// grows to the burst high-water mark within a batch and is trimmed afterwards.
const segmentRetainCount = 128

func tcpSegmentSize(packet *forwardPacket, raw []byte, effectiveMTU uint32) (headerLength int, segmentSize int, ok bool) {
	if packet.fragment || len(packet.transport) < header.TCPMinimumSize {
		return 0, 0, false
	}
	networkLength := len(raw) - len(packet.transport)
	if packet.ipVersion == 6 && networkLength != header.IPv6MinimumSize {
		return 0, 0, false
	}
	tcpHeaderLength := int(header.TCP(packet.transport).DataOffset())
	if tcpHeaderLength < header.TCPMinimumSize || tcpHeaderLength > len(packet.transport) {
		return 0, 0, false
	}
	headerLength = networkLength + tcpHeaderLength
	segmentSize = int(effectiveMTU) - headerLength
	return headerLength, segmentSize, segmentSize > 0
}

// Linux delivers TSO aggregates to the TUN even with IFF_VNET_HDR off
// (observed on 6.x: the pre-segmentation skb is handed to the fd as-is).
func segmentTCP(output relayOutput, packet *forwardPacket, raw []byte, headerLength int, segmentSize int) error {
	headroom := output.relayHeadroom()
	gsoType := GSOTCPv4
	if packet.ipVersion == 6 {
		gsoType = GSOTCPv6
	}
	neededSegments := max((len(raw)-headerLength+segmentSize-1)/segmentSize, 1)
	buffers, sizes := output.relayReserve(neededSegments, headroom+headerLength+segmentSize)
	n, err := GSOSplit(raw, GSOOptions{
		GSOType:    gsoType,
		HdrLen:     uint16(headerLength),
		CsumStart:  uint16(len(raw) - len(packet.transport)),
		CsumOffset: header.TCPChecksumOffset,
		GSOSize:    uint16(segmentSize),
	}, buffers, sizes, headroom)
	if err != nil {
		return err
	}
	for i := range n {
		output.relaySegment(buffers[i][:headroom+sizes[i]])
	}
	return nil
}

func (s *ForwardStage) reserveSegments(count, size int) ([][]byte, []int) {
	start := s.segmentUsed
	end := start + count
	for len(s.segmentBuffers) < end {
		s.segmentBuffers = append(s.segmentBuffers, make([]byte, size))
		s.segmentSizes = append(s.segmentSizes, 0)
	}
	for i := start; i < end; i++ {
		if cap(s.segmentBuffers[i]) < size {
			s.segmentBuffers[i] = make([]byte, size)
		} else {
			s.segmentBuffers[i] = s.segmentBuffers[i][:size]
		}
	}
	s.segmentUsed = end
	return s.segmentBuffers[start:end], s.segmentSizes[start:end]
}

const synthesizedTTL = 64

func fragmentIPv4Packet(packet header.IPv4, effectiveMTU uint32, headroom int) ([][]byte, bool) {
	headerLength := int(packet.HeaderLength())
	if headerLength < header.IPv4MinimumSize || headerLength >= len(packet) {
		return nil, false
	}
	payload := packet[headerLength:]
	maxFragmentPayload := (int(effectiveMTU) - headerLength) &^ 7
	if maxFragmentPayload <= 0 {
		return nil, false
	}
	baseOffset := packet.FragmentOffset()
	originalMore := packet.Flags()&header.IPv4FlagMoreFragments != 0
	baseFlags := packet.Flags() &^ header.IPv4FlagMoreFragments
	fragments := make([][]byte, 0, (len(payload)+maxFragmentPayload-1)/maxFragmentPayload)
	for start := 0; start < len(payload); start += maxFragmentPayload {
		end := min(start+maxFragmentPayload, len(payload))
		buffer := make([]byte, headroom+headerLength+end-start)
		fragment := header.IPv4(buffer[headroom:])
		copy(fragment, packet[:headerLength])
		copy(fragment[headerLength:], payload[start:end])
		flags := baseFlags
		if originalMore || end < len(payload) {
			flags |= header.IPv4FlagMoreFragments
		}
		fragment.SetFlagsFragmentOffset(flags, baseOffset+uint16(start))
		fragment.SetTotalLength(uint16(len(fragment)))
		fragment.SetChecksum(0)
		fragment.SetChecksum(^fragment.CalculateChecksum())
		fragments = append(fragments, buffer)
	}
	return fragments, true
}

func fragmentIPv6Packet(packet header.IPv6, effectiveMTU uint32, ident uint32, headroom int) ([][]byte, bool) {
	if len(packet) < header.IPv6MinimumSize {
		return nil, false
	}
	payload := packet.Payload()
	maxFragmentPayload := (int(effectiveMTU) - header.IPv6MinimumSize - header.IPv6FragmentHeaderSize) &^ 7
	if maxFragmentPayload <= 0 {
		return nil, false
	}
	transportProtocol := packet.NextHeader()
	fragments := make([][]byte, 0, (len(payload)+maxFragmentPayload-1)/maxFragmentPayload)
	for start := 0; start < len(payload); start += maxFragmentPayload {
		end := min(start+maxFragmentPayload, len(payload))
		buffer := make([]byte, headroom+header.IPv6MinimumSize+header.IPv6FragmentHeaderSize+end-start)
		fragment := header.IPv6(buffer[headroom:])
		copy(fragment, packet[:header.IPv6MinimumSize])
		fragment.SetNextHeader(header.IPv6FragmentHeader)
		fragment.SetPayloadLength(uint16(header.IPv6FragmentHeaderSize + end - start))
		encodeIPv6FragmentHeader(fragment[header.IPv6MinimumSize:], transportProtocol, start, end < len(payload), ident)
		copy(fragment[header.IPv6MinimumSize+header.IPv6FragmentHeaderSize:], payload[start:end])
		fragments = append(fragments, buffer)
	}
	return fragments, true
}

func encodeIPv6FragmentHeader(target []byte, nextHeader uint8, offset int, more bool, ident uint32) {
	target[0] = nextHeader
	target[1] = 0
	value := uint16(offset)
	if more {
		value |= 1
	}
	binary.BigEndian.PutUint16(target[2:], value)
	binary.BigEndian.PutUint32(target[4:], ident)
}
