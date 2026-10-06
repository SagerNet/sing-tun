package tun

import (
	"net/netip"
	"time"
)

type FlowVerdict struct {
	Action      FlowAction
	Port        Port
	Destination netip.AddrPort
	UDPTimeout  time.Duration
	NewTracker  func() FlowTracker
}

type FlowAction uint8

const (
	ActionAccept FlowAction = iota
	ActionFlow
	ActionReject
	ActionDrop
	ActionBypass
	ActionHijackDNS
)

type FlowTracker interface {
	AttachFlow(handle FlowHandle)
	CountForward(n int)
	CountReverse(n int)
	FlowEstablished()
	CloseFlow(reason FlowCloseReason)
}

type FlowHandle interface {
	CloseFlow()
}

type FlowCloseReason uint8

const (
	FlowCloseReset FlowCloseReason = iota
	FlowCloseFinished
	FlowCloseTimeout
)

func (r FlowCloseReason) String() string {
	switch r {
	case FlowCloseFinished:
		return "finished"
	case FlowCloseTimeout:
		return "idle timeout"
	default:
		return "connection reset"
	}
}

type Port interface {
	PortAddresses() (v4 netip.Addr, v6 netip.Addr)
	PortMTU() uint32
	AttachReturn(returnPath Return) error
	DetachReturn(returnPath Return) error
	WritePackets(packets [][]byte) error
}

type SelectorRange struct {
	Start uint16
	Count uint16
}

type PortWithSelectorRange interface {
	PortSelectorRanges(protocol uint8) []SelectorRange
	ExpandSelectorRanges(protocol uint8) bool
}

type PortWithSelectorReservation interface {
	ReserveSelector(protocol uint8, address netip.AddrPort) bool
	ReleaseSelector(protocol uint8, address netip.AddrPort)
}

type PortWithUpstream interface {
	UpstreamPort() any
}

func portCapability[T any](port any) (T, bool) {
	for port != nil {
		capability, matched := port.(T)
		if matched {
			return capability, true
		}
		wrapper, isWrapper := port.(PortWithUpstream)
		if !isWrapper {
			break
		}
		port = wrapper.UpstreamPort()
	}
	var zero T
	return zero, false
}

type Return interface {
	ReturnHeadroom() int
	ReturnPackets(packets [][]byte) [][]byte
}
