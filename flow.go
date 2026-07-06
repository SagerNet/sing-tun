package tun

import "net/netip"

type FlowVerdict struct {
	Action      FlowAction
	Port        Port
	Destination netip.AddrPort
}

type FlowAction uint8

const (
	ActionAccept FlowAction = iota
	ActionFlow
	ActionReject
	ActionDrop
	ActionBypass
)

type Port interface {
	PortAddresses() (v4 netip.Addr, v6 netip.Addr)
	PortMTU() uint32
	AttachReturn(returnPath Return) error
	DetachReturn(returnPath Return) error
	WritePackets(packets [][]byte) error
}

type Return interface {
	ReturnHeadroom() int
	ReturnPackets(packets [][]byte) [][]byte
}
