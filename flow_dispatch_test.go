package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
)

type closeOnAttachTracker struct{}

func (closeOnAttachTracker) AttachFlow(handle FlowHandle) { handle.CloseFlow() }
func (closeOnAttachTracker) CountForward(int)             {}
func (closeOnAttachTracker) CountReverse(int)             {}
func (closeOnAttachTracker) FlowEstablished()             {}
func (closeOnAttachTracker) CloseFlow(FlowCloseReason)    {}

type recordingPort struct {
	address netip.Addr
	written int
}

func (p *recordingPort) PortAddresses() (netip.Addr, netip.Addr) { return p.address, netip.Addr{} }
func (*recordingPort) PortMTU() uint32                           { return 0 }
func (*recordingPort) AttachReturn(Return) error                 { return nil }
func (*recordingPort) DetachReturn(Return) error                 { return nil }
func (p *recordingPort) WritePackets(packets [][]byte) error {
	p.written += len(packets)
	return nil
}

type closeOnAttachHandler struct {
	Handler
	port Port
}

func (h closeOnAttachHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	return FlowVerdict{Action: ActionFlow, Port: h.port, NewTracker: func() FlowTracker { return closeOnAttachTracker{} }}
}

func TestForwardFlowClosedOnAttach(t *testing.T) {
	port := &recordingPort{address: netip.MustParseAddr("192.0.2.1")}
	dispatcher := NewForwardDispatcher(closeOnAttachHandler{port: port}, nil, logger.NOP(), 0, 0)
	t.Cleanup(dispatcher.Close)
	stage := dispatcher.NewStage(nil)
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+1)
	goEncodeUDPPacket(packet, 4, netip.MustParseAddrPort("198.18.0.2:12345"), netip.MustParseAddrPort("203.0.113.1:443"), []byte{1}, 1)
	if !stage.Dispatch(packet) {
		t.Fatal("packet was not handled")
	}
	stage.Flush()
	if port.written != 0 {
		t.Fatal("packet forwarded on a flow closed by its tracker")
	}
}
