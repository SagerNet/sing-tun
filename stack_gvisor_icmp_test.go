//go:build with_gvisor

package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing/common/logger"
)

func TestICMPForwarderClosedOnAttach(t *testing.T) {
	port := &recordingPort{address: netip.IPv4Unspecified()}
	forwarder := NewICMPForwarder(nil, nil, logger.NOP())
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData([]byte{1})})
	defer pkt.DecRef()
	key := icmpFlowKey{source: netip.MustParseAddr("198.18.0.2"), destination: netip.MustParseAddr("203.0.113.1"), identifier: 1}
	verdict := FlowVerdict{Action: ActionFlow, Port: port, NewTracker: func() FlowTracker { return closeOnAttachTracker{} }}
	if !forwarder.installFlow(key, verdict, pkt) {
		t.Fatal("flow was not installed")
	}
	if port.written != 0 {
		t.Fatal("packet forwarded on a flow closed by its tracker")
	}
}
