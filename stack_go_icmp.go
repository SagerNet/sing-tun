package tun

import (
	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
)

func (e *goEngine) answerEcho(packet []byte, parsed *forwardPacket) {
	switch parsed.protocol {
	case uint8(header.ICMPv4ProtocolNumber):
		if len(parsed.transport) < header.ICMPv4MinimumSize {
			return
		}
		if !rewriteEchoReplyIPv4(header.IPv4(parsed.network), header.ICMPv4(parsed.transport)) {
			return
		}
	case uint8(header.ICMPv6ProtocolNumber):
		if len(parsed.transport) < header.ICMPv6MinimumSize {
			return
		}
		if !rewriteEchoReplyIPv6(header.IPv6(parsed.network), header.ICMPv6(parsed.transport)) {
			return
		}
	default:
		return
	}
	err := e.platformIO.writeFrame(e.singleFrame(packet), ForwardFrameMeta{})
	if err != nil {
		e.stack.logger.Trace(E.Cause(err, "go: write echo reply"))
	}
}
