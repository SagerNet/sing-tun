package tun

import (
	"bytes"
	"fmt"
	"net/netip"
	_ "unsafe"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type Rule struct {
	Priority             int
	Family               int
	Table                int
	Mark                 int
	Mask                 int
	TunID                uint
	Goto                 int
	Src                  netip.Prefix
	Dst                  netip.Prefix
	Flow                 int
	IifName              string
	OifName              string
	SuppressIfgroup      int
	SuppressPrefixLength int
	Invert               bool

	IPProtocol   int
	SrcPortRange *RulePortRange
	DstPortRange *RulePortRange
	UIDRange     *RuleUIDRange
}

func NewRule() *Rule {
	return &Rule{
		SuppressIfgroup:      -1,
		SuppressPrefixLength: -1,
		Priority:             -1,
		Mark:                 -1,
		Mask:                 -1,
		Goto:                 -1,
		Flow:                 -1,
		IPProtocol:           -1,
	}
}

//go:linkname pkgHandle github.com/vishvananda/netlink.pkgHandle
var pkgHandle *netlink.Handle

//go:linkname newNetlinkRequest github.com/vishvananda/netlink.(*Handle).newNetlinkRequest
func newNetlinkRequest(h *netlink.Handle, proto, flags int) *nl.NetlinkRequest

func RuleAdd(rule *Rule) error {
	req := newNetlinkRequest(pkgHandle, unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)
	return ruleHandle(rule, req)
}

func RuleDel(rule *Rule) error {
	req := newNetlinkRequest(pkgHandle, unix.RTM_DELRULE, unix.NLM_F_ACK)
	return ruleHandle(rule, req)
}

type RulePortRange struct {
	Start uint16
	End   uint16
}

func (pr *RulePortRange) toRtAttrData() []byte {
	native := nl.NativeEndian()
	b := [][]byte{make([]byte, 2), make([]byte, 2)}
	native.PutUint16(b[0], pr.Start)
	native.PutUint16(b[1], pr.End)
	return bytes.Join(b, []byte{})
}

type RuleUIDRange struct {
	Start uint32
	End   uint32
}

func (pr *RuleUIDRange) toRtAttrData() []byte {
	native := nl.NativeEndian()
	b := [][]byte{make([]byte, 4), make([]byte, 4)}
	native.PutUint32(b[0], pr.Start)
	native.PutUint32(b[1], pr.End)
	return bytes.Join(b, []byte{})
}

func ruleHandle(rule *Rule, req *nl.NetlinkRequest) error {
	msg := nl.NewRtMsg()
	msg.Family = unix.AF_INET
	msg.Protocol = unix.RTPROT_BOOT
	msg.Scope = unix.RT_SCOPE_UNIVERSE
	msg.Table = unix.RT_TABLE_UNSPEC
	msg.Type = unix.RTN_UNSPEC
	if rule.Table >= 256 {
		msg.Type = unix.FR_ACT_TO_TBL
	} else if rule.Goto >= 0 {
		msg.Type = unix.FR_ACT_GOTO
	} else if req.NlMsghdr.Flags&unix.NLM_F_CREATE > 0 {
		msg.Type = unix.FR_ACT_NOP
	}
	if rule.Invert {
		msg.Flags |= netlink.FibRuleInvert
	}
	if rule.Family != 0 {
		msg.Family = uint8(rule.Family)
	}
	if rule.Table >= 0 && rule.Table < 256 {
		msg.Table = uint8(rule.Table)
	}

	var dstFamily uint8
	var rtAttrs []*nl.RtAttr

	if rule.Dst.IsValid() {
		msg.Dst_len = uint8(rule.Dst.Bits())
		msg.Family = uint8(nl.GetIPFamily(rule.Dst.Addr().AsSlice()))
		dstFamily = msg.Family
		rtAttrs = append(rtAttrs, nl.NewRtAttr(unix.RTA_DST, rule.Dst.Addr().AsSlice()))
	}

	if rule.Src.IsValid() {
		msg.Src_len = uint8(rule.Src.Bits())
		msg.Family = uint8(nl.GetIPFamily(rule.Src.Addr().AsSlice()))
		if dstFamily != 0 && dstFamily != msg.Family {
			return fmt.Errorf("source and destination ip are not the same IP family")
		}
		dstFamily = msg.Family
		rtAttrs = append(rtAttrs, nl.NewRtAttr(unix.RTA_SRC, rule.Src.Addr().AsSlice()))
	}

	req.AddData(msg)
	for i := range rtAttrs {
		req.AddData(rtAttrs[i])
	}

	native := nl.NativeEndian()

	if rule.Priority >= 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.Priority))
		req.AddData(nl.NewRtAttr(nl.FRA_PRIORITY, b))
	}
	if rule.Mark >= 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.Mark))
		req.AddData(nl.NewRtAttr(nl.FRA_FWMARK, b))
	}
	if rule.Mask >= 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.Mask))
		req.AddData(nl.NewRtAttr(nl.FRA_FWMASK, b))
	}
	if rule.Flow >= 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.Flow))
		req.AddData(nl.NewRtAttr(nl.FRA_FLOW, b))
	}
	if rule.TunID > 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.TunID))
		req.AddData(nl.NewRtAttr(nl.FRA_TUN_ID, b))
	}
	if rule.Table >= 256 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.Table))
		req.AddData(nl.NewRtAttr(nl.FRA_TABLE, b))
	}
	if msg.Table > 0 {
		if rule.SuppressPrefixLength >= 0 {
			b := make([]byte, 4)
			native.PutUint32(b, uint32(rule.SuppressPrefixLength))
			req.AddData(nl.NewRtAttr(nl.FRA_SUPPRESS_PREFIXLEN, b))
		}
		if rule.SuppressIfgroup >= 0 {
			b := make([]byte, 4)
			native.PutUint32(b, uint32(rule.SuppressIfgroup))
			req.AddData(nl.NewRtAttr(nl.FRA_SUPPRESS_IFGROUP, b))
		}
	}
	if rule.IifName != "" {
		req.AddData(nl.NewRtAttr(nl.FRA_IIFNAME, []byte(rule.IifName)))
	}
	if rule.OifName != "" {
		req.AddData(nl.NewRtAttr(nl.FRA_OIFNAME, []byte(rule.OifName)))
	}
	if rule.Goto >= 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(rule.Goto))
		req.AddData(nl.NewRtAttr(nl.FRA_GOTO, b))
	}
	if rule.IPProtocol >= 0 {
		req.AddData(nl.NewRtAttr(unix.FRA_IP_PROTO, []byte{byte(rule.IPProtocol)}))
	}
	if rule.SrcPortRange != nil {
		b := rule.SrcPortRange.toRtAttrData()
		req.AddData(nl.NewRtAttr(unix.FRA_SPORT_RANGE, b))
	}
	if rule.DstPortRange != nil {
		b := rule.DstPortRange.toRtAttrData()
		req.AddData(nl.NewRtAttr(unix.FRA_DPORT_RANGE, b))
	}
	if rule.UIDRange != nil {
		b := rule.UIDRange.toRtAttrData()
		req.AddData(nl.NewRtAttr(unix.FRA_UID_RANGE, b))
	}
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}
