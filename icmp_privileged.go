package tun

import (
	"context"
	"net"
	"net/netip"
	"os"

	"github.com/sagernet/sing-tun/internal/gtcpip/checksum"
	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type PrivilegedICMPDestination struct {
	ctx          context.Context
	cancel       context.CancelCauseFunc
	logger       logger.Logger
	routeContext DirectRouteContext
	isIPv6       bool
	localAddr    atomic.TypedValue[netip.Addr]
	rawConn      net.Conn
}

func NewPrivilegedICMPDestination(ctx context.Context, logger logger.Logger, dialer net.Dialer, network string, address netip.Addr, routeContext DirectRouteContext) (DirectRouteDestination, error) {
	var dialNetwork string
	switch network {
	case N.NetworkICMPv4:
		dialNetwork = "ip4:icmp"
	case N.NetworkICMPv6:
		dialNetwork = "ip6:icmp"
	default:
		return nil, E.New("unsupported network: ", network)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	rawConn, err := dialer.DialContext(ctx, dialNetwork, address.String())
	if err != nil {
		cancel(err)
		return nil, err
	}
	d := &PrivilegedICMPDestination{
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		routeContext: routeContext,
		isIPv6:       network == N.NetworkICMPv6,
		rawConn:      rawConn,
	}
	go d.loopRead()
	return d, nil
}

func (d *PrivilegedICMPDestination) loopRead() {
	for {
		buffer := buf.NewPacket()
		_, err := buffer.ReadOnceFrom(d.rawConn)
		if err != nil {
			return
		}
		if !d.isIPv6 {
			ipHdr := header.IPv4(buffer.Bytes())
			ipHdr.SetDestinationAddr(d.localAddr.Load())
			ipHdr.SetChecksum(0)
			ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
			icmpHdr := header.ICMPv4(ipHdr.Payload())
			icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(icmpHdr.Payload(), 0)))
		} else {
			ipHdr := header.IPv6(buffer.Bytes())
			ipHdr.SetDestinationAddr(d.localAddr.Load())
			icmpHdr := header.ICMPv6(ipHdr.Payload())
			icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: icmpHdr,
				Src:    ipHdr.SourceAddress(),
				Dst:    ipHdr.DestinationAddress(),
			}))
		}
		err = d.routeContext.WritePacket(buffer.Bytes())
		if err != nil {
			d.logger.Error(err)
		}
	}
}

func (d *PrivilegedICMPDestination) WritePacket(packet *buf.Buffer) error {
	if !d.isIPv6 {
		ipHdr := header.IPv4(packet.Bytes())
		d.localAddr.Store(M.AddrFromIP(ipHdr.SourceAddressSlice()))
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		_, err := d.rawConn.Write(icmpHdr)
		if err != nil {
			return err
		}
	} else {
		ipHdr := header.IPv6(packet.Bytes())
		d.localAddr.Store(M.AddrFromIP(ipHdr.SourceAddressSlice()))
		icmpHdr := header.ICMPv6(ipHdr.Payload())
		_, err := d.rawConn.Write(icmpHdr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *PrivilegedICMPDestination) Close() error {
	d.cancel(os.ErrClosed)
	return d.rawConn.Close()
}
