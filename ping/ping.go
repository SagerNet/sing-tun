package ping

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"time"

	"github.com/sagernet/sing-tun/internal/gtcpip/checksum"
	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Conn struct {
	ctx         context.Context
	logger      logger.ContextLogger
	privileged  bool
	conn        net.Conn
	destination netip.Addr
	source      atomic.TypedValue[netip.Addr]
	closed      atomic.Bool
}

func Connect(ctx context.Context, logger logger.ContextLogger, privileged bool, controlFunc control.Func, destination netip.Addr) (*Conn, error) {
	conn, err := connect0(ctx, privileged, controlFunc, destination)
	if err != nil {
		return nil, err
	}
	return &Conn{
		ctx:         ctx,
		logger:      logger,
		privileged:  privileged,
		conn:        conn,
		destination: destination,
	}, nil
}

func connect0(ctx context.Context, privileged bool, controlFunc control.Func, destination netip.Addr) (net.Conn, error) {
	if (runtime.GOOS == "linux" || runtime.GOOS == "android") && !privileged {
		return newUnprivilegedConn(ctx, controlFunc, destination)
	} else {
		return connect(privileged, controlFunc, destination)
	}
}

func (c *Conn) ReadIP(buffer *buf.Buffer) error {
	if c.destination.Is6() || (runtime.GOOS == "linux" || runtime.GOOS == "android") && !c.privileged {
		var readMsg func(b, oob []byte) (n, oobn int, addr netip.Addr, err error)
		switch conn := c.conn.(type) {
		case *net.IPConn:
			readMsg = func(b, oob []byte) (n, oobn int, addr netip.Addr, err error) {
				var ipAddr *net.IPAddr
				n, oobn, _, ipAddr, err = conn.ReadMsgIP(b, oob)
				if err == nil {
					addr = M.AddrFromNet(ipAddr)
				}
				return
			}
		case *net.UDPConn:
			readMsg = func(b, oob []byte) (n, oobn int, addr netip.Addr, err error) {
				var addrPort netip.AddrPort
				n, oobn, _, addrPort, err = conn.ReadMsgUDPAddrPort(b, oob)
				if err == nil {
					addr = addrPort.Addr()
				}
				return
			}
		case *UnprivilegedConn:
			readMsg = conn.ReadMsg
		default:
			return E.New("unsupported conn type: ", reflect.TypeOf(c.conn))
		}
		if !c.destination.Is6() {
			oob := ipv4.NewControlMessage(ipv4.FlagTTL)
			buffer.Advance(header.IPv4MinimumSize)
			var ttl int
			// tos int
			n, oobn, addr, err := readMsg(buffer.FreeBytes(), oob)
			if err != nil {
				return err
			}
			if err != nil {
				return err
			}
			buffer.Truncate(n)
			if oobn > 0 {
				var controlMessage ipv4.ControlMessage
				err = controlMessage.Parse(oob[:oobn])
				if err != nil {
					return err
				}
				ttl = controlMessage.TTL
			}
			ipHdr := header.IPv4(buffer.ExtendHeader(header.IPv4MinimumSize))
			ipHdr.Encode(&header.IPv4Fields{
				// TOS:         uint8(tos),
				SrcAddr:     addr,
				DstAddr:     c.source.Load(),
				Protocol:    uint8(header.ICMPv4ProtocolNumber),
				TTL:         uint8(ttl),
				TotalLength: uint16(buffer.Len()),
			})
			ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
			c.logger.TraceContext(c.ctx, "read icmpv4 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr())
		} else {
			oob := make([]byte, 1024)
			buffer.Advance(header.IPv6MinimumSize)
			var (
				hopLimit     int
				trafficClass int
			)
			n, oobn, addr, err := readMsg(buffer.FreeBytes(), oob)
			if err != nil {
				return err
			}
			buffer.Truncate(n)
			if oobn > 0 {
				var controlMessage *ipv6.ControlMessage
				controlMessage, err = parseIPv6ControlMessage(oob[:oobn])
				if err != nil {
					return err
				}
				hopLimit = controlMessage.HopLimit
				trafficClass = controlMessage.TrafficClass
			}
			icmpHdr := header.ICMPv6(buffer.Bytes())
			icmpHdr.SetChecksum(0)
			icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: icmpHdr[:header.ICMPv6DstUnreachableMinimumSize],
				Src:    addr.AsSlice(),
				Dst:    c.source.Load().AsSlice(),
			}))
			ipHdr := header.IPv6(buffer.ExtendHeader(header.IPv6MinimumSize))
			ipHdr.Encode(&header.IPv6Fields{
				TrafficClass:      uint8(trafficClass),
				PayloadLength:     uint16(buffer.Len() - header.IPv6MinimumSize),
				TransportProtocol: header.ICMPv6ProtocolNumber,
				HopLimit:          uint8(hopLimit),
				SrcAddr:           addr,
				DstAddr:           c.source.Load(),
			})
			c.logger.TraceContext(c.ctx, "read icmpv6 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr())
		}
	} else {
		_, err := buffer.ReadOnceFrom(c.conn)
		if err != nil {
			return err
		}
		if !c.destination.Is6() {
			ipHdr := header.IPv4(buffer.Bytes())
			ipHdr.SetDestinationAddr(c.source.Load())
			ipHdr.SetChecksum(0)
			ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
			icmpHdr := header.ICMPv4(ipHdr.Payload())
			icmpHdr.SetChecksum(0)
			icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(icmpHdr.Payload(), 0)))
			c.logger.TraceContext(c.ctx, "read icmpv4 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr())
		} else {
			ipHdr := header.IPv6(buffer.Bytes())
			ipHdr.SetDestinationAddr(c.source.Load())
			icmpHdr := header.ICMPv6(ipHdr.Payload())
			icmpHdr.SetChecksum(0)
			icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: icmpHdr,
				Src:    ipHdr.SourceAddressSlice(),
				Dst:    ipHdr.DestinationAddressSlice(),
			}))
			c.logger.TraceContext(c.ctx, "read icmpv6 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr())
		}
	}
	return nil
}

func (c *Conn) ReadICMP(buffer *buf.Buffer) error {
	_, err := buffer.ReadOnceFrom(c.conn)
	if err != nil {
		return err
	}
	if c.destination.Is6() || (runtime.GOOS == "linux" || runtime.GOOS == "android") && !c.privileged {
		return nil
	}
	if !c.destination.Is6() {
		ipHdr := header.IPv4(buffer.Bytes())
		buffer.Advance(int(ipHdr.HeaderLength()))
		c.logger.TraceContext(c.ctx, "read icmpv4 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr())
	} else {
		ipHdr := header.IPv6(buffer.Bytes())
		buffer.Advance(buffer.Len() - int(ipHdr.PayloadLength()))
		c.logger.TraceContext(c.ctx, "read icmpv6 echo reply from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr())
	}
	return nil
}

func (c *Conn) WriteIP(buffer *buf.Buffer) error {
	defer buffer.Release()
	if !c.destination.Is6() {
		ipHdr := header.IPv4(buffer.Bytes())
		c.source.Store(M.AddrFromIP(ipHdr.SourceAddressSlice()))
		c.logger.TraceContext(c.ctx, "write icmpv4 echo request from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr())
		return common.Error(c.conn.Write(ipHdr.Payload()))
	} else {
		ipHdr := header.IPv6(buffer.Bytes())
		c.source.Store(M.AddrFromIP(ipHdr.SourceAddressSlice()))
		c.logger.TraceContext(c.ctx, "write icmpv6 echo request from ", ipHdr.SourceAddr(), " to ", ipHdr.DestinationAddr())
		return common.Error(c.conn.Write(ipHdr.Payload()))
	}
}

func (c *Conn) WriteICMP(buffer *buf.Buffer) error {
	defer buffer.Release()
	return common.Error(c.conn.Write(buffer.Bytes()))
}

func (c *Conn) SetLocalAddr(addr netip.Addr) {
	c.source.Store(addr)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) Close() error {
	defer c.closed.Store(true)
	return c.conn.Close()
}

func (c *Conn) IsClosed() bool {
	return c.closed.Load()
}
