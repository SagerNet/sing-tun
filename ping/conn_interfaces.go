package ping

import "net/netip"

type readMsgConn interface {
	ReadMsg(b, oob []byte) (n, oobn int, addr netip.Addr, err error)
}

type ttlSetter interface {
	SetTTL(ttl uint8)
}
