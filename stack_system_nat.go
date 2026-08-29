package tun

import (
	"context"
	"net/netip"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type TCPNat struct {
	timeout    time.Duration
	portIndex  uint16
	portAccess sync.RWMutex
	addrAccess sync.RWMutex
	addrMap    map[tcpNatKey]uint16
	portMap    map[uint16]*TCPSession
}

type tcpNatKey struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
}

type TCPSession struct {
	sync.Mutex
	Source      netip.AddrPort
	Destination netip.AddrPort
	LastActive  time.Time
}

func NewNat(ctx context.Context, timeout time.Duration) *TCPNat {
	natMap := &TCPNat{
		timeout:   timeout,
		portIndex: 10000,
		addrMap:   make(map[tcpNatKey]uint16),
		portMap:   make(map[uint16]*TCPSession),
	}
	go natMap.loopCheckTimeout(ctx)
	return natMap
}

func (n *TCPNat) loopCheckTimeout(ctx context.Context) {
	ticker := time.NewTicker(n.timeout)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.checkTimeout()
		case <-ctx.Done():
			return
		}
	}
}

func (n *TCPNat) checkTimeout() {
	now := time.Now()
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	n.portAccess.Lock()
	defer n.portAccess.Unlock()
	for natPort, session := range n.portMap {
		session.Lock()
		if now.Sub(session.LastActive) > n.timeout {
			delete(n.addrMap, tcpNatKey{Source: session.Source, Destination: session.Destination})
			delete(n.portMap, natPort)
		}
		session.Unlock()
	}
}

func (n *TCPNat) LookupBack(port uint16) *TCPSession {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil {
		session.refresh()
	}
	return session
}

func (s *TCPSession) refresh() {
	s.Lock()
	if time.Since(s.LastActive) > time.Second {
		s.LastActive = time.Now()
	}
	s.Unlock()
}

func (n *TCPNat) Lookup(source netip.AddrPort, destination netip.AddrPort, handler Handler) (uint16, error) {
	key := tcpNatKey{Source: source, Destination: destination}
	n.addrAccess.RLock()
	port, loaded := n.addrMap[key]
	n.addrAccess.RUnlock()
	if loaded {
		n.refresh(port)
		return port, nil
	}
	_, pErr := handler.PrepareConnection(N.NetworkTCP, M.SocksaddrFromNetIP(source), M.SocksaddrFromNetIP(destination), nil, 0)
	if pErr != nil {
		return 0, pErr
	}
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	port, loaded = n.addrMap[key]
	if loaded {
		n.refresh(port)
		return port, nil
	}
	n.portAccess.Lock()
	defer n.portAccess.Unlock()
	nextPort, allocated := n.allocatePortLocked()
	if !allocated {
		return 0, E.New("NAT port space exhausted")
	}
	n.portMap[nextPort] = &TCPSession{
		Source:      source,
		Destination: destination,
		LastActive:  time.Now(),
	}
	n.addrMap[key] = nextPort
	return nextPort, nil
}

func (n *TCPNat) refresh(port uint16) {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil {
		session.refresh()
	}
}

func (n *TCPNat) allocatePortLocked() (uint16, bool) {
	for range 65535 - 10000 + 1 {
		nextPort := n.portIndex
		if nextPort == 0 {
			nextPort = 10000
			n.portIndex = 10001
		} else {
			n.portIndex++
		}
		if _, occupied := n.portMap[nextPort]; !occupied {
			return nextPort, true
		}
	}
	return 0, false
}
