package tun

import (
	"context"
	"net/netip"
	"sync"
	"time"
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
	type expiredSession struct {
		port    uint16
		session *TCPSession
	}
	var expired []expiredSession
	n.portAccess.RLock()
	for natPort, session := range n.portMap {
		session.Lock()
		timedOut := now.Sub(session.LastActive) > n.timeout
		session.Unlock()
		if timedOut {
			expired = append(expired, expiredSession{port: natPort, session: session})
		}
	}
	n.portAccess.RUnlock()
	if len(expired) == 0 {
		return
	}
	n.addrAccess.Lock()
	n.portAccess.Lock()
	for _, e := range expired {
		e.session.Lock()
		if now.Sub(e.session.LastActive) > n.timeout {
			delete(n.addrMap, tcpNatKey{Source: e.session.Source, Destination: e.session.Destination})
			delete(n.portMap, e.port)
		}
		e.session.Unlock()
	}
	n.portAccess.Unlock()
	n.addrAccess.Unlock()
}

func (n *TCPNat) Purge() {
	n.addrAccess.Lock()
	n.portAccess.Lock()
	clear(n.addrMap)
	clear(n.portMap)
	n.portAccess.Unlock()
	n.addrAccess.Unlock()
}

func (n *TCPNat) LookupBack(port uint16) *TCPSession {
	n.portAccess.RLock()
	session := n.portMap[port]
	n.portAccess.RUnlock()
	if session != nil {
		session.Lock()
		if time.Since(session.LastActive) > time.Second {
			session.LastActive = time.Now()
		}
		session.Unlock()
	}
	return session
}

func (n *TCPNat) Lookup(source netip.AddrPort, destination netip.AddrPort) uint16 {
	key := tcpNatKey{Source: source, Destination: destination}
	n.addrAccess.RLock()
	port, loaded := n.addrMap[key]
	n.addrAccess.RUnlock()
	if loaded {
		return port
	}
	n.addrAccess.Lock()
	defer n.addrAccess.Unlock()
	if port, loaded = n.addrMap[key]; loaded {
		return port
	}
	n.portAccess.Lock()
	defer n.portAccess.Unlock()
	nextPort, ok := n.allocatePortLocked()
	if !ok {
		return 0
	}
	n.portMap[nextPort] = &TCPSession{
		Source:      source,
		Destination: destination,
		LastActive:  time.Now(),
	}
	n.addrMap[key] = nextPort
	return nextPort
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
