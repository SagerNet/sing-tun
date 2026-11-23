package tun

import (
	"net"
	"time"
)

const (
	goKeepaliveDefaultIdle     = 5 * time.Minute
	goKeepaliveDefaultInterval = 75 * time.Second
	goKeepaliveDefaultCount    = 9
	goKeepaliveMaxCount        = 127
)

func (c *GoConn) SetKeepAlive(keepalive bool) error {
	c.access.Lock()
	c.keepaliveEnabled = keepalive
	c.access.Unlock()
	c.engine.postMessage(&c.keepaliveMessage)
	return nil
}

func (c *GoConn) SetKeepAlivePeriod(d time.Duration) error {
	c.access.Lock()
	c.setKeepaliveIdle(d)
	c.access.Unlock()
	c.engine.postMessage(&c.keepaliveMessage)
	return nil
}

func (c *GoConn) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	c.access.Lock()
	c.keepaliveEnabled = config.Enable
	c.setKeepaliveIdle(config.Idle)
	switch {
	case config.Interval == 0:
		c.keepaliveInterval = goKeepaliveDefaultInterval
	case config.Interval > 0:
		c.keepaliveInterval = config.Interval
	}
	switch {
	case config.Count == 0:
		c.keepaliveCount = goKeepaliveDefaultCount
	case config.Count > 0:
		c.keepaliveCount = uint8(min(config.Count, goKeepaliveMaxCount))
	}
	c.access.Unlock()
	c.engine.postMessage(&c.keepaliveMessage)
	return nil
}

func (c *GoConn) setKeepaliveIdle(idle time.Duration) {
	switch {
	case idle == 0:
		c.keepaliveIdle = goKeepaliveDefaultIdle
	case idle > 0:
		c.keepaliveIdle = idle
	}
}

func (c *GoConn) SetNoDelay(noDelay bool) error {
	c.access.Lock()
	c.nagle = !noDelay
	c.access.Unlock()
	return nil
}

func (c *GoConn) SetLinger(sec int) error {
	c.access.Lock()
	c.linger = sec
	c.access.Unlock()
	return nil
}

func (c *GoConn) SetReadBuffer(size int) error {
	c.access.Lock()
	c.receiveCapacityMax = min(uint64(max(size, goSlabSize)), c.engine.stack.profile.receiveMax)
	c.access.Unlock()
	return nil
}

func (c *GoConn) SetWriteBuffer(size int) error {
	c.access.Lock()
	c.transmitCapacity = min(uint64(max(size, goSlabSize)), c.engine.stack.profile.transmitMax)
	c.access.Unlock()
	return nil
}
