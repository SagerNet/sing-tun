//go:build !darwin && !linux

package tun

import "time"

type goMemoryPoller struct {
	signal goSignal
	timer  *time.Timer
}

func (p *goMemoryPoller) open(deviceDescriptor int) error {
	p.signal = make(goSignal, 1)
	return nil
}

func (p *goMemoryPoller) wait(timeout time.Duration, events []goSocketEvent) (uint8, int, error) {
	switch {
	case timeout == 0:
	case timeout < 0:
		<-p.signal
	default:
		if p.timer == nil {
			p.timer = time.NewTimer(timeout)
		} else {
			p.timer.Reset(timeout)
		}
		select {
		case <-p.signal:
			p.timer.Stop()
		case <-p.timer.C:
		}
	}
	return 0, 0, nil
}

func (p *goMemoryPoller) setDeviceReadEnabled(enabled bool) error {
	return nil
}

func (p *goMemoryPoller) registerSocket(socket *goSocket, token uint32, interest uint8) error {
	return nil
}

func (p *goMemoryPoller) updateSocket(socket *goSocket, interest uint8) error {
	return nil
}

func (p *goMemoryPoller) unregisterSocket(socket *goSocket) {
}

func (p *goMemoryPoller) wake() {
	p.signal.notify()
}

func (p *goMemoryPoller) close() error {
	if p.timer != nil {
		p.timer.Stop()
	}
	return nil
}

func (o *goMemoryIO) supportsSockets() bool {
	return false
}
