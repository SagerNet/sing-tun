package tun

import (
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

func IsRecoverableReadError(err error) bool {
	return E.IsMulti(err, syscall.EAGAIN, syscall.EINTR, syscall.ENOMEM, syscall.ENOBUFS)
}

type ReadRetry struct {
	delay time.Duration
}

func (r *ReadRetry) Wait() {
	if r.delay == 0 {
		r.delay = 5 * time.Millisecond
	} else {
		r.delay = min(2*r.delay, time.Second)
	}
	time.Sleep(r.delay)
}

func (r *ReadRetry) Reset() {
	r.delay = 0
}
