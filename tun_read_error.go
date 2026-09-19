package tun

import (
	"errors"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"
)

func IsRecoverableReadError(err error) bool {
	return errors.Is(err, ErrTooManySegments) || E.IsMulti(err, syscall.EAGAIN, syscall.EINTR, syscall.ENOMEM, syscall.ENOBUFS)
}
