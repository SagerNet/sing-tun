//go:build darwin || linux

package tun

import (
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func goFatalReadError(err error) bool {
	return E.IsMulti(err, unix.EBADF, unix.ENODEV, unix.ENXIO)
}
