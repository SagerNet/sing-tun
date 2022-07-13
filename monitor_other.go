//go:build !linux && !windows

package tun

import "os"

func NewMonitor() (InterfaceMonitor, error) {
	return nil, os.ErrInvalid
}
