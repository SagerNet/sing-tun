//go:build !(linux || windows || darwin || freebsd)

package tun

import (
	"os"

	"github.com/sagernet/sing/common/logger"
)

func NewNetworkUpdateMonitor(logger logger.Logger) (NetworkUpdateMonitor, error) {
	return nil, os.ErrInvalid
}

func NewDefaultInterfaceMonitor(networkMonitor NetworkUpdateMonitor, logger logger.Logger, options DefaultInterfaceMonitorOptions) (DefaultInterfaceMonitor, error) {
	return nil, os.ErrInvalid
}
