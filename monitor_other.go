//go:build !(linux || windows || darwin)

package tun

import (
	"github.com/sagernet/sing/common/logger"
	"os"
)

func NewNetworkUpdateMonitor(logger logger.Logger) (NetworkUpdateMonitor, error) {
	return nil, os.ErrInvalid
}

func NewDefaultInterfaceMonitor(networkMonitor NetworkUpdateMonitor, logger logger.Logger, options DefaultInterfaceMonitorOptions) (DefaultInterfaceMonitor, error) {
	return nil, os.ErrInvalid
}
