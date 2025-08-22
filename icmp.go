package tun

import (
	"context"
	"net"
	"net/netip"
	"os"
	"runtime"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sys/unix"
)

func NewICMPDestination(ctx context.Context, logger logger.Logger, dialer net.Dialer, network string, address netip.Addr, routeContext DirectRouteContext) (DirectRouteDestination, error) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		return NewUnprivilegedICMPDestination(ctx, logger, dialer, network, address, routeContext)
	} else {
		destination, err := NewPrivilegedICMPDestination(ctx, logger, dialer, network, address, routeContext)
		if err != nil {
			if E.IsMulti(err, os.ErrPermission, unix.EPERM) {
				return NewUnprivilegedICMPDestination(ctx, logger, dialer, network, address, routeContext)
			}
			return nil, err
		}
		return destination, nil
	}
}
