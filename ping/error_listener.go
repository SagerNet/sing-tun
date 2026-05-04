package ping

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
)

// tryListenErrors tries to create an ICMP error listener, first with
// privileged sockets, falling back to unprivileged if needed.
// Returns nil (no error) if neither mode succeeds.
func tryListenErrors(
	ctx context.Context,
	logger logger.ContextLogger,
	controlFunc control.Func,
	destination netip.Addr,
) *ErrorListener {
	errorListener, err := listenErrors(true, controlFunc, destination)
	if err != nil {
		logger.DebugContext(ctx, "privileged error listener failed: ", err)
		errorListener, err = listenErrors(false, controlFunc, destination)
		if err != nil {
			logger.DebugContext(ctx, "unprivileged error listener failed: ", err)
		}
	}
	return errorListener
}
