package tun

import (
	"errors"
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// installRoutePrefixes adds each prefix. A prefix that already exists is
// removed and added again. If a later add fails, prefixes added by this
// call are removed in reverse. A pre-existing route deleted before a failed
// re-add is not put back.
func installRoutePrefixes(prefixes []netip.Prefix, add, remove func(netip.Prefix) error) error {
	installed := make([]netip.Prefix, 0, len(prefixes))
	rollback := func(cause error) error {
		var rollbackErr error
		for i := len(installed) - 1; i >= 0; i-- {
			if err := remove(installed[i]); err != nil {
				rollbackErr = E.Errors(rollbackErr, E.Cause(err, "remove route: ", installed[i]))
			}
		}
		if rollbackErr != nil {
			return E.Errors(cause, rollbackErr)
		}
		return cause
	}
	for _, prefix := range prefixes {
		err := add(prefix)
		if err == nil {
			installed = append(installed, prefix)
			continue
		}
		if !errors.Is(err, unix.EEXIST) {
			return rollback(E.Cause(err, "add route: ", prefix))
		}
		if err = remove(prefix); err != nil {
			return rollback(E.Cause(err, "remove existing route: ", prefix))
		}
		if err = add(prefix); err != nil {
			return rollback(E.Cause(err, "re-add route: ", prefix))
		}
		installed = append(installed, prefix)
	}
	return nil
}
