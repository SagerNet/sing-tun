//go:build with_gvisor && linux

package tun

import (
	"github.com/metacubex/gvisor/pkg/tcpip/link/fdbased"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

var _ GVisorTun = (*NativeTun)(nil)

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	if t.gsoEnabled {
		ep, err := fdbased.New(&fdbased.Options{
			FDs:               []int{t.tunFd},
			MTU:               t.options.MTU,
			GSOMaxSize:        gsoMaxSize,
			RXChecksumOffload: true,
			TXChecksumOffload: t.txChecksumOffload,
		})
		if err != nil {
			return nil, stack.NICOptions{}, err
		}
		return ep, stack.NICOptions{}, nil
	} else {
		ep, err := fdbased.New(&fdbased.Options{
			FDs:               []int{t.tunFd},
			MTU:               t.options.MTU,
			RXChecksumOffload: true,
			TXChecksumOffload: t.txChecksumOffload,
		})
		if err != nil {
			return nil, stack.NICOptions{}, err
		}
		return ep, stack.NICOptions{}, nil
	}
}
