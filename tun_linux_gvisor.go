//go:build with_gvisor && linux

package tun

import (
	"github.com/sagernet/gvisor/pkg/tcpip/link/fdbased"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func init() {
	fdbased.BufConfig = []int{65535}
}

var _ GVisorTun = (*NativeTun)(nil)

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	if t.vnetHdr {
		ep, err := fdbased.New(&fdbased.Options{
			FDs:               []int{t.tunFd},
			MTU:               t.options.MTU,
			GSOMaxSize:        gsoMaxSize,
			GRO:               true,
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
