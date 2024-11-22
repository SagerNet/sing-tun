//go:build with_gvisor && linux

package tun

import (
	"github.com/sagernet/gvisor/pkg/tcpip/link/fdbased"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

var _ GVisorTun = (*NativeTun)(nil)

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, error) {
	if t.vnetHdr {
		return fdbased.New(&fdbased.Options{
			FDs:               []int{t.tunFd},
			MTU:               t.options.MTU,
			GSOMaxSize:        gsoMaxSize,
			GRO:               true,
			RXChecksumOffload: true,
			TXChecksumOffload: t.txChecksumOffload,
		})
	}
	return fdbased.New(&fdbased.Options{
		FDs:               []int{t.tunFd},
		MTU:               t.options.MTU,
		RXChecksumOffload: true,
		TXChecksumOffload: t.txChecksumOffload,
	})
}
