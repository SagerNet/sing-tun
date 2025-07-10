//go:build with_gvisor && darwin

package tun

import (
	"github.com/sagernet/gvisor/pkg/tcpip/link/qdisc/fifo"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-tun/internal/fdbased_darwin"
)

var _ GVisorTun = (*NativeTun)(nil)

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	ep, err := fdbased.New(&fdbased.Options{
		FDs:                []int{t.tunFd},
		MTU:                t.options.MTU,
		RXChecksumOffload:  true,
		PacketDispatchMode: fdbased.RecvMMsg,
	})
	if err != nil {
		return nil, stack.NICOptions{}, err
	}
	return ep, stack.NICOptions{
		QDisc: fifo.New(ep, 1, 1000),
	}, nil
}
