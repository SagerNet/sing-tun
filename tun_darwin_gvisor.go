//go:build with_gvisor && darwin

package tun

import (
	"runtime"

	"github.com/sagernet/gvisor/pkg/tcpip/link/qdisc/fifo"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-tun/internal/fdbased_darwin"
)

var _ GVisorTun = (*NativeTun)(nil)

func (t *NativeTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	ep, err := fdbased.New(&fdbased.Options{
		FDs:               []int{int(t.tunFile.Fd())},
		MTU:               t.options.MTU,
		RXChecksumOffload: true,
	})
	if err != nil {
		return nil, stack.NICOptions{}, err
	}
	return ep, stack.NICOptions{
		QDisc: fifo.New(ep, runtime.GOMAXPROCS(0), 1000),
	}, nil
}
