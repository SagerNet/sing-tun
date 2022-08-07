package tun

import E "github.com/sagernet/sing/common/exceptions"

var (
	ErrGVisorNotIncluded = E.New("gVisor is disabled in current build, try build without -tags `no_gvisor`")
	ErrGVisorUnsupported = E.New("gVisor stack is unsupported on current platform")
)

type Stack interface {
	Close() error
}
