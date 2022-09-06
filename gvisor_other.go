//go:build !no_gvisor && !(linux || windows || darwin)

package tun

func NewGVisor(
	options StackOptions,
) (Stack, error) {
	return nil, ErrGVisorUnsupported
}
