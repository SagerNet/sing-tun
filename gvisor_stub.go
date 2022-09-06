//go:build no_gvisor

package tun

func NewGVisor(
	options StackOptions,
) (Stack, error) {
	return nil, ErrGVisorNotIncluded
}
