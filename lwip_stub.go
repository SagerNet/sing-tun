//go:build !with_lwip

package tun

func NewLWIP(
	options StackOptions,
) (Stack, error) {
	return nil, ErrLWIPNotIncluded
}
