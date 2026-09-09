//go:build !linux

package tun

func newGoPlatformQueues(stack *Go) ([]goPlatformIO, error) {
	platformIO, err := newGoPlatformIO(stack)
	if err != nil {
		return nil, err
	}
	return []goPlatformIO{platformIO}, nil
}
