//go:build !(linux || windows || darwin)

package tun

import E "github.com/sagernet/sing/common/exceptions"

const goEngineInlineTransmit = false

func newGoPlatformIO(stack *Go) (goPlatformIO, error) {
	return nil, E.New("go: unsupported platform")
}

func goFatalReadError(err error) bool {
	return true
}
