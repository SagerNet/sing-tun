//go:build darwin || linux

package tun

type goMemoryPoller = goPoller

func (o *goMemoryIO) supportsSockets() bool {
	return true
}
