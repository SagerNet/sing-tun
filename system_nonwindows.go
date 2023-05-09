//go:build !windows

package tun

func fixWindowsFirewall() error {
	return nil
}
