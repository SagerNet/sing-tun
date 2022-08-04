//go:build no_gvisor

package tun

type Tun interface {
	Close() error
}
