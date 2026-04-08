//go:build !(linux || windows)

package tun

import (
	"os"
)

func NewAutoRedirect(options AutoRedirectOptions) (AutoRedirect, error) {
	return nil, os.ErrInvalid
}
