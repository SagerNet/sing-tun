//go:build (linux && !android) || (darwin && !ios)

package tun

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func kernelProcessCPU(t *testing.T) time.Duration {
	t.Helper()
	var usage unix.Rusage
	err := unix.Getrusage(unix.RUSAGE_SELF, &usage)
	if err != nil {
		t.Fatal(err)
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}
