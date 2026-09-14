package tun

import (
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func kernelProcessCPU(t *testing.T) time.Duration {
	t.Helper()
	var created, exited, kernel, user windows.Filetime
	err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user)
	if err != nil {
		t.Fatal(err)
	}
	kernelTicks := uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)
	userTicks := uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
	return time.Duration(kernelTicks+userTicks) * 100
}
