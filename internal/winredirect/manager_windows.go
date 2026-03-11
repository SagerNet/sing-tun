package winredirect

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName = "WinRedirect"
	devicePath  = `\\.\WinRedirect`
)

type Manager struct {
	driverPath string
	device     windows.Handle
}

func NewManager() (*Manager, error) {
	tmpDir, err := os.MkdirTemp("", "winredirect-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	driverPath := filepath.Join(tmpDir, "winredirect.sys")
	if err = os.WriteFile(driverPath, driverContent, 0o644); err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("write driver: %w", err)
	}
	return &Manager{
		driverPath: driverPath,
		device:     windows.InvalidHandle,
	}, nil
}

func (m *Manager) Install() error {
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer scm.Disconnect()

	// Remove stale service if it exists
	if existing, err := scm.OpenService(serviceName); err == nil {
		existing.Control(windows.SERVICE_CONTROL_STOP)
		existing.Delete()
		existing.Close()
	}

	svc, err := scm.CreateService(serviceName, m.driverPath, mgr.Config{
		ServiceType: windows.SERVICE_KERNEL_DRIVER,
		StartType:   mgr.StartManual,
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	svc.Close()
	return nil
}

func (m *Manager) Start() error {
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer scm.Disconnect()

	svc, err := scm.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer svc.Close()

	if err = svc.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

func (m *Manager) OpenDevice() error {
	path, err := windows.UTF16PtrFromString(devicePath)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		path,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return fmt.Errorf("open device: %w", err)
	}
	m.device = handle
	return nil
}

func (m *Manager) ioctl(code uint32, inBuf unsafe.Pointer, inSize uint32, outBuf unsafe.Pointer, outSize uint32) (uint32, error) {
	var bytesReturned uint32
	overlapped := &windows.Overlapped{}
	overlapped.HEvent, _ = windows.CreateEvent(nil, 1, 0, nil)
	defer windows.CloseHandle(overlapped.HEvent)

	err := windows.DeviceIoControl(
		m.device,
		code,
		(*byte)(inBuf),
		inSize,
		(*byte)(outBuf),
		outSize,
		&bytesReturned,
		overlapped,
	)
	if err == windows.ERROR_IO_PENDING {
		_, err = windows.WaitForSingleObject(overlapped.HEvent, windows.INFINITE)
		if err != nil {
			return 0, err
		}
		err = windows.GetOverlappedResult(m.device, overlapped, &bytesReturned, false)
	}
	if err != nil {
		return 0, err
	}
	return bytesReturned, nil
}

func (m *Manager) Close() error {
	if m.device != windows.InvalidHandle {
		m.StopRedirect()
		windows.CloseHandle(m.device)
		m.device = windows.InvalidHandle
	}

	scm, err := mgr.Connect()
	if err == nil {
		if svc, err := scm.OpenService(serviceName); err == nil {
			svc.Control(windows.SERVICE_CONTROL_STOP)
			svc.Delete()
			svc.Close()
		}
		scm.Disconnect()
	}

	if m.driverPath != "" {
		os.RemoveAll(filepath.Dir(m.driverPath))
	}
	return nil
}
