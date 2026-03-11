package winredirect

import (
	"unsafe"
)

func (m *Manager) SetConfig(cfg *Config) error {
	_, err := m.ioctl(
		ioctlSetConfig,
		unsafe.Pointer(cfg),
		uint32(unsafe.Sizeof(*cfg)),
		nil, 0,
	)
	return err
}

func (m *Manager) StartRedirect() error {
	_, err := m.ioctl(ioctlStart, nil, 0, nil, 0)
	return err
}

func (m *Manager) StopRedirect() error {
	_, err := m.ioctl(ioctlStop, nil, 0, nil, 0)
	return err
}

// GetPendingConn blocks until a connection needs a verdict.
// Multiple goroutines may call this concurrently (inverted IOCTL pattern).
func (m *Manager) GetPendingConn() (*PendingConn, error) {
	var conn PendingConn
	_, err := m.ioctl(
		ioctlGetPending,
		nil, 0,
		unsafe.Pointer(&conn),
		uint32(unsafe.Sizeof(conn)),
	)
	if err != nil {
		return nil, err
	}
	return &conn, nil
}

func (m *Manager) SetVerdict(v *Verdict) error {
	_, err := m.ioctl(
		ioctlSetVerdict,
		unsafe.Pointer(v),
		uint32(unsafe.Sizeof(*v)),
		nil, 0,
	)
	return err
}
