package winredirect

// IOCTL codes matching the kernel driver definitions.
// CTL_CODE(FILE_DEVICE_NETWORK=0x12, function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
const (
	ioctlSetConfig  = (0x00120000 | (0x800 << 2)) // IOCTL_WINREDIRECT_SET_CONFIG
	ioctlStart      = (0x00120000 | (0x801 << 2)) // IOCTL_WINREDIRECT_START
	ioctlStop       = (0x00120000 | (0x802 << 2)) // IOCTL_WINREDIRECT_STOP
	ioctlGetPending = (0x00120000 | (0x803 << 2)) // IOCTL_WINREDIRECT_GET_PENDING
	ioctlSetVerdict = (0x00120000 | (0x804 << 2)) // IOCTL_WINREDIRECT_SET_VERDICT
)

const (
	VerdictRedirect = 0
	VerdictBypass   = 1
	VerdictDrop     = 2
)

// Config is sent to the driver via IOCTL_SET_CONFIG.
// Must match WINREDIRECT_CONFIG in the driver.
type Config struct {
	RedirectPort uint16
	_            [2]byte // padding
	ProxyPID     uint32
	TunGUID      [16]byte
}

// PendingConn is received from the driver via IOCTL_GET_PENDING.
// Must match WINREDIRECT_PENDING_CONN in the driver.
type PendingConn struct {
	ConnID        uint64
	AddressFamily uint8
	_             [3]byte // padding
	SrcAddr       [16]byte
	SrcPort       uint16
	_             [2]byte // padding
	DstAddr       [16]byte
	DstPort       uint16
	_             [2]byte // padding
	ProcessID     uint32
}

// Verdict is sent to the driver via IOCTL_SET_VERDICT.
// Must match WINREDIRECT_VERDICT in the driver.
type Verdict struct {
	ConnID  uint64
	Verdict uint32
	_       [4]byte // padding for alignment
}
