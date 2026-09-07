package afd

import (
	"math"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	IOCTL_AFD_POLL = 0x00012024

	POLL_RECEIVE           = 0x0001
	POLL_RECEIVE_EXPEDITED = 0x0002
	POLL_SEND              = 0x0004
	POLL_DISCONNECT        = 0x0008
	POLL_ABORT             = 0x0010
	POLL_LOCAL_CLOSE       = 0x0020
	POLL_ACCEPT            = 0x0080
	POLL_CONNECT_FAIL      = 0x0100

	SIO_BASE_HANDLE     = 0x48000022
	SIO_BSP_HANDLE_POLL = 0x4800001D

	STATUS_PENDING   = 0x00000103
	STATUS_CANCELLED = 0xC0000120
	STATUS_NOT_FOUND = 0xC0000225

	FILE_OPEN            = 0x00000001
	OBJ_CASE_INSENSITIVE = 0x00000040
)

type PollHandleInfo struct {
	Handle windows.Handle
	Events uint32
	Status uint32
}

type PollInfo struct {
	Timeout         int64
	NumberOfHandles uint32
	Exclusive       uint32
	Handles         [1]PollHandleInfo
}

type OverlappedEntry struct {
	CompletionKey            uintptr
	Overlapped               *windows.Overlapped
	Internal                 uintptr
	NumberOfBytesTransferred uint32
}

type UnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type ObjectAttributes struct {
	Length                   uint32
	RootDirectory            windows.Handle
	ObjectName               *UnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type Device struct {
	handle windows.Handle
}

func Open(iocp windows.Handle, name string) (*Device, error) {
	deviceName := `\Device\Afd\` + name
	deviceNameUTF16, err := windows.UTF16FromString(deviceName)
	if err != nil {
		return nil, err
	}
	unicodeString := UnicodeString{
		Length:        uint16(len(deviceName) * 2),
		MaximumLength: uint16(len(deviceName) * 2),
		Buffer:        &deviceNameUTF16[0],
	}
	objectAttributes := ObjectAttributes{
		Length:     uint32(unsafe.Sizeof(ObjectAttributes{})),
		ObjectName: &unicodeString,
		Attributes: OBJ_CASE_INSENSITIVE,
	}
	var handle windows.Handle
	var ioStatusBlock windows.IO_STATUS_BLOCK
	err = NtCreateFile(&handle, windows.SYNCHRONIZE, &objectAttributes, &ioStatusBlock, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, FILE_OPEN, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	_, err = windows.CreateIoCompletionPort(handle, iocp, 0, 0)
	if err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	err = windows.SetFileCompletionNotificationModes(handle, windows.FILE_SKIP_SET_EVENT_ON_HANDLE)
	if err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}
	return &Device{handle: handle}, nil
}

// Poll completes through the completion port with the io status block pointer as the overlapped pointer.
func (d *Device) Poll(baseSocket windows.Handle, events uint32, ioStatusBlock *windows.IO_STATUS_BLOCK, pollInfo *PollInfo) error {
	pollInfo.Timeout = math.MaxInt64
	pollInfo.NumberOfHandles = 1
	pollInfo.Exclusive = 0
	pollInfo.Handles[0].Handle = baseSocket
	pollInfo.Handles[0].Events = events
	pollInfo.Handles[0].Status = 0
	ioStatusBlock.Status = windows.NTStatus(STATUS_PENDING)
	size := uint32(unsafe.Sizeof(*pollInfo))
	err := NtDeviceIoControlFile(d.handle, 0, 0, uintptr(unsafe.Pointer(ioStatusBlock)), ioStatusBlock, IOCTL_AFD_POLL, unsafe.Pointer(pollInfo), size, unsafe.Pointer(pollInfo), size)
	if err != nil {
		if ntstatus, isStatus := err.(windows.NTStatus); isStatus && uint32(ntstatus) == STATUS_PENDING {
			return nil
		}
		return err
	}
	return nil
}

func (d *Device) Cancel(ioStatusBlock *windows.IO_STATUS_BLOCK) error {
	if uint32(ioStatusBlock.Status) != STATUS_PENDING {
		return nil
	}
	var cancelIOStatusBlock windows.IO_STATUS_BLOCK
	err := NtCancelIoFileEx(d.handle, ioStatusBlock, &cancelIOStatusBlock)
	if err != nil {
		if ntstatus, isStatus := err.(windows.NTStatus); isStatus && (uint32(ntstatus) == STATUS_CANCELLED || uint32(ntstatus) == STATUS_NOT_FOUND) {
			return nil
		}
		return err
	}
	return nil
}

func (d *Device) Close() error {
	return windows.CloseHandle(d.handle)
}

func BaseSocket(socket windows.Handle) (windows.Handle, error) {
	var baseSocket windows.Handle
	var bytesReturned uint32
	for {
		err := windows.WSAIoctl(socket, SIO_BASE_HANDLE, nil, 0, (*byte)(unsafe.Pointer(&baseSocket)), uint32(unsafe.Sizeof(baseSocket)), &bytesReturned, nil, 0)
		if err != nil {
			err = windows.WSAIoctl(socket, SIO_BSP_HANDLE_POLL, nil, 0, (*byte)(unsafe.Pointer(&baseSocket)), uint32(unsafe.Sizeof(baseSocket)), &bytesReturned, nil, 0)
			if err != nil {
				return socket, nil
			}
		}
		if baseSocket == socket {
			return baseSocket, nil
		}
		socket = baseSocket
	}
}

type WaitCompletionPacket struct {
	handle windows.Handle
}

func WaitCompletionPacketSupported() bool {
	return procNtCreateWaitCompletionPacket.Find() == nil && procNtAssociateWaitCompletionPacket.Find() == nil && procNtCancelWaitCompletionPacket.Find() == nil
}

func NewWaitCompletionPacket() (*WaitCompletionPacket, error) {
	var handle windows.Handle
	err := NtCreateWaitCompletionPacket(&handle, windows.GENERIC_ALL, nil)
	if err != nil {
		return nil, err
	}
	return &WaitCompletionPacket{handle: handle}, nil
}

func (p *WaitCompletionPacket) Associate(iocp windows.Handle, target windows.Handle, key uintptr) (bool, error) {
	var alreadySignaled byte
	err := NtAssociateWaitCompletionPacket(p.handle, iocp, target, key, 0, 0, 0, &alreadySignaled)
	if err != nil {
		return false, err
	}
	return alreadySignaled != 0, nil
}

func (p *WaitCompletionPacket) Cancel() error {
	return NtCancelWaitCompletionPacket(p.handle, 1)
}

func (p *WaitCompletionPacket) Close() error {
	return windows.CloseHandle(p.handle)
}
