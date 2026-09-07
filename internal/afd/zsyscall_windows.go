package afd

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modntdll    = windows.NewLazySystemDLL("ntdll.dll")

	procGetQueuedCompletionStatusEx     = modkernel32.NewProc("GetQueuedCompletionStatusEx")
	procNtCancelIoFileEx                = modntdll.NewProc("NtCancelIoFileEx")
	procNtCreateFile                    = modntdll.NewProc("NtCreateFile")
	procNtDeviceIoControlFile           = modntdll.NewProc("NtDeviceIoControlFile")
	procNtCreateWaitCompletionPacket    = modntdll.NewProc("NtCreateWaitCompletionPacket")
	procNtAssociateWaitCompletionPacket = modntdll.NewProc("NtAssociateWaitCompletionPacket")
	procNtCancelWaitCompletionPacket    = modntdll.NewProc("NtCancelWaitCompletionPacket")
)

func GetQueuedCompletionStatusEx(cphandle windows.Handle, entries *OverlappedEntry, count uint32, numRemoved *uint32, timeout uint32, alertable bool) error {
	var alertableValue uint32
	if alertable {
		alertableValue = 1
	}
	r1, _, e1 := syscall.SyscallN(procGetQueuedCompletionStatusEx.Addr(), uintptr(cphandle), uintptr(unsafe.Pointer(entries)), uintptr(count), uintptr(unsafe.Pointer(numRemoved)), uintptr(timeout), uintptr(alertableValue))
	if r1 == 0 {
		if e1 != 0 {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func NtCancelIoFileEx(handle windows.Handle, ioRequestToCancel *windows.IO_STATUS_BLOCK, ioStatusBlock *windows.IO_STATUS_BLOCK) error {
	r0, _, _ := syscall.SyscallN(procNtCancelIoFileEx.Addr(), uintptr(handle), uintptr(unsafe.Pointer(ioRequestToCancel)), uintptr(unsafe.Pointer(ioStatusBlock)))
	if r0 != 0 {
		return windows.NTStatus(r0)
	}
	return nil
}

func NtCreateFile(handle *windows.Handle, access uint32, objectAttributes *ObjectAttributes, ioStatusBlock *windows.IO_STATUS_BLOCK, allocationSize *int64, attributes uint32, share uint32, disposition uint32, options uint32, eaBuffer uintptr, eaLength uint32) error {
	r0, _, _ := syscall.SyscallN(procNtCreateFile.Addr(), uintptr(unsafe.Pointer(handle)), uintptr(access), uintptr(unsafe.Pointer(objectAttributes)), uintptr(unsafe.Pointer(ioStatusBlock)), uintptr(unsafe.Pointer(allocationSize)), uintptr(attributes), uintptr(share), uintptr(disposition), uintptr(options), uintptr(eaBuffer), uintptr(eaLength))
	if r0 != 0 {
		return windows.NTStatus(r0)
	}
	return nil
}

func NtDeviceIoControlFile(handle windows.Handle, event windows.Handle, apcRoutine uintptr, apcContext uintptr, ioStatusBlock *windows.IO_STATUS_BLOCK, ioControlCode uint32, inputBuffer unsafe.Pointer, inputBufferLength uint32, outputBuffer unsafe.Pointer, outputBufferLength uint32) error {
	r0, _, _ := syscall.SyscallN(procNtDeviceIoControlFile.Addr(), uintptr(handle), uintptr(event), uintptr(apcRoutine), uintptr(apcContext), uintptr(unsafe.Pointer(ioStatusBlock)), uintptr(ioControlCode), uintptr(inputBuffer), uintptr(inputBufferLength), uintptr(outputBuffer), uintptr(outputBufferLength))
	if r0 != 0 {
		return windows.NTStatus(r0)
	}
	return nil
}

func NtCreateWaitCompletionPacket(handle *windows.Handle, access uint32, objectAttributes *ObjectAttributes) error {
	r0, _, _ := syscall.SyscallN(procNtCreateWaitCompletionPacket.Addr(), uintptr(unsafe.Pointer(handle)), uintptr(access), uintptr(unsafe.Pointer(objectAttributes)))
	if r0 != 0 {
		return windows.NTStatus(r0)
	}
	return nil
}

func NtAssociateWaitCompletionPacket(handle windows.Handle, iocp windows.Handle, target windows.Handle, keyContext uintptr, apcContext uintptr, ioStatus uint32, ioStatusInformation uintptr, alreadySignaled *byte) error {
	r0, _, _ := syscall.SyscallN(procNtAssociateWaitCompletionPacket.Addr(), uintptr(handle), uintptr(iocp), uintptr(target), keyContext, apcContext, uintptr(ioStatus), ioStatusInformation, uintptr(unsafe.Pointer(alreadySignaled)))
	if r0 != 0 {
		return windows.NTStatus(r0)
	}
	return nil
}

func NtCancelWaitCompletionPacket(handle windows.Handle, removeSignaledPacket byte) error {
	r0, _, _ := syscall.SyscallN(procNtCancelWaitCompletionPacket.Addr(), uintptr(handle), uintptr(removeSignaledPacket))
	if r0 != 0 {
		return windows.NTStatus(r0)
	}
	return nil
}
