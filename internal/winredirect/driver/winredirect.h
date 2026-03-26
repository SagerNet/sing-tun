#pragma once

#include <initguid.h>
#include <ntddk.h>
#include <wdmsec.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <mstcpip.h>

// Device names
#define DEVICE_NAME     L"\\Device\\WinRedirect"
#define SYMLINK_NAME    L"\\DosDevices\\WinRedirect"

// IOCTL codes — must match Go types_windows.go
#define IOCTL_WINREDIRECT_SET_CONFIG  CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINREDIRECT_START       CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINREDIRECT_STOP        CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINREDIRECT_GET_PENDING CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINREDIRECT_SET_VERDICT CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Verdict values
#define VERDICT_REDIRECT 0
#define VERDICT_BYPASS   1
#define VERDICT_DROP     2

// Shared structures — must match Go types_windows.go layout

#pragma pack(push, 1)

typedef struct _WINREDIRECT_CONFIG {
    UINT16 RedirectPort;
    UINT8  _pad0[2];
    UINT32 ProxyPID;
} WINREDIRECT_CONFIG;

typedef struct _WINREDIRECT_PENDING_CONN {
    UINT64 ConnID;
    UINT8  AddressFamily;
    UINT8  _pad0[3];
    UINT8  SrcAddr[16];
    UINT16 SrcPort;
    UINT8  _pad1[2];
    UINT8  DstAddr[16];
    UINT16 DstPort;
    UINT8  _pad2[2];
    UINT32 ProcessID;
} WINREDIRECT_PENDING_CONN;

typedef struct _WINREDIRECT_VERDICT {
    UINT64 ConnID;
    UINT32 Verdict;
    UINT8  _pad0[4];
} WINREDIRECT_VERDICT;

#pragma pack(pop)

// Internal pending connection entry
typedef struct _PENDING_ENTRY {
    LIST_ENTRY  ListEntry;
    UINT64      ConnID;
    UINT64      ClassifyHandle;
    UINT64      FilterId;
    UINT8       AddressFamily;
    UINT8       SrcAddr[16];
    UINT16      SrcPort;
    UINT8       DstAddr[16];
    UINT16      DstPort;
    UINT32      ProcessID;
    LARGE_INTEGER Timestamp;
} PENDING_ENTRY, *PPENDING_ENTRY;

// Global driver context
typedef struct _DRIVER_CONTEXT {
    WDFDEVICE              Device;
    WDFQUEUE               PendingIoctlQueue;

    // WFP handles
    HANDLE                 EngineHandle;
    UINT32                 CalloutIdV4;
    UINT32                 CalloutIdV6;
    UINT64                 FilterIdV4;
    UINT64                 FilterIdV6;
    HANDLE                 RedirectHandle;

    // Configuration (protected by ConfigLock)
    FAST_MUTEX             ConfigLock;
    WINREDIRECT_CONFIG     Config;
    volatile LONG          Running;

    // Pending connections (protected by PendingLock)
    LIST_ENTRY             PendingList;
    FAST_MUTEX             PendingLock;
    volatile LONG64        NextConnID;

    // Timeout timer + work item
    WDFTIMER               TimeoutTimer;
    WDFWORKITEM            TimeoutWorkItem;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DRIVER_CONTEXT, GetDriverContext)

// Function declarations
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_CANCELED_ON_QUEUE EvtIoCanceledOnQueue;
EVT_WDF_TIMER EvtTimeoutTimer;
EVT_WDF_WORKITEM EvtTimeoutWorkItem;

// WFP functions
NTSTATUS WfpSetup(_In_ PDRIVER_CONTEXT Ctx);
void     WfpCleanup(_In_ PDRIVER_CONTEXT Ctx);

// Classify callbacks
void NTAPI ClassifyFnV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI ClassifyFnV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI NotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter
);

// Pending management
PPENDING_ENTRY PendingAllocate(_In_ PDRIVER_CONTEXT Ctx);
void           PendingInsert(_In_ PDRIVER_CONTEXT Ctx, _In_ PPENDING_ENTRY Entry);
PPENDING_ENTRY PendingFindByID(_In_ PDRIVER_CONTEXT Ctx, _In_ UINT64 ConnID);
void           PendingRemove(_In_ PDRIVER_CONTEXT Ctx, _In_ PPENDING_ENTRY Entry);
void           PendingFlushAll(_In_ PDRIVER_CONTEXT Ctx);

// Verdict execution
void ExecuteVerdict(_In_ PDRIVER_CONTEXT Ctx, _In_ PPENDING_ENTRY Entry, _In_ UINT32 Verdict);
