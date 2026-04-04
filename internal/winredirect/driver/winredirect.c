
#include "winredirect.h"

// {E513903C-D2F3-4D8C-9458-0483E7D7A01F}
DEFINE_GUID(WINREDIRECT_PROVIDER_KEY,
    0xe513903c, 0xd2f3, 0x4d8c, 0x94, 0x58, 0x04, 0x83, 0xe7, 0xd7, 0xa0, 0x1f);

// {8987A44E-ECB2-4A47-9FB6-B749C804FA3B}
DEFINE_GUID(WINREDIRECT_SUBLAYER_KEY,
    0x8987a44e, 0xecb2, 0x4a47, 0x9f, 0xb6, 0xb7, 0x49, 0xc8, 0x04, 0xfa, 0x3b);

// {7EA20C4E-1A93-427E-80DC-E18A60AAB73B}
DEFINE_GUID(WINREDIRECT_CALLOUT_V4_KEY,
    0x7ea20c4e, 0x1a93, 0x427e, 0x80, 0xdc, 0xe1, 0x8a, 0x60, 0xaa, 0xb7, 0x3b);

// {AABE8538-0A09-4D47-8E61-1127CE5BB1AB}
DEFINE_GUID(WINREDIRECT_CALLOUT_V6_KEY,
    0xaabe8538, 0x0a09, 0x4d47, 0x8e, 0x61, 0x11, 0x27, 0xce, 0x5b, 0xb1, 0xab);

static PDRIVER_CONTEXT g_Ctx = NULL;

#define PENDING_QUEUED_TIMEOUT_SECONDS 5
#define PENDING_DELIVERED_TIMEOUT_SECONDS 15

static void PermitClassify(_Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static void BlockClassify(_Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static NTSTATUS ReadFatalStatus(_In_ PDRIVER_CONTEXT Ctx)
{
    return (NTSTATUS)InterlockedCompareExchange(&Ctx->FatalStatus, STATUS_SUCCESS, STATUS_SUCCESS);
}

static NTSTATUS NormalizeFatalStatus(_In_ NTSTATUS Status)
{
    if (NT_SUCCESS(Status)) {
        return STATUS_DRIVER_INTERNAL_ERROR;
    }
    return Status;
}

static NTSTATUS TriggerFatal(_In_ PDRIVER_CONTEXT Ctx, _In_ NTSTATUS Status, _In_ const char* Message)
{
    NTSTATUS normalized = NormalizeFatalStatus(Status);
    NTSTATUS previous = (NTSTATUS)InterlockedCompareExchange(&Ctx->FatalStatus, normalized, STATUS_SUCCESS);

    if (previous == STATUS_SUCCESS) {
        RtlStringCbCopyA(Ctx->FatalMessage, sizeof(Ctx->FatalMessage), Message);
        WdfWorkItemEnqueue(Ctx->FatalWorkItem);
        return normalized;
    }

    return previous;
}

static void TriggerFatalAndPermitClassify(
    _In_ PDRIVER_CONTEXT Ctx,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut,
    _In_ NTSTATUS Status,
    _In_ const char* Message)
{
    if (Ctx) {
        TriggerFatal(Ctx, Status, Message);
    }
    PermitClassify(classifyOut);
}

static BOOLEAN IsLoopbackAddress(_In_ UINT8 AddressFamily, _In_reads_(16) const UINT8* Address)
{
    if (AddressFamily == AF_INET) {
        return Address[0] == 127;
    }

    if (AddressFamily == AF_INET6) {
        for (UINT32 i = 0; i < 15; i++) {
            if (Address[i] != 0) {
                return FALSE;
            }
        }
        return Address[15] == 1;
    }

    return FALSE;
}

static BOOLEAN IsAnyAddress(_In_ UINT8 AddressFamily, _In_reads_(16) const UINT8* Address)
{
    if (AddressFamily == AF_INET) {
        return Address[0] == 0 && Address[1] == 0 && Address[2] == 0 && Address[3] == 0;
    }

    if (AddressFamily == AF_INET6) {
        for (UINT32 i = 0; i < 16; i++) {
            if (Address[i] != 0) {
                return FALSE;
            }
        }
        return TRUE;
    }

    return FALSE;
}

typedef enum _BEST_ROUTE_RESULT {
    BestRouteTun = 1,
    BestRouteOther = 2,
} BEST_ROUTE_RESULT;

static CONFIG_SNAPSHOT ReadConfigSnapshot(_In_ PDRIVER_CONTEXT Ctx)
{
    CONFIG_SNAPSHOT snapshot;
    KIRQL oldIrql;

    RtlZeroMemory(&snapshot, sizeof(snapshot));
    KeAcquireSpinLock(&Ctx->ConfigLock, &oldIrql);
    snapshot.Config = Ctx->Config;
    snapshot.TunLuid = Ctx->TunLuid;
    snapshot.HasTunLuid = Ctx->HasTunLuid;
    KeReleaseSpinLock(&Ctx->ConfigLock, oldIrql);

    return snapshot;
}

static BOOLEAN TryBestRouteForEntry(
    _In_ const CONFIG_SNAPSHOT* Snapshot,
    _In_ const PENDING_ENTRY* Entry,
    _Out_ BEST_ROUTE_RESULT* Result)
{
    SOCKADDR_INET sourceAddress;
    SOCKADDR_INET destinationAddress;
    SOCKADDR_INET bestSourceAddress;
    SOCKADDR_INET* sourceAddressPtr = NULL;
    MIB_IPFORWARD_ROW2 bestRoute;
    NETIO_STATUS status;

    if (!Snapshot->HasTunLuid) {
        return FALSE;
    }
    // GetBestRoute2 requires IRQL < DISPATCH_LEVEL. We do not currently
    // characterize every runtime context where route lookup can be unavailable,
    // so report a normal lookup failure and let the caller decide the fallback.
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
        return FALSE;
    }

    RtlZeroMemory(&sourceAddress, sizeof(sourceAddress));
    RtlZeroMemory(&destinationAddress, sizeof(destinationAddress));
    RtlZeroMemory(&bestSourceAddress, sizeof(bestSourceAddress));
    RtlZeroMemory(&bestRoute, sizeof(bestRoute));

    if (Entry->AddressFamily == AF_INET) {
        destinationAddress.Ipv4.sin_family = AF_INET;
        RtlCopyMemory(&destinationAddress.Ipv4.sin_addr, Entry->DstAddr, sizeof(destinationAddress.Ipv4.sin_addr));
        if (!IsAnyAddress(AF_INET, Entry->SrcAddr)) {
            sourceAddress.Ipv4.sin_family = AF_INET;
            RtlCopyMemory(&sourceAddress.Ipv4.sin_addr, Entry->SrcAddr, sizeof(sourceAddress.Ipv4.sin_addr));
            sourceAddressPtr = &sourceAddress;
        }
    } else if (Entry->AddressFamily == AF_INET6) {
        destinationAddress.Ipv6.sin6_family = AF_INET6;
        RtlCopyMemory(destinationAddress.Ipv6.sin6_addr.u.Byte, Entry->DstAddr, sizeof(destinationAddress.Ipv6.sin6_addr.u.Byte));
        if (!IsAnyAddress(AF_INET6, Entry->SrcAddr)) {
            sourceAddress.Ipv6.sin6_family = AF_INET6;
            RtlCopyMemory(sourceAddress.Ipv6.sin6_addr.u.Byte, Entry->SrcAddr, sizeof(sourceAddress.Ipv6.sin6_addr.u.Byte));
            sourceAddressPtr = &sourceAddress;
        }
    } else {
        return FALSE;
    }

    status = GetBestRoute2(NULL, 0, sourceAddressPtr, &destinationAddress, 0, &bestRoute, &bestSourceAddress);
    if (status != 0) {
        return FALSE;
    }
    if (bestRoute.InterfaceLuid.Value == Snapshot->TunLuid.Value) {
        *Result = BestRouteTun;
        return TRUE;
    }
    *Result = BestRouteOther;
    return TRUE;
}

static void CancelPendingIoctlRequests(_In_ PDRIVER_CONTEXT Ctx, _In_ NTSTATUS Status)
{
    WDFREQUEST request;

    while (NT_SUCCESS(WdfIoQueueRetrieveNextRequest(Ctx->PendingIoctlQueue, &request))) {
        WdfRequestComplete(request, Status);
    }
}

static void ShutdownRedirect(_In_ PDRIVER_CONTEXT Ctx, _In_ UINT32 PendingVerdict, _In_ NTSTATUS RequestStatus)
{
    if (InterlockedCompareExchange(&Ctx->Running, FALSE, TRUE) == TRUE) {
        WdfTimerStop(Ctx->TimeoutTimer, TRUE);
        WdfWorkItemFlush(Ctx->TimeoutWorkItem);
        WfpCleanup(Ctx);
        WdfWorkItemFlush(Ctx->PendingDeliveryWorkItem);
    }

    PendingFlushAll(Ctx, PendingVerdict);
    CancelPendingIoctlRequests(Ctx, RequestStatus);
}

static PPENDING_ENTRY PendingReserveNextQueued(_In_ PDRIVER_CONTEXT Ctx)
{
    PPENDING_ENTRY found = NULL;
    KIRQL oldIrql;

    KeAcquireSpinLock(&Ctx->PendingLock, &oldIrql);
    PLIST_ENTRY entry = Ctx->PendingList.Flink;
    while (entry != &Ctx->PendingList) {
        PPENDING_ENTRY pending = CONTAINING_RECORD(entry, PENDING_ENTRY, ListEntry);
        if (pending->DeliveryState == PendingDeliveryQueued) {
            pending->DeliveryState = PendingDeliveryCopying;
            found = pending;
            break;
        }
        entry = entry->Flink;
    }
    KeReleaseSpinLock(&Ctx->PendingLock, oldIrql);

    return found;
}

static void PendingSetDeliveryState(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ PPENDING_ENTRY Entry,
    _In_ LONG State,
    _In_opt_ const LARGE_INTEGER* Timestamp)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&Ctx->PendingLock, &oldIrql);
    Entry->DeliveryState = State;
    if (Timestamp) {
        Entry->Timestamp = *Timestamp;
    }
    KeReleaseSpinLock(&Ctx->PendingLock, oldIrql);
}

static void TryCompletePendingRequests(_In_ PDRIVER_CONTEXT Ctx)
{
    if (ReadFatalStatus(Ctx) != STATUS_SUCCESS) {
        return;
    }

    for (;;) {
        PPENDING_ENTRY pending = PendingReserveNextQueued(Ctx);
        if (!pending) {
            break;
        }

        WDFREQUEST request;
        NTSTATUS status = WdfIoQueueRetrieveNextRequest(Ctx->PendingIoctlQueue, &request);
        if (!NT_SUCCESS(status)) {
            PendingSetDeliveryState(Ctx, pending, PendingDeliveryQueued, NULL);
            break;
        }

        PVOID outBuf;
        status = WdfRequestRetrieveOutputBuffer(request, sizeof(WINREDIRECT_PENDING_CONN), &outBuf, NULL);
        if (!NT_SUCCESS(status)) {
            PendingSetDeliveryState(Ctx, pending, PendingDeliveryQueued, NULL);
            WdfRequestComplete(request, status);
            continue;
        }

        WINREDIRECT_PENDING_CONN* out = (WINREDIRECT_PENDING_CONN*)outBuf;
        RtlZeroMemory(out, sizeof(*out));
        out->ConnID = pending->ConnID;
        out->AddressFamily = pending->AddressFamily;
        RtlCopyMemory(out->SrcAddr, pending->SrcAddr, 16);
        out->SrcPort = pending->SrcPort;
        RtlCopyMemory(out->DstAddr, pending->DstAddr, 16);
        out->DstPort = pending->DstPort;
        out->ProcessID = pending->ProcessID;
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);
        PendingSetDeliveryState(Ctx, pending, PendingDeliveryDelivered, &now);
        WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, sizeof(WINREDIRECT_PENDING_CONN));
    }
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG driverConfig;
    WDF_OBJECT_ATTRIBUTES driverAttrs;
    WDFDRIVER driver;
    WDFDEVICE device;
    PWDFDEVICE_INIT deviceInit;
    WDF_OBJECT_ATTRIBUTES deviceAttrs;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symlinkName = RTL_CONSTANT_STRING(SYMLINK_NAME);
    PDRIVER_CONTEXT ctx;

    WDF_DRIVER_CONFIG_INIT(&driverConfig, WDF_NO_EVENT_CALLBACK);
    driverConfig.DriverInitFlags = WdfDriverInitNonPnpDriver;
    driverConfig.EvtDriverUnload = EvtDriverUnload;

    WDF_OBJECT_ATTRIBUTES_INIT(&driverAttrs);
    status = WdfDriverCreate(DriverObject, RegistryPath, &driverAttrs, &driverConfig, &driver);
    if (!NT_SUCCESS(status)) return status;

    deviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (!deviceInit) return STATUS_INSUFFICIENT_RESOURCES;

    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) { WdfDeviceInitFree(deviceInit); return status; }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttrs, DRIVER_CONTEXT);
    deviceAttrs.ExecutionLevel = WdfExecutionLevelPassive;
    status = WdfDeviceCreate(&deviceInit, &deviceAttrs, &device);
    if (!NT_SUCCESS(status)) return status;

    status = WdfDeviceCreateSymbolicLink(device, &symlinkName);
    if (!NT_SUCCESS(status)) return status;

    ctx = GetDriverContext(device);
    RtlZeroMemory(ctx, sizeof(DRIVER_CONTEXT));
    ctx->Device = device;
    InitializeListHead(&ctx->PendingList);
    KeInitializeSpinLock(&ctx->PendingLock);
    KeInitializeSpinLock(&ctx->ConfigLock);
    g_Ctx = ctx;

    // Create manual-dispatch queue for pending IOCTLs
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    queueConfig.EvtIoCanceledOnQueue = EvtIoCanceledOnQueue;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &ctx->PendingIoctlQueue);
    if (!NT_SUCCESS(status)) return status;

    // Create default queue for all other IOCTLs
    WDF_IO_QUEUE_CONFIG defaultQueueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&defaultQueueConfig, WdfIoQueueDispatchParallel);
    defaultQueueConfig.EvtIoDeviceControl = EvtIoDeviceControl;
    status = WdfIoQueueCreate(device, &defaultQueueConfig, WDF_NO_OBJECT_ATTRIBUTES, NULL);
    if (!NT_SUCCESS(status)) return status;

    // Create timeout timer (sweeps stale pending entries every 5 seconds)
    WDF_TIMER_CONFIG timerConfig;
    WDF_TIMER_CONFIG_INIT_PERIODIC(&timerConfig, EvtTimeoutTimer, 5000);
    WDF_OBJECT_ATTRIBUTES timerAttrs;
    WDF_OBJECT_ATTRIBUTES_INIT(&timerAttrs);
    timerAttrs.ParentObject = device;
    status = WdfTimerCreate(&timerConfig, &timerAttrs, &ctx->TimeoutTimer);
    if (!NT_SUCCESS(status)) return status;

    // Create work item for timeout processing at PASSIVE_LEVEL
    WDF_WORKITEM_CONFIG workItemConfig;
    WDF_WORKITEM_CONFIG_INIT(&workItemConfig, EvtTimeoutWorkItem);
    WDF_OBJECT_ATTRIBUTES workItemAttrs;
    WDF_OBJECT_ATTRIBUTES_INIT(&workItemAttrs);
    workItemAttrs.ParentObject = device;
    status = WdfWorkItemCreate(&workItemConfig, &workItemAttrs, &ctx->TimeoutWorkItem);
    if (!NT_SUCCESS(status)) return status;

    WDF_WORKITEM_CONFIG pendingDeliveryConfig;
    WDF_WORKITEM_CONFIG_INIT(&pendingDeliveryConfig, EvtPendingDeliveryWorkItem);
    WDF_OBJECT_ATTRIBUTES pendingDeliveryAttrs;
    WDF_OBJECT_ATTRIBUTES_INIT(&pendingDeliveryAttrs);
    pendingDeliveryAttrs.ParentObject = device;
    status = WdfWorkItemCreate(&pendingDeliveryConfig, &pendingDeliveryAttrs, &ctx->PendingDeliveryWorkItem);
    if (!NT_SUCCESS(status)) return status;

    WDF_WORKITEM_CONFIG fatalConfig;
    WDF_WORKITEM_CONFIG_INIT(&fatalConfig, EvtFatalWorkItem);
    WDF_OBJECT_ATTRIBUTES fatalAttrs;
    WDF_OBJECT_ATTRIBUTES_INIT(&fatalAttrs);
    fatalAttrs.ParentObject = device;
    status = WdfWorkItemCreate(&fatalConfig, &fatalAttrs, &ctx->FatalWorkItem);
    if (!NT_SUCCESS(status)) return status;

    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}

void EvtDriverUnload(_In_ WDFDRIVER Driver)
{
    NTSTATUS fatalStatus;

    UNREFERENCED_PARAMETER(Driver);
    if (g_Ctx) {
        WdfWorkItemFlush(g_Ctx->FatalWorkItem);
        fatalStatus = ReadFatalStatus(g_Ctx);
        ShutdownRedirect(
            g_Ctx,
            VERDICT_PERMIT,
            fatalStatus != STATUS_SUCCESS ? fatalStatus : STATUS_CANCELLED);
    }
}

void EvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    PDRIVER_CONTEXT ctx = g_Ctx;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS fatalStatus = STATUS_SUCCESS;
    PVOID inBuf = NULL;
    size_t inLen = 0;

    if (!ctx) {
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_STATE);
        return;
    }

    fatalStatus = ReadFatalStatus(ctx);

    switch (IoControlCode) {
    case IOCTL_WINREDIRECT_SET_CONFIG:
        if (fatalStatus != STATUS_SUCCESS) {
            WdfRequestComplete(Request, fatalStatus);
            break;
        }
        if (ctx->Running) {
            WdfRequestComplete(Request, STATUS_DEVICE_BUSY);
            break;
        }
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(WINREDIRECT_CONFIG), &inBuf, &inLen);
        if (NT_SUCCESS(status)) {
            WINREDIRECT_CONFIG* config = (WINREDIRECT_CONFIG*)inBuf;
            NET_LUID tunLuid = {0};
            const GUID nullGuid = {0};
            KIRQL oldIrql;
            if (config->RedirectPort == 0 || config->ProxyPID == 0 || InlineIsEqualGUID(&nullGuid, &config->TunGuid)) {
                status = STATUS_INVALID_PARAMETER;
            } else {
                status = ConvertInterfaceGuidToLuid(&config->TunGuid, &tunLuid);
            }
            if (NT_SUCCESS(status)) {
                KeAcquireSpinLock(&ctx->ConfigLock, &oldIrql);
                RtlCopyMemory(&ctx->Config, config, sizeof(WINREDIRECT_CONFIG));
                ctx->TunLuid = tunLuid;
                ctx->HasTunLuid = TRUE;
                KeReleaseSpinLock(&ctx->ConfigLock, oldIrql);
            }
        }
        WdfRequestComplete(Request, status);
        break;

    case IOCTL_WINREDIRECT_START: {
        CONFIG_SNAPSHOT snapshot;
        if (fatalStatus != STATUS_SUCCESS) {
            WdfRequestComplete(Request, fatalStatus);
            break;
        }
        if (InterlockedCompareExchange(&ctx->Running, TRUE, FALSE) != FALSE) {
            WdfRequestComplete(Request, STATUS_ALREADY_REGISTERED);
            break;
        }
        snapshot = ReadConfigSnapshot(ctx);
        if (!snapshot.HasTunLuid || snapshot.Config.RedirectPort == 0 || snapshot.Config.ProxyPID == 0) {
            InterlockedExchange(&ctx->Running, FALSE);
            WdfRequestComplete(Request, STATUS_INVALID_DEVICE_STATE);
            break;
        }
        status = WfpSetup(ctx);
        if (NT_SUCCESS(status)) {
            WdfTimerStart(ctx->TimeoutTimer, WDF_REL_TIMEOUT_IN_SEC(5));
        } else {
            InterlockedExchange(&ctx->Running, FALSE);
        }
        WdfRequestComplete(Request, status);
        break;
    }

    case IOCTL_WINREDIRECT_STOP:
        if (fatalStatus != STATUS_SUCCESS) {
            ShutdownRedirect(ctx, VERDICT_PERMIT, fatalStatus);
        } else {
            ShutdownRedirect(ctx, VERDICT_PERMIT, STATUS_CANCELLED);
        }
        WdfRequestComplete(Request, STATUS_SUCCESS);
        break;

    case IOCTL_WINREDIRECT_GET_PENDING:
        if (fatalStatus != STATUS_SUCCESS) {
            WdfRequestComplete(Request, fatalStatus);
            break;
        }
        if (!ctx->Running) {
            WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
            break;
        }
        // Forward to manual queue - will be completed when a connection arrives
        status = WdfRequestForwardToIoQueue(Request, ctx->PendingIoctlQueue);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
        } else {
            WdfWorkItemEnqueue(ctx->PendingDeliveryWorkItem);
        }
        break;

    case IOCTL_WINREDIRECT_SET_VERDICT: {
        if (fatalStatus != STATUS_SUCCESS) {
            WdfRequestComplete(Request, fatalStatus);
            break;
        }
        if (!ctx->Running) {
            WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
            break;
        }
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(WINREDIRECT_VERDICT), &inBuf, &inLen);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            break;
        }
        WINREDIRECT_VERDICT* v = (WINREDIRECT_VERDICT*)inBuf;
        if (v->Verdict != VERDICT_REDIRECT && v->Verdict != VERDICT_PERMIT) {
            WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
            break;
        }
        PPENDING_ENTRY entry = PendingFindByID(ctx, v->ConnID);
        if (entry) {
            ExecuteVerdict(ctx, entry, v->Verdict);
            ExFreePoolWithTag(entry, 'rniW');
        }
        WdfRequestComplete(Request, entry ? STATUS_SUCCESS : STATUS_NOT_FOUND);
        break;
    }

    case IOCTL_WINREDIRECT_GET_FATAL_INFO: {
        PVOID outBuf;
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(WINREDIRECT_FATAL_INFO), &outBuf, NULL);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            break;
        }
        WINREDIRECT_FATAL_INFO* info = (WINREDIRECT_FATAL_INFO*)outBuf;
        info->Status = (UINT32)ReadFatalStatus(ctx);
        RtlStringCbCopyA(info->Message, sizeof(info->Message), ctx->FatalMessage);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(WINREDIRECT_FATAL_INFO));
        break;
    }

    default:
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        break;
    }
}

void EvtIoCanceledOnQueue(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request)
{
    UNREFERENCED_PARAMETER(Queue);
    WdfRequestComplete(Request, STATUS_CANCELLED);
}

void EvtTimeoutTimer(_In_ WDFTIMER Timer)
{
    UNREFERENCED_PARAMETER(Timer);
    if (!g_Ctx) return;
    WdfWorkItemEnqueue(g_Ctx->TimeoutWorkItem);
}

void EvtTimeoutWorkItem(_In_ WDFWORKITEM WorkItem)
{
    UNREFERENCED_PARAMETER(WorkItem);
    if (!g_Ctx) return;
    if (ReadFatalStatus(g_Ctx) != STATUS_SUCCESS) return;

    for (;;) {
        LARGE_INTEGER now;
        PPENDING_ENTRY expired = NULL;
        KIRQL oldIrql;

        KeQuerySystemTime(&now);
        KeAcquireSpinLock(&g_Ctx->PendingLock, &oldIrql);

        PLIST_ENTRY entry = g_Ctx->PendingList.Flink;
        while (entry != &g_Ctx->PendingList) {
            PPENDING_ENTRY pending = CONTAINING_RECORD(entry, PENDING_ENTRY, ListEntry);
            LONGLONG timeoutSeconds = 0;
            entry = entry->Flink;

            if (pending->DeliveryState == PendingDeliveryQueued) {
                timeoutSeconds = PENDING_QUEUED_TIMEOUT_SECONDS;
            } else if (pending->DeliveryState == PendingDeliveryDelivered) {
                timeoutSeconds = PENDING_DELIVERED_TIMEOUT_SECONDS;
            } else {
                continue;
            }

            LONGLONG elapsed = (now.QuadPart - pending->Timestamp.QuadPart) / 10000000LL;
            if (elapsed >= timeoutSeconds) {
                RemoveEntryList(&pending->ListEntry);
                expired = pending;
                break;
            }
        }

        KeReleaseSpinLock(&g_Ctx->PendingLock, oldIrql);

        if (!expired) {
            break;
        }

        ExecuteVerdict(g_Ctx, expired, VERDICT_PERMIT);
        ExFreePoolWithTag(expired, 'rniW');
    }
}

void EvtPendingDeliveryWorkItem(_In_ WDFWORKITEM WorkItem)
{
    UNREFERENCED_PARAMETER(WorkItem);
    if (!g_Ctx || !g_Ctx->Running || ReadFatalStatus(g_Ctx) != STATUS_SUCCESS) return;
    TryCompletePendingRequests(g_Ctx);
}

void EvtFatalWorkItem(_In_ WDFWORKITEM WorkItem)
{
    NTSTATUS fatalStatus;

    UNREFERENCED_PARAMETER(WorkItem);
    if (!g_Ctx) return;

    fatalStatus = ReadFatalStatus(g_Ctx);
    if (fatalStatus == STATUS_SUCCESS) {
        return;
    }

    ShutdownRedirect(g_Ctx, VERDICT_PERMIT, fatalStatus);
}

// --- WFP Setup ---

NTSTATUS WfpSetup(_In_ PDRIVER_CONTEXT Ctx)
{
    NTSTATUS status;
    FWPM_SESSION0 session = { .flags = FWPM_SESSION_FLAG_DYNAMIC };

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &Ctx->EngineHandle);
    if (!NT_SUCCESS(status)) return status;

    FWPM_SUBLAYER0 subLayer = {
        .subLayerKey = WINREDIRECT_SUBLAYER_KEY,
        .displayData = { .name = L"WinRedirect SubLayer" },
        .weight = MAXUINT16,
    };
    status = FwpmSubLayerAdd0(Ctx->EngineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status)) goto cleanup;

    // Create redirect handle
    status = FwpsRedirectHandleCreate0(&WINREDIRECT_PROVIDER_KEY, 0, &Ctx->RedirectHandle);
    if (!NT_SUCCESS(status)) goto cleanup;

    // Register callouts
    FWPS_CALLOUT1 sCalloutV4 = {
        .calloutKey = WINREDIRECT_CALLOUT_V4_KEY,
        .classifyFn = ClassifyFnV4,
        .notifyFn = NotifyFn,
    };
    status = FwpsCalloutRegister1(WdfDeviceWdmGetDeviceObject(Ctx->Device), &sCalloutV4, &Ctx->CalloutIdV4);
    if (!NT_SUCCESS(status)) goto cleanup;

    FWPS_CALLOUT1 sCalloutV6 = {
        .calloutKey = WINREDIRECT_CALLOUT_V6_KEY,
        .classifyFn = ClassifyFnV6,
        .notifyFn = NotifyFn,
    };
    status = FwpsCalloutRegister1(WdfDeviceWdmGetDeviceObject(Ctx->Device), &sCalloutV6, &Ctx->CalloutIdV6);
    if (!NT_SUCCESS(status)) goto cleanup;

    // Add callouts to BFE
    FWPM_CALLOUT0 mCalloutV4 = {
        .calloutKey = WINREDIRECT_CALLOUT_V4_KEY,
        .displayData = { .name = L"WinRedirect V4 Callout" },
        .applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
    };
    status = FwpmCalloutAdd0(Ctx->EngineHandle, &mCalloutV4, NULL, NULL);
    if (!NT_SUCCESS(status)) goto cleanup;

    FWPM_CALLOUT0 mCalloutV6 = {
        .calloutKey = WINREDIRECT_CALLOUT_V6_KEY,
        .displayData = { .name = L"WinRedirect V6 Callout" },
        .applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
    };
    status = FwpmCalloutAdd0(Ctx->EngineHandle, &mCalloutV6, NULL, NULL);
    if (!NT_SUCCESS(status)) goto cleanup;

    // Add filters - condition: TCP only
    FWPM_FILTER_CONDITION0 tcpCondition = {
        .fieldKey = FWPM_CONDITION_IP_PROTOCOL,
        .matchType = FWP_MATCH_EQUAL,
        .conditionValue = { .type = FWP_UINT8, .uint8 = IPPROTO_TCP },
    };

    FWPM_FILTER0 filterV4 = {
        .displayData = { .name = L"WinRedirect V4 Filter" },
        .layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        .subLayerKey = WINREDIRECT_SUBLAYER_KEY,
        .action = { .type = FWP_ACTION_CALLOUT_TERMINATING, .calloutKey = WINREDIRECT_CALLOUT_V4_KEY },
        .weight = { .type = FWP_UINT8, .uint8 = 15 },
        .numFilterConditions = 1,
        .filterCondition = &tcpCondition,
    };
    status = FwpmFilterAdd0(Ctx->EngineHandle, &filterV4, NULL, &Ctx->FilterIdV4);
    if (!NT_SUCCESS(status)) goto cleanup;

    FWPM_FILTER0 filterV6 = {
        .displayData = { .name = L"WinRedirect V6 Filter" },
        .layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        .subLayerKey = WINREDIRECT_SUBLAYER_KEY,
        .action = { .type = FWP_ACTION_CALLOUT_TERMINATING, .calloutKey = WINREDIRECT_CALLOUT_V6_KEY },
        .weight = { .type = FWP_UINT8, .uint8 = 15 },
        .numFilterConditions = 1,
        .filterCondition = &tcpCondition,
    };
    status = FwpmFilterAdd0(Ctx->EngineHandle, &filterV6, NULL, &Ctx->FilterIdV6);
    if (!NT_SUCCESS(status)) goto cleanup;

    return STATUS_SUCCESS;

cleanup:
    WfpCleanup(Ctx);
    return status;
}

void WfpCleanup(_In_ PDRIVER_CONTEXT Ctx)
{
    if (Ctx->CalloutIdV4) {
        FwpsCalloutUnregisterById0(Ctx->CalloutIdV4);
        Ctx->CalloutIdV4 = 0;
    }
    if (Ctx->CalloutIdV6) {
        FwpsCalloutUnregisterById0(Ctx->CalloutIdV6);
        Ctx->CalloutIdV6 = 0;
    }
    if (Ctx->RedirectHandle) {
        FwpsRedirectHandleDestroy0(Ctx->RedirectHandle);
        Ctx->RedirectHandle = NULL;
    }
    if (Ctx->EngineHandle) {
        FwpmEngineClose0(Ctx->EngineHandle);
        Ctx->EngineHandle = NULL;
    }
}

NTSTATUS NTAPI NotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

// --- Classify callbacks ---

static void ClassifyFnCommon(
    _In_ UINT8 addressFamily,
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut,
    _In_ UINT32 localAddrIdx,
    _In_ UINT32 localPortIdx,
    _In_ UINT32 remoteAddrIdx,
    _In_ UINT32 remotePortIdx)
{
    PDRIVER_CONTEXT ctx = g_Ctx;
    NTSTATUS fatalStatus;
    NTSTATUS status;
    CONFIG_SNAPSHOT snapshot;
    PPENDING_ENTRY entry;
    BEST_ROUTE_RESULT bestRoute;
    UINT64 classifyHandle;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);

    if (!ctx || !ctx->Running) {
        PermitClassify(classifyOut);
        return;
    }

    fatalStatus = ReadFatalStatus(ctx);
    if (fatalStatus != STATUS_SUCCESS) {
        PermitClassify(classifyOut);
        return;
    }

    // Must have write rights to modify the classify decision
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        return;
    }

    snapshot = ReadConfigSnapshot(ctx);

#if (NTDDI_VERSION >= NTDDI_WIN8)
    if (ctx->RedirectHandle &&
        FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)) {
        FWPS_CONNECTION_REDIRECT_STATE redirectState =
            FwpsQueryConnectionRedirectState0(inMetaValues->redirectRecords, ctx->RedirectHandle, NULL);
        switch (redirectState) {
        case FWPS_CONNECTION_REDIRECTED_BY_SELF:
        case FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF:
            PermitClassify(classifyOut);
            return;
        case FWPS_CONNECTION_NOT_REDIRECTED:
        case FWPS_CONNECTION_REDIRECTED_BY_OTHER:
        default:
            break;
        }
    }
#endif

    if (snapshot.Config.ProxyPID != 0 &&
        FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID) &&
        (UINT32)inMetaValues->processId == snapshot.Config.ProxyPID) {
        PermitClassify(classifyOut);
        return;
    }

    // Allocate pending entry
    entry = (PPENDING_ENTRY)ExAllocatePoolZero(NonPagedPoolNx, sizeof(PENDING_ENTRY), 'rniW');
    if (!entry) {
        TriggerFatalAndPermitClassify(ctx, classifyOut, STATUS_INSUFFICIENT_RESOURCES, "allocate pending entry");
        return;
    }
    entry->ConnID = InterlockedIncrement64(&ctx->NextConnID);
    entry->AddressFamily = addressFamily;
    entry->FilterId = filter->filterId;

    // Extract addresses with NULL checks for IPv6 pointers
    if (addressFamily == AF_INET) {
        UINT32 srcIp = inFixedValues->incomingValue[localAddrIdx].value.uint32;
        UINT32 dstIp = inFixedValues->incomingValue[remoteAddrIdx].value.uint32;
        // WFP stores IPv4 in host byte order
        *(UINT32*)entry->SrcAddr = RtlUlongByteSwap(srcIp);
        *(UINT32*)entry->DstAddr = RtlUlongByteSwap(dstIp);
    } else {
        FWP_BYTE_ARRAY16* srcArr = inFixedValues->incomingValue[localAddrIdx].value.byteArray16;
        FWP_BYTE_ARRAY16* dstArr = inFixedValues->incomingValue[remoteAddrIdx].value.byteArray16;
        if (srcArr) {
            RtlCopyMemory(entry->SrcAddr, srcArr->byteArray16, 16);
        }
        if (dstArr) {
            RtlCopyMemory(entry->DstAddr, dstArr->byteArray16, 16);
        } else {
            ExFreePoolWithTag(entry, 'rniW');
            TriggerFatalAndPermitClassify(ctx, classifyOut, STATUS_INVALID_ADDRESS_COMPONENT, "ipv6 null destination");
            return;
        }
    }
    entry->SrcPort = inFixedValues->incomingValue[localPortIdx].value.uint16;
    entry->DstPort = inFixedValues->incomingValue[remotePortIdx].value.uint16;

    if (IsLoopbackAddress(addressFamily, entry->DstAddr)) {
        ExFreePoolWithTag(entry, 'rniW');
        PermitClassify(classifyOut);
        return;
    }

    if (!TryBestRouteForEntry(&snapshot, entry, &bestRoute) || bestRoute == BestRouteOther) {
        ExFreePoolWithTag(entry, 'rniW');
        PermitClassify(classifyOut);
        return;
    }
    // Windows auto-redirect is best-effort: only redirect connections that are
    // positively identified as already routed to the TUN. If route lookup says
    // "not TUN" or fails for a context we do not currently characterize, leave
    // the original connect alone instead of redirecting unknown traffic.

    // Extract PID from metadata
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        entry->ProcessID = (UINT32)inMetaValues->processId;
    }

    if (!classifyContext) {
        ExFreePoolWithTag(entry, 'rniW');
        TriggerFatalAndPermitClassify(ctx, classifyOut, STATUS_INVALID_DEVICE_STATE, "no classify context");
        return;
    }

    // Pend the classify
    status = FwpsAcquireClassifyHandle0((void*)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(entry, 'rniW');
        TriggerFatalAndPermitClassify(ctx, classifyOut, status, "acquire classify handle");
        return;
    }

    entry->ClassifyHandle = classifyHandle;
    entry->ClassifyOut = *classifyOut;

    status = FwpsAcquireWritableLayerDataPointer0(
        classifyHandle, filter->filterId, 0,
        &entry->WritableLayerData, classifyOut);
    if (!NT_SUCCESS(status) || !entry->WritableLayerData) {
        FwpsReleaseClassifyHandle0(classifyHandle);
        ExFreePoolWithTag(entry, 'rniW');
        TriggerFatalAndPermitClassify(ctx, classifyOut, !NT_SUCCESS(status) ? status : STATUS_INVALID_DEVICE_STATE, "acquire writable layer data");
        return;
    }

    status = FwpsPendClassify0(classifyHandle, filter->filterId, 0, classifyOut);
    if (!NT_SUCCESS(status)) {
        FwpsApplyModifiedLayerData0(
            classifyHandle,
            entry->WritableLayerData,
            FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS);
        FwpsReleaseClassifyHandle0(classifyHandle);
        ExFreePoolWithTag(entry, 'rniW');
        TriggerFatalAndPermitClassify(ctx, classifyOut, status, "pend classify");
        return;
    }

    BlockClassify(classifyOut);

    KeQuerySystemTime(&entry->Timestamp);
    entry->DeliveryState = PendingDeliveryQueued;
    PendingInsert(ctx, entry);
    WdfWorkItemEnqueue(ctx->PendingDeliveryWorkItem);
}

void NTAPI ClassifyFnV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    ClassifyFnCommon(AF_INET, inFixedValues, inMetaValues, layerData,
        classifyContext, filter, flowContext, classifyOut,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT);
}

void NTAPI ClassifyFnV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    ClassifyFnCommon(AF_INET6, inFixedValues, inMetaValues, layerData,
        classifyContext, filter, flowContext, classifyOut,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_PORT,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS,
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT);
}

// --- Pending connection management ---

void PendingInsert(_In_ PDRIVER_CONTEXT Ctx, _In_ PPENDING_ENTRY Entry)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&Ctx->PendingLock, &oldIrql);
    InsertTailList(&Ctx->PendingList, &Entry->ListEntry);
    KeReleaseSpinLock(&Ctx->PendingLock, oldIrql);
}

PPENDING_ENTRY PendingFindByID(_In_ PDRIVER_CONTEXT Ctx, _In_ UINT64 ConnID)
{
    PPENDING_ENTRY found = NULL;
    KIRQL oldIrql;
    KeAcquireSpinLock(&Ctx->PendingLock, &oldIrql);
    PLIST_ENTRY entry = Ctx->PendingList.Flink;
    while (entry != &Ctx->PendingList) {
        PPENDING_ENTRY pending = CONTAINING_RECORD(entry, PENDING_ENTRY, ListEntry);
        if (pending->ConnID == ConnID) {
            RemoveEntryList(entry);
            found = pending;
            break;
        }
        entry = entry->Flink;
    }
    KeReleaseSpinLock(&Ctx->PendingLock, oldIrql);
    return found;
}

void PendingFlushAll(_In_ PDRIVER_CONTEXT Ctx, _In_ UINT32 Verdict)
{
    for (;;) {
        KIRQL oldIrql;
        PPENDING_ENTRY pending = NULL;

        KeAcquireSpinLock(&Ctx->PendingLock, &oldIrql);
        if (!IsListEmpty(&Ctx->PendingList)) {
            PLIST_ENTRY entry = RemoveHeadList(&Ctx->PendingList);
            pending = CONTAINING_RECORD(entry, PENDING_ENTRY, ListEntry);
        }
        KeReleaseSpinLock(&Ctx->PendingLock, oldIrql);

        if (!pending) {
            break;
        }

        ExecuteVerdict(Ctx, pending, Verdict);
        ExFreePoolWithTag(pending, 'rniW');
    }
}

// --- Verdict execution ---

void ExecuteVerdict(_In_ PDRIVER_CONTEXT Ctx, _In_ PPENDING_ENTRY Entry, _In_ UINT32 Verdict)
{
    FWPS_CLASSIFY_OUT0 classifyOut = Entry->ClassifyOut;
    FWPS_CONNECT_REQUEST0* connReq = (FWPS_CONNECT_REQUEST0*)Entry->WritableLayerData;
    NTSTATUS redirectStatus = STATUS_SUCCESS;
    CONFIG_SNAPSHOT snapshot;

    if (Verdict == VERDICT_REDIRECT) {
        snapshot = ReadConfigSnapshot(Ctx);
        if (!connReq ||
            !snapshot.HasTunLuid ||
            snapshot.Config.RedirectPort == 0 ||
            snapshot.Config.ProxyPID == 0 ||
            Ctx->RedirectHandle == NULL) {
            redirectStatus = STATUS_INVALID_DEVICE_STATE;
        } else {
            SOCKADDR_STORAGE* redirectContext =
                (SOCKADDR_STORAGE*)ExAllocatePoolZero(NonPagedPoolNx, sizeof(SOCKADDR_STORAGE) * 2, 'rniW');
            if (!redirectContext) {
                redirectStatus = STATUS_INSUFFICIENT_RESOURCES;
            } else {
                RtlCopyMemory(&redirectContext[0], &connReq->remoteAddressAndPort, sizeof(SOCKADDR_STORAGE));
                RtlCopyMemory(&redirectContext[1], &connReq->localAddressAndPort, sizeof(SOCKADDR_STORAGE));

                if (Entry->AddressFamily == AF_INET) {
                    SOCKADDR_IN* localAddr = (SOCKADDR_IN*)&connReq->localAddressAndPort;
                    SOCKADDR_IN* addr = (SOCKADDR_IN*)&connReq->remoteAddressAndPort;
                    addr->sin_family = AF_INET;
                    if (localAddr->sin_addr.s_addr == 0) {
                        addr->sin_addr.s_addr = RtlUlongByteSwap(0x7F000001); // 127.0.0.1
                    } else {
                        addr->sin_addr = localAddr->sin_addr;
                    }
                    addr->sin_port = RtlUshortByteSwap(snapshot.Config.RedirectPort);
                } else if (Entry->AddressFamily == AF_INET6) {
                    SOCKADDR_IN6* localAddr = (SOCKADDR_IN6*)&connReq->localAddressAndPort;
                    SOCKADDR_IN6* addr = (SOCKADDR_IN6*)&connReq->remoteAddressAndPort;
                    if (IsAnyAddress(AF_INET6, localAddr->sin6_addr.u.Byte)) {
                        RtlZeroMemory(addr, sizeof(SOCKADDR_IN6));
                        addr->sin6_family = AF_INET6;
                        addr->sin6_addr.u.Byte[15] = 1; // ::1
                    } else {
                        *addr = *localAddr;
                        addr->sin6_family = AF_INET6;
                    }
                    addr->sin6_port = RtlUshortByteSwap(snapshot.Config.RedirectPort);
                } else {
                    redirectStatus = STATUS_INVALID_PARAMETER;
                }

                if (NT_SUCCESS(redirectStatus)) {
                    connReq->localRedirectHandle = Ctx->RedirectHandle;
                    connReq->localRedirectTargetPID = snapshot.Config.ProxyPID;
                    connReq->localRedirectContext = redirectContext;
                    connReq->localRedirectContextSize = sizeof(SOCKADDR_STORAGE) * 2;
                } else {
                    ExFreePoolWithTag(redirectContext, 'rniW');
                }
            }
        }

        if (!NT_SUCCESS(redirectStatus)) {
            TriggerFatal(Ctx, redirectStatus, "execute redirect");
            Verdict = VERDICT_PERMIT;
        }
    }

    if (Entry->WritableLayerData) {
        FwpsApplyModifiedLayerData0(
            Entry->ClassifyHandle,
            Entry->WritableLayerData,
            FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS);
        Entry->WritableLayerData = NULL;
    }

    classifyOut.actionType = FWP_ACTION_PERMIT;
    classifyOut.rights &= ~FWPS_RIGHT_ACTION_WRITE;

    FwpsCompleteClassify0(Entry->ClassifyHandle, 0, &classifyOut);
    FwpsReleaseClassifyHandle0(Entry->ClassifyHandle);
}
