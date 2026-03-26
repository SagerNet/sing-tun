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
    status = WdfDeviceCreate(&deviceInit, &deviceAttrs, &device);
    if (!NT_SUCCESS(status)) return status;

    status = WdfDeviceCreateSymbolicLink(device, &symlinkName);
    if (!NT_SUCCESS(status)) return status;

    ctx = GetDriverContext(device);
    RtlZeroMemory(ctx, sizeof(DRIVER_CONTEXT));
    ctx->Device = device;
    InitializeListHead(&ctx->PendingList);
    ExInitializeFastMutex(&ctx->PendingLock);
    ExInitializeFastMutex(&ctx->ConfigLock);
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

    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}

void EvtDriverUnload(_In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    if (g_Ctx) {
        WfpCleanup(g_Ctx);
        PendingFlushAll(g_Ctx);
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
    PDRIVER_CONTEXT ctx = g_Ctx;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inBuf = NULL;
    size_t inLen = 0;

    switch (IoControlCode) {
    case IOCTL_WINREDIRECT_SET_CONFIG:
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(WINREDIRECT_CONFIG), &inBuf, &inLen);
        if (NT_SUCCESS(status)) {
            ExAcquireFastMutex(&ctx->ConfigLock);
            RtlCopyMemory(&ctx->Config, inBuf, sizeof(WINREDIRECT_CONFIG));
            ExReleaseFastMutex(&ctx->ConfigLock);
        }
        WdfRequestComplete(Request, status);
        break;

    case IOCTL_WINREDIRECT_START:
        if (InterlockedCompareExchange(&ctx->Running, TRUE, FALSE) != FALSE) {
            WdfRequestComplete(Request, STATUS_ALREADY_REGISTERED);
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

    case IOCTL_WINREDIRECT_STOP:
        if (InterlockedCompareExchange(&ctx->Running, FALSE, TRUE) == TRUE) {
            WdfTimerStop(ctx->TimeoutTimer, TRUE);
            WdfWorkItemFlush(ctx->TimeoutWorkItem);
            WfpCleanup(ctx);
            PendingFlushAll(ctx);
        }
        WdfRequestComplete(Request, STATUS_SUCCESS);
        break;

    case IOCTL_WINREDIRECT_GET_PENDING:
        // Forward to manual queue — will be completed when a connection arrives
        status = WdfRequestForwardToIoQueue(Request, ctx->PendingIoctlQueue);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
        }
        break;

    case IOCTL_WINREDIRECT_SET_VERDICT: {
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(WINREDIRECT_VERDICT), &inBuf, &inLen);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            break;
        }
        WINREDIRECT_VERDICT* v = (WINREDIRECT_VERDICT*)inBuf;
        PPENDING_ENTRY entry = PendingFindByID(ctx, v->ConnID);
        if (entry) {
            ExecuteVerdict(ctx, entry, v->Verdict);
            ExFreePoolWithTag(entry, 'rniW');
        }
        WdfRequestComplete(Request, entry ? STATUS_SUCCESS : STATUS_NOT_FOUND);
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

    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    ExAcquireFastMutex(&g_Ctx->PendingLock);

    PLIST_ENTRY entry = g_Ctx->PendingList.Flink;
    while (entry != &g_Ctx->PendingList) {
        PPENDING_ENTRY pending = CONTAINING_RECORD(entry, PENDING_ENTRY, ListEntry);
        entry = entry->Flink;

        // Auto-bypass entries older than 5 seconds
        LONGLONG elapsed = (now.QuadPart - pending->Timestamp.QuadPart) / 10000000LL; // to seconds
        if (elapsed >= 5) {
            RemoveEntryList(&pending->ListEntry);
            ExReleaseFastMutex(&g_Ctx->PendingLock);
            ExecuteVerdict(g_Ctx, pending, VERDICT_BYPASS);
            ExFreePoolWithTag(pending, 'rniW');
            ExAcquireFastMutex(&g_Ctx->PendingLock);
            entry = g_Ctx->PendingList.Flink;
        }
    }

    ExReleaseFastMutex(&g_Ctx->PendingLock);
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
    FWPS_CALLOUT3 sCalloutV4 = {
        .calloutKey = WINREDIRECT_CALLOUT_V4_KEY,
        .classifyFn = ClassifyFnV4,
        .notifyFn = NotifyFn,
    };
    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(Ctx->Device), &sCalloutV4, &Ctx->CalloutIdV4);
    if (!NT_SUCCESS(status)) goto cleanup;

    FWPS_CALLOUT3 sCalloutV6 = {
        .calloutKey = WINREDIRECT_CALLOUT_V6_KEY,
        .classifyFn = ClassifyFnV6,
        .notifyFn = NotifyFn,
    };
    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(Ctx->Device), &sCalloutV6, &Ctx->CalloutIdV6);
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

    // Add filters — condition: TCP only
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
    if (Ctx->RedirectHandle) {
        FwpsRedirectHandleDestroy0(Ctx->RedirectHandle);
        Ctx->RedirectHandle = NULL;
    }
    if (Ctx->CalloutIdV4) {
        FwpsCalloutUnregisterById0(Ctx->CalloutIdV4);
        Ctx->CalloutIdV4 = 0;
    }
    if (Ctx->CalloutIdV6) {
        FwpsCalloutUnregisterById0(Ctx->CalloutIdV6);
        Ctx->CalloutIdV6 = 0;
    }
    if (Ctx->EngineHandle) {
        FwpmEngineClose0(Ctx->EngineHandle);
        Ctx->EngineHandle = NULL;
    }
}

NTSTATUS NTAPI NotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter)
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
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut,
    _In_ UINT32 localAddrIdx,
    _In_ UINT32 localPortIdx,
    _In_ UINT32 remoteAddrIdx,
    _In_ UINT32 remotePortIdx)
{
    PDRIVER_CONTEXT ctx = g_Ctx;
    if (!ctx || !ctx->Running) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Allocate pending entry
    PPENDING_ENTRY entry = (PPENDING_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(PENDING_ENTRY), 'rniW');
    if (!entry) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    RtlZeroMemory(entry, sizeof(PENDING_ENTRY));
    entry->ConnID = InterlockedIncrement64(&ctx->NextConnID);
    entry->AddressFamily = addressFamily;
    entry->FilterId = filter->filterId;

    // Extract addresses
    if (addressFamily == AF_INET) {
        UINT32 srcIp = inFixedValues->incomingValue[localAddrIdx].value.uint32;
        UINT32 dstIp = inFixedValues->incomingValue[remoteAddrIdx].value.uint32;
        // WFP stores IPv4 in host byte order
        *(UINT32*)entry->SrcAddr = RtlUlongByteSwap(srcIp);
        *(UINT32*)entry->DstAddr = RtlUlongByteSwap(dstIp);
    } else {
        RtlCopyMemory(entry->SrcAddr,
            inFixedValues->incomingValue[localAddrIdx].value.byteArray16->byteArray16, 16);
        RtlCopyMemory(entry->DstAddr,
            inFixedValues->incomingValue[remoteAddrIdx].value.byteArray16->byteArray16, 16);
    }
    entry->SrcPort = inFixedValues->incomingValue[localPortIdx].value.uint16;
    entry->DstPort = inFixedValues->incomingValue[remotePortIdx].value.uint16;

    // Extract PID from metadata
    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        entry->ProcessID = (UINT32)inMetaValues->processId;
    }

    // Pend the classify
    UINT64 classifyHandle;
    NTSTATUS status = FwpsAcquireClassifyHandle0(classifyOut, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(entry, 'rniW');
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    entry->ClassifyHandle = classifyHandle;

    status = FwpsPendClassify0(
        inFixedValues, inMetaValues, layerData,
        classifyContext, filter, flowContext, classifyOut);
    if (!NT_SUCCESS(status)) {
        FwpsReleaseClassifyHandle0(classifyHandle);
        ExFreePoolWithTag(entry, 'rniW');
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    KeQuerySystemTime(&entry->Timestamp);
    PendingInsert(ctx, entry);

    // Try to complete a waiting IOCTL_GET_PENDING
    WDFREQUEST request;
    status = WdfIoQueueRetrieveNextRequest(ctx->PendingIoctlQueue, &request);
    if (NT_SUCCESS(status)) {
        PVOID outBuf;
        status = WdfRequestRetrieveOutputBuffer(request, sizeof(WINREDIRECT_PENDING_CONN), &outBuf, NULL);
        if (NT_SUCCESS(status)) {
            WINREDIRECT_PENDING_CONN* out = (WINREDIRECT_PENDING_CONN*)outBuf;
            RtlZeroMemory(out, sizeof(*out));
            out->ConnID = entry->ConnID;
            out->AddressFamily = entry->AddressFamily;
            RtlCopyMemory(out->SrcAddr, entry->SrcAddr, 16);
            out->SrcPort = entry->SrcPort;
            RtlCopyMemory(out->DstAddr, entry->DstAddr, 16);
            out->DstPort = entry->DstPort;
            out->ProcessID = entry->ProcessID;
            WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, sizeof(WINREDIRECT_PENDING_CONN));
        } else {
            WdfRequestComplete(request, status);
        }
    }
}

void NTAPI ClassifyFnV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
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
    _In_ const FWPS_FILTER3* filter,
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

PPENDING_ENTRY PendingAllocate(_In_ PDRIVER_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    return (PPENDING_ENTRY)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(PENDING_ENTRY), 'rniW');
}

void PendingInsert(_In_ PDRIVER_CONTEXT Ctx, _In_ PPENDING_ENTRY Entry)
{
    ExAcquireFastMutex(&Ctx->PendingLock);
    InsertTailList(&Ctx->PendingList, &Entry->ListEntry);
    ExReleaseFastMutex(&Ctx->PendingLock);
}

PPENDING_ENTRY PendingFindByID(_In_ PDRIVER_CONTEXT Ctx, _In_ UINT64 ConnID)
{
    PPENDING_ENTRY found = NULL;
    ExAcquireFastMutex(&Ctx->PendingLock);
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
    ExReleaseFastMutex(&Ctx->PendingLock);
    return found;
}

void PendingRemove(_In_ PDRIVER_CONTEXT Ctx, _In_ PPENDING_ENTRY Entry)
{
    ExAcquireFastMutex(&Ctx->PendingLock);
    RemoveEntryList(&Entry->ListEntry);
    ExReleaseFastMutex(&Ctx->PendingLock);
}

void PendingFlushAll(_In_ PDRIVER_CONTEXT Ctx)
{
    ExAcquireFastMutex(&Ctx->PendingLock);
    while (!IsListEmpty(&Ctx->PendingList)) {
        PLIST_ENTRY entry = RemoveHeadList(&Ctx->PendingList);
        PPENDING_ENTRY pending = CONTAINING_RECORD(entry, PENDING_ENTRY, ListEntry);
        ExReleaseFastMutex(&Ctx->PendingLock);
        ExecuteVerdict(Ctx, pending, VERDICT_BYPASS);
        ExFreePoolWithTag(pending, 'rniW');
        ExAcquireFastMutex(&Ctx->PendingLock);
    }
    ExReleaseFastMutex(&Ctx->PendingLock);
}

// --- Verdict execution ---

void ExecuteVerdict(_In_ PDRIVER_CONTEXT Ctx, _In_ PPENDING_ENTRY Entry, _In_ UINT32 Verdict)
{
    FWPS_CLASSIFY_OUT0 classifyOut = { 0 };

    if (Verdict == VERDICT_REDIRECT) {
        FWPS_CONNECT_REQUEST0* connReq = NULL;
        NTSTATUS status = FwpsAcquireWritableLayerDataPointer0(
            Entry->ClassifyHandle, Entry->FilterId, 0,
            (PVOID*)&connReq, &classifyOut);

        if (NT_SUCCESS(status) && connReq) {
            ExAcquireFastMutex(&Ctx->ConfigLock);
            WINREDIRECT_CONFIG config = Ctx->Config;
            ExReleaseFastMutex(&Ctx->ConfigLock);

            if (Entry->AddressFamily == AF_INET) {
                SOCKADDR_IN* addr = (SOCKADDR_IN*)&connReq->remoteAddressAndPort;
                addr->sin_family = AF_INET;
                addr->sin_addr.s_addr = RtlUlongByteSwap(0x7F000001); // 127.0.0.1
                addr->sin_port = RtlUshortByteSwap(config.RedirectPort);
            } else {
                SOCKADDR_IN6* addr = (SOCKADDR_IN6*)&connReq->remoteAddressAndPort;
                RtlZeroMemory(addr, sizeof(SOCKADDR_IN6));
                addr->sin6_family = AF_INET6;
                addr->sin6_addr.u.Byte[15] = 1; // ::1
                addr->sin6_port = RtlUshortByteSwap(config.RedirectPort);
            }
            connReq->localRedirectTargetPID = config.ProxyPID;
            connReq->localRedirectHandle = Ctx->RedirectHandle;

            FwpsApplyModifiedLayerData0(Entry->ClassifyHandle, connReq, 0);
        }

        classifyOut.actionType = FWP_ACTION_PERMIT;
        classifyOut.rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else if (Verdict == VERDICT_BYPASS) {
        classifyOut.actionType = FWP_ACTION_PERMIT;
        classifyOut.rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else { // VERDICT_DROP
        classifyOut.actionType = FWP_ACTION_BLOCK;
        classifyOut.rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }

    FwpsCompleteClassify0(Entry->ClassifyHandle, 0, &classifyOut);
    FwpsReleaseClassifyHandle0(Entry->ClassifyHandle);
}
