#include <ndis.h>

// GUID (يجب تسجيله)
DEFINE_GUID(
    THOR_LWF_GUID,
    0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
);

// هيكل البيانات
typedef struct _THOR_LWF_DATA {
    NDIS_HANDLE FilterHandle;
    NDIS_SPIN_LOCK Lock;
    LIST_ENTRY BlockedIpsList;
    ULONG BlockedCount;
} THOR_LWF_DATA, *PTHOR_LWF_DATA;

typedef struct _THOR_IP_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG IpAddress;
    ULONG64 LastSeen;
    ULONG RequestCount;
} THOR_IP_ENTRY, *PTHOR_IP_ENTRY;

NDIS_STATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
) {
    NDIS_FILTER_DRIVER_CHARACTERISTICS chars;
    NDIS_STATUS status;
    
    NdisZeroMemory(&chars, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));
    chars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    chars.Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);
    chars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
    chars.MajorNdisVersion = NDIS_FILTER_MAJOR_VERSION;
    chars.MinorNdisVersion = NDIS_FILTER_MINOR_VERSION;
    chars.MajorDriverVersion = 1;
    chars.MinorDriverVersion = 0;
    chars.FriendlyName = L"Thor Network Filter";
    chars.UniqueName = L"ThorLWF";
    chars.ServiceName = L"ThorLWF";
    chars.AttachHandler = ThorAttach;
    chars.DetachHandler = ThorDetach;
    chars.ReceiveNetBufferListsHandler = ThorReceive;
    chars.SendNetBufferListsHandler = ThorSend;
    
    status = NdisFRegisterFilterDriver(
        DriverObject,
        NULL,
        &chars,
        &ThorDriverHandle
    );
    
    return status;
}

NDIS_STATUS ThorAttach(
    NDIS_HANDLE NdisFilterHandle,
    NDIS_HANDLE FilterDriverContext,
    PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters
) {
    PTHOR_LWF_DATA filterData;
    NDIS_STATUS status;
    
    status = NdisAllocateMemoryWithTag(
        (PVOID*)&filterData,
        sizeof(THOR_LWF_DATA),
        'rohT'
    );
    
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }
    
    NdisZeroMemory(filterData, sizeof(THOR_LWF_DATA));
    NdisInitializeListHead(&filterData->BlockedIpsList);
    NdisAllocateSpinLock(&filterData->Lock);
    
    NDIS_FILTER_ATTRIBUTES attrs;
    NdisZeroMemory(&attrs, sizeof(NDIS_FILTER_ATTRIBUTES));
    attrs.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    attrs.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
    attrs.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    
    status = NdisFSetAttributes(NdisFilterHandle, filterData, &attrs);
    
    if (status == NDIS_STATUS_SUCCESS) {
        filterData->FilterHandle = NdisFilterHandle;
    }
    
    return status;
}

VOID ThorDetach(
    NDIS_HANDLE FilterModuleContext
) {
    PTHOR_LWF_DATA filterData = (PTHOR_LWF_DATA)FilterModuleContext;
    PLIST_ENTRY entry;
    PTHOR_IP_ENTRY ipEntry;
    
    NdisAcquireSpinLock(&filterData->Lock);
    
    while (!IsListEmpty(&filterData->BlockedIpsList)) {
        entry = RemoveHeadList(&filterData->BlockedIpsList);
        ipEntry = CONTAINING_RECORD(entry, THOR_IP_ENTRY, ListEntry);
        NdisFreeMemory(ipEntry, 0, 0);
    }
    
    NdisReleaseSpinLock(&filterData->Lock);
    NdisFreeSpinLock(&filterData->Lock);
    NdisFreeMemory(filterData, 0, 0);
}

VOID ThorReceive(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG NumberOfNetBufferLists,
    ULONG ReceiveFlags
) {
    PTHOR_LWF_DATA filterData = (PTHOR_LWF_DATA)FilterModuleContext;
    PNET_BUFFER_LIST currentNbl = NetBufferLists;
    PNET_BUFFER_LIST allowedNbls = NULL;
    PNET_BUFFER_LIST blockedNbls = NULL;
    PNET_BUFFER_LIST lastAllowed = NULL;
    PNET_BUFFER_LIST lastBlocked = NULL;
    
    NdisAcquireSpinLock(&filterData->Lock);
    
    while (currentNbl != NULL) {
        PNET_BUFFER_LIST nextNbl = NET_BUFFER_LIST_NEXT_NBL(currentNbl);
        PNET_BUFFER netBuffer = NET_BUFFER_LIST_FIRST_NB(currentNbl);
        BOOLEAN shouldBlock = FALSE;
        
        while (netBuffer != NULL) {
            PMDL mdl = NET_BUFFER_FIRST_MDL(netBuffer);
            PVOID address = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoWrite);
            
            if (address != NULL) {
                PUCHAR ethHeader = (PUCHAR)address;
                UINT16 ethType = (ethHeader[12] << 8) | ethHeader[13];
                
                if (ethType == 0x0800) { // IPv4
                    ULONG srcIp = ((PULONG)(ethHeader + 14))[3];
                    ULONG64 now;
                    KeQuerySystemTime((PLARGE_INTEGER)&now);
                    
                    // فحص القائمة السوداء
                    PLIST_ENTRY entry;
                    for (entry = filterData->BlockedIpsList.Flink;
                         entry != &filterData->BlockedIpsList;
                         entry = entry->Flink) {
                        PTHOR_IP_ENTRY ipEntry = CONTAINING_RECORD(entry, THOR_IP_ENTRY, ListEntry);
                        if (ipEntry->IpAddress == srcIp) {
                            shouldBlock = TRUE;
                            break;
                        }
                    }
                }
            }
            
            netBuffer = NET_BUFFER_NEXT_NB(netBuffer);
        }
        
        NET_BUFFER_LIST_NEXT_NBL(currentNbl) = NULL;
        
        if (shouldBlock) {
            if (blockedNbls == NULL) {
                blockedNbls = currentNbl;
                lastBlocked = currentNbl;
            } else {
                NET_BUFFER_LIST_NEXT_NBL(lastBlocked) = currentNbl;
                lastBlocked = currentNbl;
            }
        } else {
            if (allowedNbls == NULL) {
                allowedNbls = currentNbl;
                lastAllowed = currentNbl;
            } else {
                NET_BUFFER_LIST_NEXT_NBL(lastAllowed) = currentNbl;
                lastAllowed = currentNbl;
            }
        }
        
        currentNbl = nextNbl;
    }
    
    NdisReleaseSpinLock(&filterData->Lock);
    
    if (allowedNbls != NULL) {
        NdisFIndicateReceiveNetBufferLists(
            filterData->FilterHandle,
            allowedNbls,
            PortNumber,
            NumberOfNetBufferLists,
            ReceiveFlags
        );
    }
    
    if (blockedNbls != NULL) {
        filterData->BlockedCount++;
        // تحرير
        PNET_BUFFER_LIST tempNbl;
        while (blockedNbls != NULL) {
            tempNbl = blockedNbls;
            blockedNbls = NET_BUFFER_LIST_NEXT_NBL(blockedNbls);
            NdisFreeNetBufferList(tempNbl);
        }
    }
}

VOID ThorSend(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG NumberOfNetBufferLists,
    ULONG SendFlags
) {
    PTHOR_LWF_DATA filterData = (PTHOR_LWF_DATA)FilterModuleContext;
    NdisFSendNetBufferLists(
        filterData->FilterHandle,
        NetBufferLists,
        PortNumber,
        SendFlags
    );
}
