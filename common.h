#pragma once

#include <Windows.h>
#include <iostream>
#include <sstream>
#include "ntddk.h"

#define KWAIT_REASON_TO_STRING(reason) \
    ((reason) == Executive ? "Executive" : \
    (reason) == FreePage ? "FreePage" : \
    (reason) == PageIn ? "PageIn" : \
    (reason) == PoolAllocation ? "PoolAllocation" : \
    (reason) == DelayExecution ? "DelayExecution" : \
    (reason) == Suspended ? "Suspended" : \
    (reason) == UserRequest ? "UserRequest" : \
    (reason) == WrExecutive ? "WrExecutive" : \
    (reason) == WrFreePage ? "WrFreePage" : \
    (reason) == WrPageIn ? "WrPageIn" : \
    (reason) == WrPoolAllocation ? "WrPoolAllocation" : \
    (reason) == WrDelayExecution ? "WrDelayExecution" : \
    (reason) == WrSuspended ? "WrSuspended" : \
    (reason) == WrUserRequest ? "WrUserRequest" : \
    (reason) == WrEventPair ? "WrEventPair" : \
    (reason) == WrQueue ? "WrQueue" : \
    (reason) == WrLpcReceive ? "WrLpcReceive" : \
    (reason) == WrLpcReply ? "WrLpcReply" : \
    (reason) == WrVirtualMemory ? "WrVirtualMemory" : \
    (reason) == WrPageOut ? "WrPageOut" : \
    (reason) == WrRendezvous ? "WrRendezvous" : \
    (reason) == WrKeyedEvent ? "WrKeyedEvent" : \
    (reason) == WrTerminated ? "WrTerminated" : \
    (reason) == WrProcessInSwap ? "WrProcessInSwap" : \
    (reason) == WrCpuRateControl ? "WrCpuRateControl" : \
    (reason) == WrCalloutStack ? "WrCalloutStack" : \
    (reason) == WrKernel ? "WrKernel" : \
    (reason) == WrResource ? "WrResource" : \
    (reason) == WrPushLock ? "WrPushLock" : \
    (reason) == WrMutex ? "WrMutex" : \
    (reason) == WrQuantumEnd ? "WrQuantumEnd" : \
    (reason) == WrDispatchInt ? "WrDispatchInt" : \
    (reason) == WrPreempted ? "WrPreempted" : \
    (reason) == WrYieldExecution ? "WrYieldExecution" : \
    (reason) == WrFastMutex ? "WrFastMutex" : \
    (reason) == WrGuardedMutex ? "WrGuardedMutex" : \
    (reason) == WrRundown ? "WrRundown" : \
    (reason) == WrAlertByThreadId ? "WrAlertByThreadId" : \
    (reason) == WrDeferredPreempt ? "WrDeferredPreempt" : \
    (reason) == WrPhysicalFault ? "WrPhysicalFault" : \
    "Unknown")


inline DWORD loadInt(const std::string& str, bool as_hex)
{
    DWORD intVal = 0;

    std::stringstream ss;
    ss << (as_hex ? std::hex : std::dec) << str;
    ss >> intVal;
    return intVal;
}

inline std::string writeInt(ULONGLONG val, bool as_hex)
{
    std::stringstream ss;
    ss << (as_hex ? std::hex : std::dec) << val;
    return ss.str();
}

inline BYTE* load_from_file(const char* filename, size_t& data_size)
{
    FILE* fp = fopen(filename, "rb");
    if (!fp) return nullptr;

    fseek(fp, 0, SEEK_END);
    size_t fsize = ftell(fp);
    BYTE* data = (BYTE*)::calloc(fsize, 1);
    if (!data) return nullptr;

    fseek(fp, 0, SEEK_SET);
    data_size = fsize;
    fread(data, 1, data_size, fp);
    fclose(fp);
    return data;
}
