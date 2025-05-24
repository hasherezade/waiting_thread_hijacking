#pragma once

#include <windows.h>

#define WAIT_REASON_UNDEFINED (-1)

LPVOID alloc_memory_in_process(DWORD processID, const size_t shellcode_size);

bool write_shc_into_process(DWORD processID, LPVOID shellcodePtr, const BYTE* shellc_buf, const size_t shellc_size);

bool run_injected(DWORD pid, ULONGLONG shellcodePtr, size_t shellcodeSize, DWORD wait_reason);
