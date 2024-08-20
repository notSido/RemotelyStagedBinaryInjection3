//
// Created by Sido on 19/08/2024.
//

#ifndef ENUM_H
#define ENUM_H
#include <Windows.h>
#include <tlhelp32.h>
#include "debug.h"

DWORD FindProcessID(const wchar_t* processName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD dwPID = 0;
    char convertedProcessName[MAX_PATH];

    wcstombs(convertedProcessName, processName, MAX_PATH);

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to take a snapshot of the processes, error: %ld", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        LOG_ERROR("Failed to gather information on system processes, error: %ld", GetLastError());
        CloseHandle(hProcessSnap);
        return 0;
    }

    do {
        if (_stricmp(pe32.szExeFile, convertedProcessName) == 0) {
            // Attempt to open a handle to the process
            HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                // Successfully opened a handle, this process is unprotected and can be used
                dwPID = pe32.th32ProcessID;
                CloseHandle(hProcess);
                break;
            } else {
                DWORD error = GetLastError();
                if (error == ERROR_ACCESS_DENIED) {
                    LOG_INFO("Access denied to process %ld, skipping...", pe32.th32ProcessID);
                } else {
                    LOG_ERROR("Failed to open handle to process %ld, error: %ld", pe32.th32ProcessID, error);
                }
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    LOG_INFO("Found %ld", dwPID);
    return dwPID;
}

#endif //ENUM_H
