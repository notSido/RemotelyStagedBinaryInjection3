#pragma once

#include <windows.h>
#include <stdio.h>

#define STATUS_SUCCESS ((NTSTATUS)0X00000000l)

/*------------------[FUNCTION PROTOTYPES]----------------*/

// Declare the function prototypes
extern BOOL InitNtUnmapView();
extern DWORD GetMainThreadId(DWORD dwProcessId);
extern BOOL SuspendProcess(DWORD dwPID);
extern BOOL HollowProcess(HANDLE hProcess, PBYTE pPayload, SIZE_T sSize);
extern DWORD FindProcessID(const wchar_t* processName);

// Declare the global variable as extern
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);
extern NtUnmapViewOfSection_t pNtUnmapViewOfSection;

typedef NTSTATUS(NTAPI* NtUnmapViewOfSection)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
);
