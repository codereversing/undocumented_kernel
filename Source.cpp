#include "stdafx.h"

#include "Undocumented.h"
#include <wdm.h>

#ifdef __cplusplus
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath);
#endif

pPsGetProcessImageFileName PsGetProcessImageFileName;
pPsGetProcessSectionBaseAddress PsGetProcessSectionBaseAddress;
pPsGetNextProcess PsGetNextProcess;
pZwSuspendProcess ZwSuspendProcess;
pZwResumeProcess ZwResumeProcess;
pZwProtectVirtualMemory ZwProtectVirtualMemory;
pZwWriteVirtualMemory ZwWriteVirtualMemory;
pKiSystemService KiSystemService;

#ifdef _M_IX86
__declspec(naked) VOID SyscallTemplate(VOID) {
    __asm {
        /*B8 XX XX XX XX   */ mov eax, 0xC0DE
            /*8D 54 24 04      */ lea edx, [esp + 0x4]
            /*9C               */ pushfd
            /*6A 08            */ push 0x8
            /*FF 15 XX XX XX XX*/ call KiSystemService
            /*C2 XX XX         */ retn 0xBBBB
    }
}
#elif defined(_M_AMD64)

BYTE NullStub = 0xC3;

BYTE SyscallTemplate[] =
{
    0x48, 0x8B, 0xC4,                                           /*mov rax, rsp*/
    0xFA,                                                       /*cli*/
    0x48, 0x83, 0xEC, 0x10,                                     /*sub rsp, 0x10*/
    0x50,                                                       /*push rax*/
    0x9C,                                                       /*pushfq*/
    0x6A, 0x10,                                                 /*push 0x10*/
    0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, /*mov rax, NullStubAddress*/
    0x50,                                                       /*push rax*/
    0xB8, 0xBB, 0xBB, 0xBB, 0xBB,                               /*mov eax, Syscall*/
    0x68, 0xCC, 0xCC, 0xCC, 0xCC,                               /*push LowBytes*/
    0xC7, 0x44, 0x24, 0x04, 0xCC, 0xCC, 0xCC, 0xCC,             /*mov [rsp+0x4], HighBytes*/
    0xC3                                                        /*ret*/
};
#endif

PVOID FindFunctionInModule(IN CONST BYTE *Signature,
    IN ULONG SignatureSize,
    IN PVOID KernelBaseAddress,
    IN ULONG ImageSize) {

    BYTE *CurrentAddress = 0;
    ULONG i = 0;

    DbgPrint("+ Scanning from %p to %p\n", KernelBaseAddress, (ULONG_PTR)KernelBaseAddress + ImageSize);
    CurrentAddress = (BYTE *)KernelBaseAddress;
    DbgPrint("+ Scanning from %p to %p\n", KernelBaseAddress, (ULONG_PTR)KernelBaseAddress + ImageSize);
    CurrentAddress = (BYTE *)KernelBaseAddress;

    for (i = 0; i < ImageSize; ++i) {
        if (RtlCompareMemory(CurrentAddress, Signature, SignatureSize) == SignatureSize) {
            DbgPrint("+ Found function at %p\n", CurrentAddress);
            return (PVOID)CurrentAddress;
        }
        ++CurrentAddress;
    }
    return NULL;
}

NTSTATUS ResolveFunctions(IN PSYSTEM_MODULE KernelInfo) {

    UNICODE_STRING PsGetProcessImageFileNameStr = { 0 };
    UNICODE_STRING PsGetProcessSectionBaseAddressStr = { 0 };
#ifdef _M_IX86
    CONST BYTE PsGetNextProcessSignature[] =
    {
        0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x51, 0x83, 0x65,
        0xFC, 0x00, 0x56, 0x57, 0x64, 0xA1, 0x24, 0x01, 0x00, 0x00,
        0x8B, 0xF0, 0xFF, 0x8E, 0xD4, 0x00, 0x00, 0x00, 0xB9, 0xC0,
        0x38, 0x56, 0x80, 0xE8, 0xB4, 0xEE, 0xF6, 0xFF, 0x8B, 0x45,
        0x08, 0x85, 0xC0
    };
#elif defined(_M_AMD64)
    CONST BYTE PsGetNextProcessSignature[] =
    {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x41, 0x54, 0x41, 0x55,
        0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x65, 0x48,
        0x8B, 0x34, 0x25, 0x88, 0x01, 0x00, 0x00, 0x45, 0x33, 0xED,
        0x48, 0x8B, 0xF9, 0x66, 0xFF, 0x8E, 0xC6, 0x01, 0x00, 0x00,
        0x4D, 0x8B, 0xE5, 0x41, 0x8B, 0xED, 0x41, 0x8D, 0x4D, 0x11,
        0x33, 0xC0,
    };
#endif
#ifdef _M_IX86
    CONST BYTE KiSystemServiceSignature[] =
    {
        0x6A, 0x00, 0x55, 0x53, 0x56, 0x57, 0x0F, 0xA0, 0xBB, 0x30,
        0x00, 0x00, 0x00, 0x66, 0x8E, 0xE3, 0x64, 0xFF, 0x35, 0x00,
        0x00, 0x00, 0x00
    };
#elif defined(_M_AMD64)
    CONST BYTE KiSystemServiceSignature[] =
    {
        0x48, 0x83, 0xEC, 0x08, 0x55, 0x48, 0x81, 0xEC, 0x58, 0x01,
        0x00, 0x00, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x9D, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x89, 0xBD,
        0xC8, 0x00, 0x00, 0x00, 0x48, 0x89, 0xB5, 0xD0, 0x00, 0x00,
        0x00, 0xFB, 0x65, 0x48, 0x8B, 0x1C, 0x25, 0x88, 0x01, 0x00,
        0x00
    };
#endif
    RtlInitUnicodeString(&PsGetProcessImageFileNameStr, L"PsGetProcessImageFileName");
    RtlInitUnicodeString(&PsGetProcessSectionBaseAddressStr, L"PsGetProcessSectionBaseAddress");

    PsGetProcessImageFileName = (pPsGetProcessImageFileName)MmGetSystemRoutineAddress(&PsGetProcessImageFileNameStr);
    if (PsGetProcessImageFileName == NULL) {
        DbgPrint("- Could not find PsGetProcessImageFileName\n");
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrint("+ Found PsGetProcessImageFileName at %p\n", PsGetProcessImageFileName);

    PsGetProcessSectionBaseAddress = (pPsGetProcessSectionBaseAddress)MmGetSystemRoutineAddress(&PsGetProcessSectionBaseAddressStr);
    if (PsGetProcessSectionBaseAddress == NULL) {
        DbgPrint("- Could not find PsGetProcessSectionBaseAddress\n");
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrint("+ Found PsGetProcessSectionBaseAddress at %p\n", PsGetProcessSectionBaseAddress);

    PsGetNextProcess = (pPsGetNextProcess)FindFunctionInModule(PsGetNextProcessSignature,
        sizeof(PsGetNextProcessSignature), KernelInfo->ImageBaseAddress, KernelInfo->ImageSize);
    if (PsGetNextProcess == NULL) {
        DbgPrint("- Could not find PsGetNextProcess\n");
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrint("+ Found PsGetNextProcess at %p\n", PsGetNextProcess);

    KiSystemService = (pKiSystemService)FindFunctionInModule(KiSystemServiceSignature,
        sizeof(KiSystemServiceSignature), KernelInfo->ImageBaseAddress, KernelInfo->ImageSize);
    if (KiSystemService == NULL) {
        DbgPrint("- Could not find KiSystemService\n");
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrint("+ Found KiSystemService at %p\n", KiSystemService);

    return STATUS_SUCCESS;
}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject) {

    DbgPrint("+ Unloading\n");
}

PSYSTEM_MODULE GetKernelModuleInfo(VOID) {

    PSYSTEM_MODULE SystemModule = NULL;
    PSYSTEM_MODULE FoundModule = NULL;
    ULONG_PTR SystemInfoLength = 0;
    PVOID Buffer = NULL;
    ULONG Count = 0;
    ULONG i = 0;
    ULONG j = 0;
    //Other names for WinXP
    CONST CHAR *KernelNames[] = { "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe" };

    //Perform error checking on the calls in actual code
    (VOID)ZwQuerySystemInformation(SystemModuleInformation, &SystemInfoLength, 0, &SystemInfoLength);
    Buffer = ExAllocatePool(NonPagedPool, SystemInfoLength);
    (VOID)ZwQuerySystemInformation(SystemModuleInformation, Buffer, SystemInfoLength, NULL);

    Count = ((PSYSTEM_MODULE_INFORMATION)Buffer)->ModulesCount;
    for (i = 0; i < Count; ++i) {
        SystemModule = &((PSYSTEM_MODULE_INFORMATION)Buffer)->Modules[i];
        for (j = 0; j < sizeof(KernelNames) / sizeof(KernelNames[0]); ++j) {
            if (strstr((LPCSTR)SystemModule->Name, KernelNames[j]) != NULL) {
                FoundModule = (PSYSTEM_MODULE)ExAllocatePool(NonPagedPool, sizeof(SYSTEM_MODULE));
                RtlCopyMemory(FoundModule, SystemModule, sizeof(SYSTEM_MODULE));
                ExFreePool(Buffer);
                return FoundModule;
            }
        }
    }
    DbgPrint("Could not find the kernel in module list\n");
    return NULL;
}

PEPROCESS GetEPROCESSFromName(IN CONST CHAR *ImageName) {

    PEPROCESS ProcessHead = PsGetNextProcess(NULL);
    PEPROCESS Process = PsGetNextProcess(NULL);
    CHAR *ProcessName = NULL;

    do {
        ProcessName = PsGetProcessImageFileName(Process);
        DbgPrint("+ Currently looking at %s\n", ProcessName);
        if (strstr(ProcessName, ImageName) != NULL) {
            DbgPrint("+ Found the process -- %s\n", ProcessName);
            return Process;
        }
        Process = PsGetNextProcess(Process);
    } while (Process != NULL && Process != ProcessHead);
    DbgPrint("- Could not find %s\n", ProcessName);
    return NULL;
}

HANDLE GetProcessIdFromEPROCESS(PEPROCESS Process) {

    return PsGetProcessId(Process);
}

HANDLE OpenProcess(IN CONST CHAR *ProcessName, OUT OPTIONAL PEPROCESS *pProcess) {

    HANDLE ProcessHandle = NULL;
    CLIENT_ID ClientId = { 0 };
    OBJECT_ATTRIBUTES ObjAttributes = { 0 };
    PEPROCESS EProcess = GetEPROCESSFromName(ProcessName);
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (EProcess == NULL) {
        return NULL;
    }
    InitializeObjectAttributes(&ObjAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    ObjAttributes.ObjectName = NULL;
    ClientId.UniqueProcess = GetProcessIdFromEPROCESS(EProcess);
    ClientId.UniqueThread = NULL;

    Status = ZwOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjAttributes, &ClientId);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("- Could not open process %s. -- %X\n", ProcessName, Status);
        return NULL;
    }
    if (pProcess != NULL) {
        *pProcess = EProcess;
    }
    return ProcessHandle;
}

PVOID CreateSyscallWrapper(IN LONG Index, IN SHORT NumParameters) {

#ifdef _M_IX86
    SIZE_T StubLength = 0x15;
    PVOID Buffer = ExAllocatePool(NonPagedPool, StubLength);
    BYTE *SyscallIndex = ((BYTE *)Buffer) + sizeof(BYTE);
    BYTE *Retn = ((BYTE *)Buffer) + (0x13 * (sizeof(BYTE)));
    RtlCopyMemory(Buffer, SyscallTemplate, StubLength);
    NumParameters = NumParameters * sizeof(ULONG_PTR);
    RtlCopyMemory(SyscallIndex, &Index, sizeof(LONG));
    RtlCopyMemory(Retn, &NumParameters, sizeof(SHORT));
    return Buffer;
#elif defined(_M_AMD64)
    PVOID Buffer = ExAllocatePool(NonPagedPool, sizeof(SyscallTemplate));
    BYTE *NullStubAddress = &NullStub;
    BYTE *NullStubAddressIndex = ((BYTE *)Buffer) + (14 * sizeof(BYTE));
    BYTE *SyscallIndex = ((BYTE *)Buffer) + (24 * sizeof(BYTE));
    BYTE *LowBytesIndex = ((BYTE *)Buffer) + (29 * sizeof(BYTE));
    BYTE *HighBytesIndex = ((BYTE *)Buffer) + (37 * sizeof(BYTE));
    ULONG LowAddressBytes = ((ULONG_PTR)KiSystemService) & 0xFFFFFFFF;
    ULONG HighAddressBytes = ((ULONG_PTR)KiSystemService >> 32);
    RtlCopyMemory(Buffer, SyscallTemplate, sizeof(SyscallTemplate));
    RtlCopyMemory(NullStubAddressIndex, (PVOID)&NullStubAddress, sizeof(BYTE *));
    RtlCopyMemory(SyscallIndex, &Index, sizeof(LONG));
    RtlCopyMemory(LowBytesIndex, &LowAddressBytes, sizeof(ULONG));
    RtlCopyMemory(HighBytesIndex, &HighAddressBytes, sizeof(ULONG));
    return Buffer;
#endif
}

VOID InitializeSyscalls(VOID) {

#ifdef _M_IX86
    ZwSuspendProcess = (pZwSuspendProcess)CreateSyscallWrapper(0x00FD, 1);
    ZwResumeProcess = (pZwResumeProcess)CreateSyscallWrapper(0x00CD, 1);
    ZwProtectVirtualMemory = (pZwProtectVirtualMemory)CreateSyscallWrapper(0x0089, 5);
    ZwWriteVirtualMemory = (pZwWriteVirtualMemory)CreateSyscallWrapper(0x0115, 5);
#elif defined(_M_AMD64)
    ZwSuspendProcess = (pZwSuspendProcess)CreateSyscallWrapper(0x017A, 1);
    ZwResumeProcess = (pZwResumeProcess)CreateSyscallWrapper(0x0144, 1);
    ZwProtectVirtualMemory = (pZwProtectVirtualMemory)CreateSyscallWrapper(0x004D, 5);
    ZwWriteVirtualMemory = (pZwWriteVirtualMemory)CreateSyscallWrapper(0x0037, 5);
#endif
}

VOID FreeSyscalls(VOID) {

    ExFreePool(ZwSuspendProcess);
    ExFreePool(ZwResumeProcess);
    ExFreePool(ZwProtectVirtualMemory);
    ExFreePool(ZwWriteVirtualMemory);
}

PVOID GetProcessBaseAddress(IN PEPROCESS Process) {

    return PsGetProcessSectionBaseAddress(Process);
}

NTSTATUS WriteToProcessAddress(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN BYTE *NewBytes, IN SIZE_T NewBytesSize) {

    ULONG OldProtections = 0;
    SIZE_T BytesWritten = 0;
    SIZE_T NumBytesToProtect = NewBytesSize;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    //Needs error checking
    Status = ZwSuspendProcess(ProcessHandle);
    Status = ZwProtectVirtualMemory(ProcessHandle, &BaseAddress, &NumBytesToProtect, PAGE_EXECUTE_READWRITE, &OldProtections);
    Status = ZwWriteVirtualMemory(ProcessHandle, BaseAddress, NewBytes, NewBytesSize, &BytesWritten);
    Status = ZwProtectVirtualMemory(ProcessHandle, &BaseAddress, &NumBytesToProtect, OldProtections, &OldProtections);
    Status = ZwResumeProcess(ProcessHandle);

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath) {

    PSYSTEM_MODULE KernelInfo = NULL;
    PEPROCESS Process = NULL;
    HANDLE ProcessHandle = NULL;
    PVOID BaseAddress = NULL;
    BYTE NewBytes[0x100] = { 0 };
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    DbgPrint("+ Driver successfully loaded\n");

    DriverObject->DriverUnload = OnUnload;

    KernelInfo = GetKernelModuleInfo();
    if (KernelInfo == NULL) {
        DbgPrint("Could not find kernel module\n");
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrint("+ Found kernel module.\n"
        "+ Name: %s -- Base address: %p -- Size: %p\n", KernelInfo->Name,
        KernelInfo->ImageBaseAddress, KernelInfo->ImageSize);

    if (!NT_SUCCESS(ResolveFunctions(KernelInfo))) {
        return STATUS_UNSUCCESSFUL;
    }

    InitializeSyscalls();

    ProcessHandle = OpenProcess("notepad.exe", &Process);
    if (ProcessHandle == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    BaseAddress = GetProcessBaseAddress(Process);
    if (BaseAddress == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("Invoking\n");
    RtlFillMemory(NewBytes, sizeof(NewBytes), 0x90);
    (VOID)WriteToProcessAddress(ProcessHandle, BaseAddress, NewBytes, sizeof(NewBytes));
    DbgPrint("+ Done\n");

    ExFreePool(KernelInfo);
    FreeSyscalls();
    ZwClose(ProcessHandle);

    return STATUS_SUCCESS;
}