#ifndef _HOOK_H_
#define _HOOK_H_

typedef struct _BLOCK
{
	LONG
	(CDECL* DbgPrint)(
	IN  PCSTR Format,
	...
		);
	VOID
	(NTAPI* IofCompleteRequest)(
		IN PIRP Irp,
		IN CCHAR PriorityBoost
		);
	PVOID
	(NTAPI* ExAllocatePool)(
		IN POOL_TYPE PoolType, 
		IN SIZE_T NumberOfBytes
		);
	VOID
	(NTAPI* ExFreePoolWithTag)(
		IN PVOID P,
		IN ULONG Tag
		);
	PKTHREAD
	(NTAPI* KeGetCurrentThread)(
		VOID
		);
	PEPROCESS
	(NTAPI* IoThreadToProcess)(
		IN PETHREAD Thread
		);
	NTSTATUS
	(NTAPI* PsLookupThreadByThreadId)(
		IN HANDLE ThreadId,
		OUT PETHREAD* Thread
		);
	LONG_PTR
	(NTAPI* ObfDereferenceObject)(
		IN PVOID Object
		);
	PVOID
	(NTAPI* PsGetThreadWin32Thread)(
		IN PETHREAD Thread
		);
	PVOID
	(NTAPI* PsSetThreadWin32Thread)(
		IN PETHREAD Thread,
		IN PVOID Win32Thread
		);
	VOID
	(NTAPI* KeStackAttachProcess)(
		IN PRKPROCESS PROCESS,
		OUT PRKAPC_STATE ApcState
		);
	VOID
	(NTAPI* KeUnstackDetachProcess)(
		IN PRKAPC_STATE ApcState
		);
	KIRQL
	(NTAPI* KeGetCurrentIrql)(
		VOID);
	NTSTATUS
	(NTAPI* MmCopyVirtualMemory)(
		IN PEPROCESS FromProcess,
		IN PVOID FromAddress,
		IN PEPROCESS ToProcess,
		OUT PVOID ToAddress,
		IN SIZE_T BufferSize,
		IN KPROCESSOR_MODE PreviousMode,
		OUT PSIZE_T NumberOfBytesCopied
		);
	NTSTATUS
	(NTAPI* PsLookupProcessByProcessId)(
		IN HANDLE ProcessId,
		OUT PEPROCESS* Process
		);
	PVOID
	(NTAPI* PsGetProcessPeb)(
		IN PEPROCESS Process
		);
	PVOID
	(NTAPI* PsGetProcessWow64Process)(
		IN PEPROCESS Process
		);
	PEPROCESS
	(NTAPI* PsGetCurrentProcess)(
		VOID
		);
	PWCHAR
	(CDECL* wcsstr)(
		IN CONST PWCHAR _Str,
		IN CONST PWCHAR _SubStr
		);
	PWCHAR
	(CDECL* wcslwr)(
		IN PWCHAR _Str
		);
	PVOID
	(CDECL* memcpy)(
		OUT PVOID _Dst,
		IN PVOID _Src,
		IN SIZE_T _MaxCount
		);
	PVOID
	(CDECL* memset)(
		OUT PVOID _Dst,
		IN INT _Val,
		IN SIZE_T _Size
		);
	KIRQL
	(NTAPI* KeRaiseIrqlToDpcLevel)(
		VOID
		);
	NTSTATUS
	(NTAPI* ZwAllocateVirtualMemory)(
		IN HANDLE ProcessHandle,
		OUT PVOID* BaseAddress,
		IN ULONG_PTR ZeroBits,
		OUT PSIZE_T RegionSize,
		IN ULONG AllocationType,
		IN ULONG Protect
		);
	PMDL
	(NTAPI* IoAllocateMdl)(
		IN PVOID VirtualAddress,
		IN ULONG Length,
		IN BOOLEAN SecondaryBuffer,
		IN BOOLEAN ChargeQuota,
		OUT PIRP Irp
		);
	VOID
	(NTAPI* MmProbeAndLockPages)(
		IN PMDL MemoryDescriptorList,
		IN KPROCESSOR_MODE AccessMode,
		IN LOCK_OPERATION Operation
		);
	PVOID
	(NTAPI* MmMapLockedPagesSpecifyCache)(
		IN PMDL MemoryDescriptorList, 
		IN KPROCESSOR_MODE AccessMode,
		IN MEMORY_CACHING_TYPE CacheType,
		IN PVOID RequestedAddress,
		IN ULONG BugCheckOnFailure,
		IN ULONG Priority
		);
	VOID
	(NTAPI* MmUnlockPages)(
		IN PMDL MemoryDescriptorList
		);
	VOID
	(NTAPI* MmBuildMdlForNonPagedPool)(
		IN PMDL MemoryDescriptorList
		);
	PVOID
	(NTAPI* MmMapLockedPages)(
		IN PMDL MemoryDescriptorList,
		IN KPROCESSOR_MODE AccessMode
		);
	VOID
	(NTAPI* MmUnmapLockedPages)(
		IN PVOID BaseAddress,
		OUT PMDL MemoryDescriptorList
		);
	VOID
	(NTAPI* IoFreeMdl)(
		IN PMDL Mdl
		);
	PHYSICAL_ADDRESS
	(NTAPI* MmGetPhysicalAddress)(
		IN PVOID BaseAddress
		);
	BOOLEAN
	(NTAPI*	MmIsAddressValid)(
		IN PVOID VirtualAddress
		);
	ULONG64
	(NTAPI* ValidateHwnd)(
		PVOID a1
		);
	INT
	(CDECL* wcsnicmp)(
		IN CONST PWCHAR _Str1,
		IN CONST PWCHAR _Str2,
		IN SIZE_T _MaxCount
		);
	INT
	(CDECL* strnicmp)(
		IN CONST PCHAR _Str1,
		IN CONST PCHAR _Str2,
		IN SIZE_T _MaxCount
		);
	ULONG
	(NTAPI* NtUserQueryWindow)(
		ULONG hWnd,
		ULONG Index
		);
	BOOLEAN
	(NTAPI* NtUserSetWindowDisplayAffinity)(
		ULONG hWnd,
		ULONG dwAffinity
		);
	NTSTATUS
	(NTAPI* ZwQueryVirtualMemory)(
		IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
		OUT PVOID MemoryInformation, 
		IN SIZE_T MemoryInformationLength, 
		OUT PSIZE_T ReturnLength
		);

	PEPROCESS Process;
	PMM_UNLOADED_DRIVER MmUnloadedDrivers;
	ULONG64 MmLastUnloadedDriver;
	ULONG64 CurrentModuleBase;

}BLOCK, *PBLOCK;

BOOLEAN
NTAPI
Hook(
	VOID
);

extern PBLOCK CodeBlock;

#endif