#include <ntifs.h>
#include <windef.h>
#include <ntimage.h>
#include <VMProtectDDK.h>
#include <capstone/capstone.h>
#include "Tools.h"
#include "Sssdt.h"
#include "Hook.h"
#include "Mutation.h"

// #pragma warning(disable:4024)
// #pragma warning(disable:4047)
// #pragma warning(disable:4242)
// #pragma warning(disable:4244)

#define BLOCK_KEY 2847263840

#define BUG

#pragma pack(4)

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		ULONG SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG LoadedImports;
	};
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

#pragma pack()

#pragma pack(8)

typedef struct _PROCESS_BASIC_INFORMATION64 {
	ULONG64 ExitStatus;
	ULONG64 PebBaseAddress;
	ULONG64 AffinityMask;
	ULONG64 BasePriority;
	ULONG64 UniqueProcessId;
	ULONG64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64, * PPROCESS_BASIC_INFORMATION64;

typedef struct _PEB64
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG64 Mutant;
	ULONG64 ImageBaseAddress;
	ULONG64 Ldr;
	ULONG64 ProcessParameters;
	ULONG64 SubSystemData;
	ULONG64 ProcessHeap;
	ULONG64 FastPebLock;
	ULONG64 AtlThunkSListPtr;
	ULONG64 IFEOKey;
	ULONG64 CrossProcessFlags;
	ULONG64 UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG64 ApiSetMap;
} PEB64, * PPEB64;

typedef struct _PEB_LDR_DATA64
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY64 HashLinks;
		ULONG64 SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG64 LoadedImports;
	};
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

#pragma pack()

typedef struct _READ_WRITE_DATA
{
	PVOID Address;
	PVOID Buffer;
	ULONG64 Size;
}READ_WRITE_DATA, * PREAD_WRITE_DATA;

typedef struct _tag_thread_info
{
	PETHREAD owning_thread;
}tag_thread_info, * Ptag_thread_info;

typedef struct _tag_wnd
{
	char pad_0[0x10];
	tag_thread_info* thread_info;
}tag_wnd, * Ptag_wnd;

typedef struct _generic_thread_ctx_t
{
	ULONG64 window_handle;
	ULONG64 thread_pointer;
	ULONG64 isget;
}generic_thread_ctx_t;