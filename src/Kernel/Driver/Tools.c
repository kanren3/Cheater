#include "Sword.h"

PVOID
NTAPI
GetProcAddress(
	IN LPCWSTR ProcName
)
{
	PVOID Address = NULL;
	UNICODE_STRING RoutineName;

	RtlInitUnicodeString(&RoutineName, ProcName);
	Address = MmGetSystemRoutineAddress(&RoutineName);

//	DbgPrint("%S--%p\n", ProcName, Address);

	return Address;
}

BOOLEAN
NTAPI
SetDeviceControl(
	IN PDRIVER_DISPATCH Address
)
{
	UNICODE_STRING DriverName = { 0 };
	PDRIVER_OBJECT DriverObject = NULL;

	RtlInitUnicodeString(&DriverName, L"\\Driver\\QMTclsDriver64");

	ObReferenceObjectByName(
		&DriverName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode, NULL,
		(PVOID*)&DriverObject);

	if (DriverObject)
	{
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Address;
		return TRUE;
	}
	return FALSE;
}

PVOID
NTAPI
GetDeviceControl(
	VOID
)
{
	UNICODE_STRING DriverName = { 0 };
	PDRIVER_OBJECT DriverObject = NULL;

	RtlInitUnicodeString(&DriverName, L"\\Driver\\WeGameDriver764");

	ObReferenceObjectByName(
		&DriverName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode, NULL,
		(PVOID*)&DriverObject);

	if (DriverObject)
	{
		return (PVOID)DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	}
	return NULL;
}

PVOID
NTAPI
ImgGetBaseAddress(
	IN	LPCSTR ImageName,
	OUT	PULONG SizeOfImage
)
{
	NTSTATUS Status = STATUS_SUCCESS;

	PVOID Buffer = NULL;
	ULONG SizeOfBuffer = 0;

	ULONG ReturnLength = 0;

	do
	{
		Status = ZwQuerySystemInformation(
			SystemModuleInformation,
			Buffer,
			SizeOfBuffer,
			&ReturnLength
		);

		if (NT_SUCCESS(Status))
		{
			break;
		}

		else if (Status == STATUS_INFO_LENGTH_MISMATCH || Status == STATUS_BUFFER_TOO_SMALL)
		{
			SizeOfBuffer = ReturnLength;

			if (Buffer)
			{
				ExFreePool(Buffer);
				Buffer = NULL;
			}

			Buffer = ExAllocatePool(NonPagedPool, SizeOfBuffer);
			if (!Buffer)
			{
				break;
			}
		}
		else
		{
			break;
		}
	} while (TRUE);

	if (!Buffer)
	{
		return NULL;
	}

	PRTL_PROCESS_MODULES SystemModules = (PRTL_PROCESS_MODULES)Buffer;

	for (ULONG i = 0; i < SystemModules->NumberOfModules; ++i)
	{
		PRTL_PROCESS_MODULE_INFORMATION ModuleInformation = &SystemModules->Modules[i];

		if (!ImageName || !_stricmp(ImageName, (LPCSTR)&ModuleInformation->FullPathName[ModuleInformation->OffsetToFileName]))
		{
			if (SizeOfImage)
			{
				*SizeOfImage = ModuleInformation->ImageSize;
			}
			PVOID ImageBase = ModuleInformation->ImageBase;
			ExFreePool(Buffer);
			return ImageBase;
		}
	}

	ExFreePool(Buffer);
	return NULL;
}

PVOID
NTAPI
ImgGetImageSection(
	IN PVOID	ImageBase,
	IN LPCSTR	SectionName,
	OUT PULONG	SizeOfSection
)
{
	PIMAGE_NT_HEADERS64 NtHeaders = RtlImageNtHeader(ImageBase);

	if (!NtHeaders)
	{
		return NULL;
	}

	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);

	for (USHORT i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++SectionHeader)
	{
		if (!_strnicmp((const char*)SectionHeader->Name, SectionName, IMAGE_SIZEOF_SHORT_NAME))
		{
			if (SizeOfSection)
			{
				*SizeOfSection = SectionHeader->SizeOfRawData;
			}

			return (PVOID)((ULONG64)ImageBase + SectionHeader->VirtualAddress);
		}
	}

	return NULL;
}

BOOLEAN
NTAPI
RtlSuperCopyMemory(
	IN PVOID Destination,
	IN PVOID Source,
	IN ULONG Length
)
{
	PMDL g_pmdl = IoAllocateMdl(Destination, Length, 0, 0, NULL);
	if (!g_pmdl)
		return FALSE;

	MmBuildMdlForNonPagedPool(g_pmdl);
	PVOID Mapped = MmMapLockedPages(g_pmdl, KernelMode);
	if (!Mapped)
	{
		IoFreeMdl(g_pmdl);
		return FALSE;
	}

	KIRQL kirql = KeRaiseIrqlToDpcLevel();
	RtlCopyMemory(Mapped, Source, Length);
	KeLowerIrql(kirql);

	MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
	IoFreeMdl(g_pmdl);
	return TRUE;
}

KIRQL
NTAPI
CloseProtect(
	VOID
)
{
	KIRQL  irql = KeRaiseIrqlToDpcLevel();
	UINT64  cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return  irql;
}

VOID
NTAPI
OpenProtect(
	IN KIRQL irql
)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

ULONG
NTAPI
GetDwmProcessId(
	VOID
)
{
	ULONG ProcessId = 0;
	PEPROCESS DwmProcess = NULL;
	for (size_t i = 0xFFFF; i > 1; i--)
	{
		ProcessId = i * 4;
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)ProcessId, &DwmProcess)))
		{
			char* ProcessName = PsGetProcessImageFileName(DwmProcess);
			ObfDereferenceObject(DwmProcess);
			if (!_stricmp("dwm.exe", ProcessName))
			{
				return ProcessId;
			}
		}
	}
	return 0;
}

ULONG
NTAPI
GetNtFunctionsIndex(
	IN CONST PCHAR Name,
	IN PCWSTR Path
)
{
	NTSTATUS Status;

	UNICODE_STRING SourceString;
	OBJECT_ATTRIBUTES  ObjectAttributes;
	HANDLE hFile = NULL, hSection = NULL;
	IO_STATUS_BLOCK IOStatus = { 0 };

	SIZE_T MapSize = 0;
	ULONG64 ImageBase = 0;

	PIMAGE_DOS_HEADER DosHeader = NULL;
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportTable = NULL;

	ULONG Index;
	ULONG NtIndex = 0;


	RtlInitUnicodeString(&SourceString, Path);

	InitializeObjectAttributes(
		&ObjectAttributes,
		&SourceString,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	Status = ZwCreateFile(
		&hFile,
		FILE_EXECUTE | SYNCHRONIZE,
		&ObjectAttributes,
		&IOStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE |
		FILE_RANDOM_ACCESS |
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);

	if (!NT_SUCCESS(Status))
	{
		return 0;
	}

	InitializeObjectAttributes(
		&ObjectAttributes,
		NULL,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	Status = ZwCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		&ObjectAttributes,
		0,
		PAGE_EXECUTE,
		0x01000000,
		hFile
	);

	if (!NT_SUCCESS(Status))
	{
		ZwClose(hFile);
		return 0;
	}

	Status = ZwMapViewOfSection(
		hSection,
		NtCurrentProcess(),
		(PVOID*)&ImageBase,
		0,
		1000,
		0,
		&MapSize,
		(SECTION_INHERIT)1,
		MEM_TOP_DOWN,
		PAGE_READWRITE
	);

	if (!NT_SUCCESS(Status))
	{
		ZwClose(hSection);
		ZwClose(hFile);
		return 0;
	}

	DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	NtHeader = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
	ExportTable = (PIMAGE_EXPORT_DIRECTORY)(NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + ImageBase);

	for (Index = 0; Index < ExportTable->NumberOfNames; Index++)
	{
		PULONG AddressOfNames = (PULONG)(ExportTable->AddressOfNames + ImageBase + Index * 4);
		PULONG AddressOfFunctions = (PULONG)(ImageBase + ExportTable->AddressOfFunctions);
		PSHORT AddressOfNameOrdinals = (PSHORT)(ImageBase + ExportTable->AddressOfNameOrdinals);

		ULONG FunctionIndex = AddressOfNameOrdinals[Index];
		ULONG64 FunctionAddress = AddressOfFunctions[FunctionIndex] + ImageBase;
		PCHAR FunctionName = (PCHAR)(*AddressOfNames + ImageBase);

		if (FunctionAddress)
		{
			if (FunctionName)
			{
				if (!strnicmp(FunctionName, Name, 64))
				{
					NtIndex = *(PULONG)(FunctionAddress + 4);
					break;
				}
			}
		}
	}

	ZwUnmapViewOfSection(NtCurrentProcess(), (PVOID)ImageBase);
	ZwClose(hSection);
	ZwClose(hFile);
	return NtIndex;
}

ULONG64
NTAPI
GetFunctionsAddress(
	IN CONST PCHAR Name,
	IN PCWSTR Path
)
{
	NTSTATUS Status;

	UNICODE_STRING SourceString;
	OBJECT_ATTRIBUTES  ObjectAttributes;
	HANDLE hFile = NULL, hSection = NULL;
	IO_STATUS_BLOCK IOStatus = { 0 };

	SIZE_T MapSize = 0;
	ULONG64 ImageBase = 0;

	PIMAGE_DOS_HEADER DosHeader = NULL;
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportTable = NULL;

	ULONG Index;
	ULONG64 Address = 0;


	RtlInitUnicodeString(&SourceString, Path);

	InitializeObjectAttributes(
		&ObjectAttributes,
		&SourceString,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	Status = ZwCreateFile(
		&hFile,
		FILE_EXECUTE | SYNCHRONIZE,
		&ObjectAttributes,
		&IOStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE |
		FILE_RANDOM_ACCESS |
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);

	if (!NT_SUCCESS(Status))
	{
		return 0;
	}

	InitializeObjectAttributes(
		&ObjectAttributes,
		NULL,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	Status = ZwCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		&ObjectAttributes,
		0,
		PAGE_EXECUTE,
		0x01000000,
		hFile
	);

	if (!NT_SUCCESS(Status))
	{
		ZwClose(hFile);
		return 0;
	}

	Status = ZwMapViewOfSection(
		hSection,
		NtCurrentProcess(),
		(PVOID*)&ImageBase,
		0,
		1000,
		0,
		&MapSize,
		(SECTION_INHERIT)1,
		MEM_TOP_DOWN,
		PAGE_READWRITE
	);

	if (!NT_SUCCESS(Status))
	{
		ZwClose(hSection);
		ZwClose(hFile);
		return 0;
	}

	DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	NtHeader = (PIMAGE_NT_HEADERS)(ImageBase + DosHeader->e_lfanew);
	ExportTable = (PIMAGE_EXPORT_DIRECTORY)(NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + ImageBase);

	for (Index = 0; Index < ExportTable->NumberOfNames; Index++)
	{
		PULONG AddressOfNames = (PULONG)(ExportTable->AddressOfNames + ImageBase + Index * 4);
		PULONG AddressOfFunctions = (PULONG)(ImageBase + ExportTable->AddressOfFunctions);
		PSHORT AddressOfNameOrdinals = (PSHORT)(ImageBase + ExportTable->AddressOfNameOrdinals);

		ULONG FunctionIndex = AddressOfNameOrdinals[Index];
		ULONG64 FunctionAddress = AddressOfFunctions[FunctionIndex] + ImageBase;

		PCHAR FunctionName = (PCHAR)(*AddressOfNames + ImageBase);

//		DbgPrint("Name:%s  0x%llX  %d\n", FunctionName, FunctionAddress, *(PULONG)(FunctionAddress + 4));

		if (!strnicmp(FunctionName, Name, 64))
		{
			Address = FunctionAddress;
			break;
		}
	}

	ZwUnmapViewOfSection(NtCurrentProcess(), (PVOID)ImageBase);
	ZwClose(hSection);
	ZwClose(hFile);
	return Address;
}

NTSTATUS
SearchPattern(
	IN PCUCHAR pattern,
	IN UCHAR wildcard,
	IN ULONG64 len,
	IN PVOID base,
	IN ULONG64 size,
	OUT PVOID* ppFound
)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

ULONG
NTAPI
CheckSystemVersion(
	VOID
)
{
	ULONG ulBuildNumber = 0;
	RTL_OSVERSIONINFOW	osi;

	osi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	RtlFillMemory(&osi, sizeof(RTL_OSVERSIONINFOW), 0);
	RtlGetVersion(&osi);
	ulBuildNumber = osi.dwBuildNumber;
	return ulBuildNumber;
}

ULONG64
NTAPI
GetMmUnloadedDrivers(
	VOID
)
{
	CONTEXT Context = { 0 };
	PKDDEBUGGER_DATA64 KdDebuggerDataBlock = NULL;
	PVOID DumpHeader = NULL;

	Context.ContextFlags = CONTEXT_FULL;
	RtlCaptureContext(&Context);

	DumpHeader = ExAllocatePool(NonPagedPool, 0x40000);

	KeCapturePersistentThreadState(
		&Context,
		NULL,
		0,
		0,
		0,
		0,
		0,
		DumpHeader);

	KdDebuggerDataBlock = (PKDDEBUGGER_DATA64)((PCHAR)DumpHeader + KDDEBUGGER_DATA_OFFSET);

	return KdDebuggerDataBlock->MmUnloadedDrivers;
}

ULONG64
NTAPI
GetMmLastUnloadedDriver(
	VOID
)
{
	CONTEXT Context = { 0 };
	PKDDEBUGGER_DATA64 KdDebuggerDataBlock = NULL;
	PVOID DumpHeader = NULL;

	Context.ContextFlags = CONTEXT_FULL;
	RtlCaptureContext(&Context);

	DumpHeader = ExAllocatePool(NonPagedPool, 0x40000);

	KeCapturePersistentThreadState(
		&Context,
		NULL,
		0,
		0,
		0,
		0,
		0,
		DumpHeader);

	KdDebuggerDataBlock = (PKDDEBUGGER_DATA64)((PCHAR)DumpHeader + KDDEBUGGER_DATA_OFFSET);

//  	DbgPrint(
// 		"KdDebuggerDataBlock->MmLastUnloadedDriver:%llX\n",
// 		KdDebuggerDataBlock->MmLastUnloadedDriver);

	return KdDebuggerDataBlock->MmLastUnloadedDriver;
}