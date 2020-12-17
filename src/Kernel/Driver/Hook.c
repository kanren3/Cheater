#include "Sword.h"

PBLOCK CodeBlock = NULL;

VOID
NTAPI
DeviceControl(
	IN PIRP Irp,
	IN CCHAR PriorityBoost,
	IN PBLOCK DecryptBlock
)
{
	ULONG DecryptIndex = 0;
	BLOCK BlockMem;
	PBLOCK Block = NULL;
	PULONG64 BlockTemp = NULL;

	PIO_STACK_LOCATION IrpSp = NULL;
	ULONG64 Status = 0;
	ULONG XorIndex = 0;

	ULONG64 ProcessId = 0;
	READ_WRITE_DATA ReadWriteData;
	SIZE_T NumberOfBytesCopied = 0;

	PMDL pMDL = NULL;
	PVOID MAPAddress = NULL;
	PVOID DataBuffer = NULL;

	WCHAR ModuleName[256];
	WCHAR Name[256];
	KAPC_STATE KAPC;
	PPEB32 peb32 = NULL;
	PPEB64 peb64 = NULL;
	PPEB_LDR_DATA32 ldr32 = NULL;
	PPEB_LDR_DATA64 ldr64 = NULL;
	PLDR_DATA_TABLE_ENTRY32 LdrEntry32 = NULL;
	PLDR_DATA_TABLE_ENTRY64 LdrEntry64 = NULL;
	PLIST_ENTRY32 EntryStart32 = NULL;
	PLIST_ENTRY32 EntryEnd32 = NULL;
	PLIST_ENTRY64 EntryStart64 = NULL;
	PLIST_ENTRY64 EntryEnd64 = NULL;
	ULONG64 ModuleBase = 0;

	ULONG64 AllocSize = 0;
	ULONG64 AllocAddress = 0;

	PETHREAD WindowThread = NULL;
	PEPROCESS WindowProcess = NULL;
	ULONG64 WindowHWnd = 0;
	PVOID OldWindowThread = NULL;

	ULONG UnLoadedCount = 0;
	ULONG Index = 0;

	PVOID QueryAddress = 0;
	MEMORY_BASIC_INFORMATION BasicInformation;

	Block = &BlockMem;
	BlockTemp = (PULONG64)DecryptBlock;

	for (DecryptIndex = 0; DecryptIndex < sizeof(BLOCK) / 8; DecryptIndex++)
	{		
		((PULONG64)Block)[DecryptIndex] = BlockTemp[DecryptIndex] ^ BLOCK_KEY;
	}

	Block->memset(&ReadWriteData, 0, sizeof(ReadWriteData));
	Block->memset(ModuleName, 0, sizeof(ModuleName));
	Block->memset(Name, 0, sizeof(Name));
	Block->memset(&KAPC, 0, sizeof(KAPC));
	Block->memset(&BasicInformation, 0, sizeof(MEMORY_BASIC_INFORMATION));

	IrpSp = Irp->Tail.Overlay.CurrentStackLocation;

	if (IrpSp->Parameters.DeviceIoControl.IoControlCode >= 0x722000)
	{
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	}

	if (Block->KeGetCurrentIrql() == PASSIVE_LEVEL)
	{

		if (IrpSp->Parameters.DeviceIoControl.IoControlCode == 0x722020)
		{
			for (XorIndex = 0; XorIndex < IrpSp->Parameters.DeviceIoControl.InputBufferLength; XorIndex++)
			{
				((PUCHAR)&ProcessId)[XorIndex] = ((PUCHAR)Irp->AssociatedIrp.SystemBuffer)[XorIndex] ^ 69;
			}
			if (ProcessId)
			{
				if (NT_SUCCESS(Block->PsLookupProcessByProcessId((HANDLE)ProcessId, &Block->Process)))
				{
					Block->ObfDereferenceObject(Block->Process);
					DecryptBlock->Process = (PEPROCESS)((ULONG64)Block->Process ^ BLOCK_KEY);
				}
			}
		}

		if (IrpSp->Parameters.DeviceIoControl.IoControlCode == 0x722030)
		{
			for (XorIndex = 0; XorIndex < IrpSp->Parameters.DeviceIoControl.InputBufferLength; XorIndex++)
			{
				((PUCHAR)&ReadWriteData)[XorIndex] = ((PUCHAR)Irp->AssociatedIrp.SystemBuffer)[XorIndex] ^ 69;
			}
			if (Block->Process && 
				ReadWriteData.Address > (PVOID)0x10000 && 
				ReadWriteData.Address < (PVOID)0x7FFFFFFFFFFF)
			{
				Irp->IoStatus.Status = Block->MmCopyVirtualMemory(
					Block->Process,
					ReadWriteData.Address,
					Block->PsGetCurrentProcess(),
					ReadWriteData.Buffer,
					ReadWriteData.Size,
					KernelMode,
					&NumberOfBytesCopied
				);
			}
		}

		if (IrpSp->Parameters.DeviceIoControl.IoControlCode == 0x722040)
		{
			for (XorIndex = 0; XorIndex < IrpSp->Parameters.DeviceIoControl.InputBufferLength; XorIndex++)
			{
				((PUCHAR)&ReadWriteData)[XorIndex] = ((PUCHAR)Irp->AssociatedIrp.SystemBuffer)[XorIndex] ^ 69;
			}
			if (Block->Process &&
				ReadWriteData.Address > (PVOID)0x10000 &&
				ReadWriteData.Address < (PVOID)0x7FFFFFFFFFFF)
			{
				Irp->IoStatus.Status = Block->MmCopyVirtualMemory(
					Block->PsGetCurrentProcess(),
					ReadWriteData.Buffer,
					Block->Process,
					ReadWriteData.Address,
					ReadWriteData.Size,
					KernelMode,
					&NumberOfBytesCopied
				);
			}
		}

		if (IrpSp->Parameters.DeviceIoControl.IoControlCode == 0x722050)
		{
			for (XorIndex = 0; XorIndex < IrpSp->Parameters.DeviceIoControl.InputBufferLength; XorIndex++)
			{
				((PUCHAR)&ReadWriteData)[XorIndex] = ((PUCHAR)Irp->AssociatedIrp.SystemBuffer)[XorIndex] ^ 69;
			}
			if (Block->Process &&
				ReadWriteData.Address > (PVOID)0x10000 &&
				ReadWriteData.Address < (PVOID)0x7FFFFFFFFFFF)
			{
				DataBuffer = Block->ExAllocatePool(NonPagedPool, ReadWriteData.Size);
				Block->memcpy(DataBuffer, ReadWriteData.Buffer, ReadWriteData.Size);
				Block->KeStackAttachProcess(Block->Process, &KAPC);

				pMDL = Block->IoAllocateMdl(
					ReadWriteData.Address,
					(ULONG)ReadWriteData.Size,
					0, 0, NULL
				);
				if (pMDL)
				{
					Block->MmBuildMdlForNonPagedPool(pMDL);
					Block->MmProbeAndLockPages(pMDL, KernelMode, IoReadAccess);
					MAPAddress = Block->MmMapLockedPagesSpecifyCache(
						pMDL,
						KernelMode,
						MmCached, 
						NULL, 0,
						NormalPagePriority
					);
					if (MAPAddress)
					{
						Block->memset(MAPAddress, 0, ReadWriteData.Size);
						Block->memcpy(MAPAddress, DataBuffer, ReadWriteData.Size);
						Block->MmUnmapLockedPages(MAPAddress, pMDL);
						Irp->IoStatus.Status = STATUS_SUCCESS;
					}
					Block->MmUnlockPages(pMDL);
					Block->IoFreeMdl(pMDL);
				}
				Block->KeUnstackDetachProcess(&KAPC);
				Block->ExFreePoolWithTag(DataBuffer, 0);
			}
		}

		if (IrpSp->Parameters.DeviceIoControl.IoControlCode == 0x722060)
		{
			if (Block->Process)
			{
				for (XorIndex = 0; XorIndex < IrpSp->Parameters.DeviceIoControl.InputBufferLength; XorIndex++)
				{
					((PUCHAR)Name)[XorIndex] = ((PUCHAR)Irp->AssociatedIrp.SystemBuffer)[XorIndex] ^ 69;
				}

				peb64 = Block->PsGetProcessPeb(Block->Process);
				peb32 = Block->PsGetProcessWow64Process(Block->Process);

				Block->KeStackAttachProcess(Block->Process, &KAPC);

				if (peb32)
				{
					ldr32 = (PPEB_LDR_DATA32)peb32->Ldr;
					if (ldr32)
					{
						EntryStart32 = EntryEnd32 = (PLIST_ENTRY32)ldr32->InMemoryOrderModuleList.Flink;
						if (EntryStart32)
						{
							do
							{
								Block->memset(ModuleName, 0, sizeof(ModuleName));
								LdrEntry32 = (PLDR_DATA_TABLE_ENTRY32)
									CONTAINING_RECORD(
										EntryStart32,
										LDR_DATA_TABLE_ENTRY32,
										InMemoryOrderModuleList
									);
								if (LdrEntry32)
								{
									Block->memcpy(
										ModuleName,
										(PVOID)LdrEntry32->BaseDllName.Buffer,
										LdrEntry32->BaseDllName.Length
									);
									if (!Block->wcsnicmp(ModuleName, Name, 64))
									{
										ModuleBase = LdrEntry32->DllBase;
										break;
									}
								}
								EntryStart32 = (PLIST_ENTRY32)EntryStart32->Flink;
							} while (EntryStart32 != EntryEnd32);
						}
					}
				}

				if (peb64 && !ModuleBase)
				{
					ldr64 = (PPEB_LDR_DATA64)peb64->Ldr;
					if (ldr64)
					{
						EntryStart64 = EntryEnd64 = (PLIST_ENTRY64)ldr64->InMemoryOrderModuleList.Flink;
						if (EntryStart64)
						{
							do
							{
								Block->memset(ModuleName, 0, sizeof(ModuleName));
								LdrEntry64 = (PLDR_DATA_TABLE_ENTRY64)
									CONTAINING_RECORD(
										EntryStart64,
										LDR_DATA_TABLE_ENTRY64,
										InMemoryOrderModuleList
									);
								if (LdrEntry64)
								{
									Block->memcpy(
										ModuleName,
										(PVOID)LdrEntry64->BaseDllName.Buffer,
										LdrEntry64->BaseDllName.Length
									);
									if (!Block->wcsnicmp(ModuleName, Name, 64))
									{
										ModuleBase = LdrEntry64->DllBase;
										break;
									}
								}
								EntryStart64 = (PLIST_ENTRY64)EntryStart64->Flink;
							} while (EntryStart64 != EntryEnd64);
						}
					}
				}

				Block->KeUnstackDetachProcess(&KAPC);

				if (ModuleBase)
				{
					for (XorIndex = 0; XorIndex < 8; XorIndex++)
					{
						((PUCHAR)Irp->AssociatedIrp.SystemBuffer)[XorIndex]= ((PUCHAR)&ModuleBase)[XorIndex] ^ 69;
					}
					Irp->IoStatus.Information = 8;
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}
			}
		}

		if (IrpSp->Parameters.DeviceIoControl.IoControlCode == 0x722070)
		{
			AllocSize = *(PULONG64)Irp->AssociatedIrp.SystemBuffer;
			if (AllocSize)
			{
				Block->KeStackAttachProcess(Block->Process, &KAPC);
				
				Block->ZwAllocateVirtualMemory(
					(HANDLE)-1,
					(PVOID*)&AllocAddress,
					0,
					&AllocSize,
					MEM_COMMIT,
					PAGE_EXECUTE_READWRITE
				);

				Block->KeUnstackDetachProcess(&KAPC);

				if (AllocAddress)
				{
					for (XorIndex = 0; XorIndex < 8; XorIndex++)
					{
						((PUCHAR)Irp->AssociatedIrp.SystemBuffer)[XorIndex] = ((PUCHAR)&AllocAddress)[XorIndex] ^ 69;
					}
					Irp->IoStatus.Information = 8;
					Irp->IoStatus.Status = STATUS_SUCCESS;
				}
			}
		}

		if (IrpSp->Parameters.DeviceIoControl.IoControlCode == 0x722080)
		{
			WindowHWnd = *(PULONG64)Irp->AssociatedIrp.SystemBuffer ^ 69;
			if (WindowHWnd && Block->NtUserQueryWindow && Block->NtUserSetWindowDisplayAffinity)
			{
				if (NT_SUCCESS(
					Block->PsLookupThreadByThreadId(
					(HANDLE)Block->NtUserQueryWindow((ULONG)WindowHWnd, 2),
					&WindowThread))
					)
				{
					WindowProcess = Block->IoThreadToProcess(WindowThread);
					Block->KeStackAttachProcess(WindowProcess, &KAPC);

					OldWindowThread = Block->PsGetThreadWin32Thread(Block->KeGetCurrentThread());
					Block->PsSetThreadWin32Thread(Block->KeGetCurrentThread(), Block->PsGetThreadWin32Thread(WindowThread));
					if (Block->NtUserSetWindowDisplayAffinity((ULONG)WindowHWnd, 1))
					{
						Irp->IoStatus.Status = STATUS_SUCCESS;
					}
					Block->PsSetThreadWin32Thread(Block->KeGetCurrentThread(), OldWindowThread);

					Block->KeUnstackDetachProcess(&KAPC);
					Block->ObfDereferenceObject(WindowThread);
				}
			}
		}

		if (IrpSp->Parameters.DeviceIoControl.IoControlCode == 0x722090)
		{
			if (Block->ValidateHwnd)
			{
				generic_thread_ctx_t curr_request;
				Ptag_wnd window_instance = NULL;

				Block->memcpy(&curr_request, Irp->AssociatedIrp.SystemBuffer, sizeof(generic_thread_ctx_t));
				curr_request.window_handle ^= 69;

				window_instance = (Ptag_wnd)Block->ValidateHwnd((void*)curr_request.window_handle);
				if (window_instance && window_instance->thread_info->owning_thread)
				{
					if (curr_request.isget)
					{
						curr_request.thread_pointer = (ULONG64)window_instance->thread_info->owning_thread;
					}
					else
					{
						window_instance->thread_info->owning_thread = (PETHREAD)curr_request.thread_pointer;
					}
				}
				Block->memcpy(Irp->AssociatedIrp.SystemBuffer, &curr_request, sizeof(generic_thread_ctx_t));
				Irp->IoStatus.Information = sizeof(generic_thread_ctx_t);
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
		}

		if (IrpSp->Parameters.DeviceIoControl.IoControlCode == 0x7220A0)
		{
			if (Block->MmUnloadedDrivers && Block->MmLastUnloadedDriver && Block->CurrentModuleBase)
			{
				UnLoadedCount = *(PULONG)Block->MmLastUnloadedDriver;

				for (Index = 0; Index < UnLoadedCount; Index++)
				{
					if ((ULONG64)Block->MmUnloadedDrivers[Index].ModuleStart == Block->CurrentModuleBase)
					{
						if (Block->MmUnloadedDrivers[Index + 1].ModuleStart == 0)
						{
							Block->memset(&Block->MmUnloadedDrivers[Index], 0, sizeof(MM_UNLOADED_DRIVER));
						}
						else
						{
							while (true)
							{
								if (Block->MmUnloadedDrivers[Index + 1].ModuleStart)
								{
									Block->MmUnloadedDrivers[Index] = Block->MmUnloadedDrivers[Index + 1];
									Index++;
								}
								else
								{
									Block->memset(&Block->MmUnloadedDrivers[Index], 0, sizeof(MM_UNLOADED_DRIVER));
									break;
								}
							}
						}
						*(PULONG)Block->MmLastUnloadedDriver = UnLoadedCount - 1;
					}
				}
			}
		}

		if (IrpSp->Parameters.DeviceIoControl.IoControlCode == 0x7220B0)
		{
			QueryAddress = *(PVOID*)Irp->AssociatedIrp.SystemBuffer;
			if (QueryAddress)
			{
				Block->KeStackAttachProcess(Block->Process, &KAPC);
				
				Block->ZwQueryVirtualMemory(
					(HANDLE)-1,
					QueryAddress,
					MemoryBasicInformation,
					&BasicInformation,
					sizeof(MEMORY_BASIC_INFORMATION),
					&NumberOfBytesCopied
				);

				Block->KeUnstackDetachProcess(&KAPC);

				Block->memcpy(Irp->AssociatedIrp.SystemBuffer, &BasicInformation, sizeof(MEMORY_BASIC_INFORMATION));
				Irp->IoStatus.Information = sizeof(MEMORY_BASIC_INFORMATION);
				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
		}
	}

	Block->IofCompleteRequest(
		Irp,
		IO_NO_INCREMENT);
}

PBLOCK
NTAPI
GetProcBlock(
	VOID
)
{
#ifdef BUG
	VMProtectBegin("xor3");
#endif

	PBLOCK Block = NULL;

	PVOID ImageBase = NULL;
	ULONG SizeOfImage = 0;

	ULONG DwmProcessId = 0;
	PEPROCESS DwmProcess = NULL;
	KAPC_STATE ApcState = { 0 };

	ULONG SystemVersion = 0;
	ULONG NtUserQueryWindowIndex = 0;
	ULONG NtUserSetWindowDisplayAffinityIndex = 0;

	PSYSTEM_SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTableShadow = NULL;
	PRtlFindExportedRoutineByName RtlFindExportedRoutineByNamePointer = NULL;

	Block = ExAllocatePool(NonPagedPool, sizeof(BLOCK));
	RtlZeroMemory(Block, sizeof(BLOCK));
	if (Block)
	{
		Block->DbgPrint = GetProcAddress(L"DbgPrint");
		Block->IofCompleteRequest = GetProcAddress(L"IofCompleteRequest");
		Block->ExAllocatePool = GetProcAddress(L"ExAllocatePool");
		Block->ExFreePoolWithTag = GetProcAddress(L"ExFreePoolWithTag");
		Block->IoAllocateMdl = GetProcAddress(L"IoAllocateMdl");
		Block->IoFreeMdl = GetProcAddress(L"IoFreeMdl");
		Block->IoGetCurrentProcess = GetProcAddress(L"IoGetCurrentProcess");
		Block->IoThreadToProcess = GetProcAddress(L"IoThreadToProcess");
		Block->KeGetCurrentIrql = GetProcAddress(L"KeGetCurrentIrql");
		Block->KeGetCurrentThread = GetProcAddress(L"KeGetCurrentThread");
		Block->KeRaiseIrqlToDpcLevel = GetProcAddress(L"KeRaiseIrqlToDpcLevel");
		Block->KeStackAttachProcess = GetProcAddress(L"KeStackAttachProcess");
		Block->KeUnstackDetachProcess = GetProcAddress(L"KeUnstackDetachProcess");
		Block->memcpy = GetProcAddress(L"memcpy");
		Block->memset = GetProcAddress(L"memset");
		Block->MmBuildMdlForNonPagedPool = GetProcAddress(L"MmBuildMdlForNonPagedPool");
		Block->MmCopyVirtualMemory = GetProcAddress(L"MmCopyVirtualMemory");
		Block->MmGetPhysicalAddress = GetProcAddress(L"MmGetPhysicalAddress");
		Block->MmIsAddressValid = GetProcAddress(L"MmIsAddressValid");
		Block->MmMapLockedPages = GetProcAddress(L"MmMapLockedPages");
		Block->MmUnmapLockedPages = GetProcAddress(L"MmUnmapLockedPages");
		Block->ObfDereferenceObject = GetProcAddress(L"ObfDereferenceObject");
		Block->MmProbeAndLockPages = GetProcAddress(L"MmProbeAndLockPages");
		Block->MmMapLockedPagesSpecifyCache = GetProcAddress(L"MmMapLockedPagesSpecifyCache");
		Block->MmUnlockPages = GetProcAddress(L"MmUnlockPages");
		Block->PsGetProcessPeb = GetProcAddress(L"PsGetProcessPeb");
		Block->PsGetProcessWow64Process = GetProcAddress(L"PsGetProcessWow64Process");
		Block->PsGetThreadWin32Thread = GetProcAddress(L"PsGetThreadWin32Thread");
		Block->PsLookupProcessByProcessId = GetProcAddress(L"PsLookupProcessByProcessId");
		Block->PsLookupThreadByThreadId = GetProcAddress(L"PsLookupThreadByThreadId");
		Block->wcslwr = GetProcAddress(L"_wcslwr");
		Block->wcsstr = GetProcAddress(L"wcsstr");
		Block->wcsnicmp = GetProcAddress(L"_wcsnicmp");
		Block->strnicmp = GetProcAddress(L"_strnicmp");
		Block->ZwAllocateVirtualMemory = GetProcAddress(L"ZwAllocateVirtualMemory");
		Block->PsSetThreadWin32Thread = GetProcAddress(L"PsSetThreadWin32Thread");
		Block->ZwQueryVirtualMemory = GetProcAddress(L"ZwQueryVirtualMemory");

		Block->MmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)GetMmUnloadedDrivers();
		Block->MmLastUnloadedDriver = GetMmLastUnloadedDriver();

		RtlFindExportedRoutineByNamePointer = GetProcAddress(L"RtlFindExportedRoutineByName");
		if (RtlFindExportedRoutineByNamePointer)
		{
			DwmProcessId = GetDwmProcessId();
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)DwmProcessId, &DwmProcess)))
			{
				KeStackAttachProcess(DwmProcess, &ApcState);
				ImageBase = ImgGetBaseAddress("win32kbase.sys", &SizeOfImage);
				if (ImageBase)
				{
					Block->ValidateHwnd = RtlFindExportedRoutineByNamePointer(ImageBase, "ValidateHwnd");
				}
				else
				{
					ImageBase = ImgGetBaseAddress("win32k.sys", &SizeOfImage);
					if (ImageBase)
					{
						Block->ValidateHwnd = RtlFindExportedRoutineByNamePointer(ImageBase, "ValidateHwnd");
					}
				}
				KeUnstackDetachProcess(&ApcState);
			}
		}

		SystemVersion = CheckSystemVersion();

		if (SystemVersion == 7600 || SystemVersion == 7601)
		{
			NtUserQueryWindowIndex = 0x1010;
			NtUserSetWindowDisplayAffinityIndex = 0x1317;
		}
		if (SystemVersion == 9200)
		{
			NtUserQueryWindowIndex = 0x1011;
			NtUserSetWindowDisplayAffinityIndex = 0x13B6;
		}
		if (SystemVersion == 9600)
		{
			NtUserQueryWindowIndex = 0x1012;
			NtUserSetWindowDisplayAffinityIndex = 0x13E7;
		}
		if (SystemVersion > 9600)
		{
			NtUserQueryWindowIndex = GetNtFunctionsIndex(
				"NtUserQueryWindow",
				L"\\??\\C:\\Windows\\System32\\win32u.dll"
			);
			NtUserSetWindowDisplayAffinityIndex = GetNtFunctionsIndex(
				"NtUserSetWindowDisplayAffinity",
				L"\\??\\C:\\Windows\\System32\\win32u.dll"
			);
		}
		if (NtUserQueryWindowIndex && NtUserSetWindowDisplayAffinityIndex)
		{
			KeServiceDescriptorTableShadow = GetSSSDTTable();
			if (KeServiceDescriptorTableShadow)
			{
				DwmProcessId = GetDwmProcessId();

				if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)DwmProcessId, &DwmProcess)))
				{
					KeStackAttachProcess(DwmProcess, &ApcState);

					Block->NtUserQueryWindow = GetSSSDTProcAddress64(
						KeServiceDescriptorTableShadow,
						NtUserQueryWindowIndex
					);
					Block->NtUserSetWindowDisplayAffinity = GetSSSDTProcAddress64(
						KeServiceDescriptorTableShadow,
						NtUserSetWindowDisplayAffinityIndex
					);

					KeUnstackDetachProcess(&ApcState);
				}
			}
		}
	}

	return Block;

#ifdef BUG
	VMProtectEnd();
#endif
}


BOOLEAN
NTAPI
Hook(
	VOID
)
{
#ifdef BUG
	VMProtectBegin("xor0");
#endif

	PVOID ImageBase = NULL;
	ULONG SizeOfImage = 0;

	KIRQL IRQL = 0;

	PVOID ShellCode = NULL;
	PVOID ProcAddress = NULL;

	PIMAGE_DOS_HEADER		DosHeader = NULL;
	PIMAGE_NT_HEADERS		NtHeader = NULL;
	PIMAGE_SECTION_HEADER	SectionHeader = NULL;

// 	UCHAR JmpCode[] = {
// 	0x49 ,0xB8 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,
// 	0x48 ,0xB8 ,0x22 ,0x22 ,0x22 ,0x22 ,0x22 ,0x22 ,0x22 ,0x22 ,
// 	0xFF ,0xE0
// 	};

	UCHAR JmpCode[] = {
	0x49 ,0xB8 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,0x11 ,
	0x68, 0x22, 0x22, 0x22, 0x22,
	0xC7, 0x44, 0x24, 0x04, 0x11, 0x11, 0x11, 0x11,
	0xC3
	};

	ImageBase = ImgGetBaseAddress(
		"xxxxxxx.sys",				//Hook Driver Name
		&SizeOfImage
	);

	if (ImageBase)
	{
		CodeBlock = GetProcBlock();

		if (CodeBlock)
		{
			ShellCode = ExAllocatePool(NonPagedPool, 0x1200);
			RtlCopyMemory(ShellCode, DeviceControl, 0x1200);
			ProcAddress = (PVOID)InitSeparateBlockTable(ShellCode, 0x1200);
			ExFreePoolWithTag(ShellCode, 0);

			DbgPrint("ProcAddress:%p\n", ProcAddress);

			if (ProcAddress)
			{
				*(PBLOCK*)&JmpCode[2] = CodeBlock;
				*(ULONG*)&JmpCode[11] = *(PULONG)((ULONG64)(&ProcAddress));
				*(ULONG*)&JmpCode[19] = *(PULONG)((ULONG64)(&ProcAddress) + 4);

				ShellCode = ExAllocatePool(NonPagedPool, sizeof(JmpCode));
				RtlCopyMemory(ShellCode, JmpCode, sizeof(JmpCode));

				IRQL = CloseProtect();
				*(PVOID*)((PUCHAR)ImageBase + 0x1234567) = ShellCode;	//Hook Driver Imp_IofCompleteRequest

				OpenProtect(IRQL);
				
				return TRUE;
			}
		}
	}
	return FALSE;

#ifdef BUG
	VMProtectEnd();
#endif
}