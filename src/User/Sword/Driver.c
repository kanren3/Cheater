#include "Sword.h"

HANDLE DriverHandle;

BOOLEAN
WINAPI
InitializeDriver(
	VOID
)
{
	DriverHandle = CreateFile(
		SYMBOL_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
	);
	printf("Error:%X\n", GetLastError());
	printf("Handle:%p\n", DriverHandle);

	if (DriverHandle != INVALID_HANDLE_VALUE)
	{
		ClearUnLoadedData();
		return TRUE;
	}
	return FALSE;
}


VOID
WINAPI
DecryptEncrypt(
	IN PVOID OutData,
	IN PVOID InData,
	IN ULONG Size
)
{
	ULONG Index = 0;

	for (Index = 0; Index < Size; Index++)
	{
		((PUCHAR)OutData)[Index] = ((PUCHAR)InData)[Index] ^ 69;
	}
}

VOID
WINAPI
SetProcessId(
	IN ULONG64 ProcessId
)
{
	UCHAR Data[8] = { 0 };
	ULONG BytesReturned = 0;

	DecryptEncrypt(Data, &ProcessId, sizeof(ProcessId));

	DeviceIoControl(
		DriverHandle, 0x722020,
		Data, 8, NULL, 0,
		&BytesReturned, NULL
	);
}

VOID
WINAPI
DriverReadMemory(
	IN PVOID Address,
	IN PVOID Buffer,
	IN ULONG64 Size
)
{
	UCHAR Data[24] = { 0 };
	ULONG BytesReturned = 0;

	READ_WRITE_DATA ReadWriteData = { Address, Buffer ,Size };

	DecryptEncrypt(Data, &ReadWriteData, sizeof(ReadWriteData));

	DeviceIoControl(
		DriverHandle, 0x722030,
		Data, 24, NULL, 0,
		&BytesReturned, NULL
	);
}

VOID
WINAPI
DriverWriteMemory(
	IN PVOID Address,
	IN PVOID Buffer,
	IN ULONG64 Size
)
{
	UCHAR Data[24] = { 0 };
	ULONG BytesReturned = 0;

	READ_WRITE_DATA ReadWriteData = { Address, Buffer ,Size };

	DecryptEncrypt(Data, &ReadWriteData, sizeof(ReadWriteData));

	DeviceIoControl(
		DriverHandle, 0x722040,
		Data, 24, NULL, 0,
		&BytesReturned, NULL
	);

	//	0x722050	MDL WriteMemory
}

ULONG64
WINAPI
GetModuleBase(
	IN LPCWSTR Name
)
{
	PUCHAR Data = NULL;
	ULONG BytesReturned = 0;

	ULONG64 ModuleBase = 0;

	ULONG DataLength = lstrlenW(Name) * 2;
	Data = malloc(DataLength);

	WCHAR NNN[256] = { 0 };

	if (Data)
	{
		DecryptEncrypt(Data, (PVOID)Name, DataLength);

		DeviceIoControl(
			DriverHandle, 0x722060,
			Data, DataLength, Data, 8,
			&BytesReturned, NULL
		);

		DecryptEncrypt(&ModuleBase, Data, 8);

		free(Data);
	}
	return ModuleBase;
}

ULONG64
WINAPI
AllocateVirtualMemory(
	IN ULONG64 Size
)
{
	UCHAR Data[8] = { 0 };
	ULONG BytesReturned = 0;

	ULONG64 AllocateAddress = 0;

	DeviceIoControl(
		DriverHandle, 0x722070,
		&Size, 8, Data, 8,
		&BytesReturned, NULL
	);

	DecryptEncrypt(&AllocateAddress, Data, 8);

	return AllocateAddress;
}

VOID
WINAPI
SetWindowDisplay(
	IN ULONG64 hWnd
)
{
	ULONG64 Data = hWnd ^ 69;
	ULONG BytesReturned = 0;

	DeviceIoControl(
		DriverHandle, 0x722080,
		&Data, 8, NULL, 0,
		&BytesReturned, NULL
	);
}

ULONG64
WINAPI
GetWindowThread(
	IN ULONG64 hWnd
)
{
	GENERIC_THREAD_CTX Data = { 0 };
	ULONG BytesReturned = 0;

	Data.IsGet = 1;
	Data.WindowHandle = hWnd ^ 69;

	DeviceIoControl(
		DriverHandle, 0x722090,
		&Data, 24, &Data, 24,
		&BytesReturned, NULL
	);
	
	return Data.ThreadPointer;
}

VOID
WINAPI
SetWindowThread(
	IN ULONG64 hWnd,
	IN ULONG64 Thread
)
{
	GENERIC_THREAD_CTX Data = { 0 };
	ULONG BytesReturned = 0;

	Data.WindowHandle = hWnd ^ 69;
	Data.ThreadPointer = Thread;

	DeviceIoControl(
		DriverHandle, 0x722090,
		&Data, 24, &Data, 24,
		&BytesReturned, NULL
	);
}

VOID
WINAPI
ClearUnLoadedData(
	VOID
)
{
	ULONG BytesReturned = 0;

	DeviceIoControl(
		DriverHandle, 0x7220A0,
		NULL, 0, NULL, 0,
		&BytesReturned, NULL
	);
}

MEMORY_BASIC_INFORMATION
WINAPI
QueryVirtualMemory(
	IN ULONG64 Address
)
{
	MEMORY_BASIC_INFORMATION Data = { 0 };
	ULONG BytesReturned = 0;

	DeviceIoControl(
		DriverHandle, 0x7220B0,
		&Address, 8, &Data, sizeof(MEMORY_BASIC_INFORMATION),
		&BytesReturned, NULL
	);

	return Data;
}