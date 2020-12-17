#ifndef _DRIVER_H_
#define _DRIVER_H_

#ifdef UNICODE
#define SYMBOL_NAME	L"\\\\.\\SymbolicLink"	//Driver IRP SymbolicLink
#else
#define SYMBOL_NAME	"\\\\.\\SymbolicLink"
#endif

typedef struct _READ_WRITE_DATA
{
	PVOID Address;
	PVOID Buffer;
	ULONG64 Size;
}READ_WRITE_DATA, * PREAD_WRITE_DATA;

typedef struct _GENERIC_THREAD_CTX
{
	ULONG64 WindowHandle;
	ULONG64 ThreadPointer;
	ULONG64 IsGet;
}GENERIC_THREAD_CTX, * PGENERIC_THREAD_CTX;

BOOLEAN
WINAPI
InitializeDriver(
	VOID
);

VOID
WINAPI
SetProcessId(
	IN ULONG64 ProcessId
);

VOID
WINAPI
DriverReadMemory(
	IN PVOID Address,
	IN PVOID Buffer,
	IN ULONG64 Size
);

VOID
WINAPI
DriverWriteMemory(
	IN PVOID Address,
	IN PVOID Buffer,
	IN ULONG64 Size
);

ULONG64
WINAPI
GetModuleBase(
	IN LPCWSTR Name
);

ULONG64
WINAPI
AllocateVirtualMemory(
	IN ULONG64 Size
);

VOID
WINAPI
SetWindowDisplay(
	IN ULONG64 hWnd
);

ULONG64
WINAPI
GetWindowThread(
	IN ULONG64 hWnd
);

VOID
WINAPI
SetWindowThread(
	IN ULONG64 hWnd,
	IN ULONG64 Thread
);

VOID
WINAPI
ClearUnLoadedData(
	VOID
);

#endif