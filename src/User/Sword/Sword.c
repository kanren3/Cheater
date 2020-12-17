#include "Sword.h"

void main()
{
	ULONG64 ModuleBase = 0;
	ULONG Data = 0;
	ULONG64 AllocateAddress = 0;

	if (InitializeDriver())
	{
		SetProcessId(GetCurrentProcessId());
		ModuleBase = GetModuleBase(L"ntdll.dll");
		printf("ModuleBase:%llX\n", ModuleBase);
		DriverReadMemory((PVOID)ModuleBase, &Data, 4);
		printf("Data:%d\n", Data);
		AllocateAddress = AllocateVirtualMemory(64);
		printf("AllocateAddress:%llX\n", AllocateAddress);
	}
	
	system("pause");
}