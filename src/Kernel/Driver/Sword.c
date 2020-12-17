#include "Sword.h"

VOID
NTAPI
DriverUnload(
	IN PDRIVER_OBJECT DriverObject
)
{

}

NTSTATUS
NTAPI
DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
)
{
#ifdef BUG
	VMProtectBegin("xor4");
#endif

	NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;

	PLDR_DATA_TABLE_ENTRY64 LdrData = NULL;

	DriverObject->DriverUnload = DriverUnload;
	
	if (Hook())
	{
		Status = STATUS_UNSUCCESSFUL;

		if (CodeBlock)
		{
			LdrData = (PLDR_DATA_TABLE_ENTRY64)DriverObject->DriverSection;
			if (LdrData)
			{
				CodeBlock->CurrentModuleBase = LdrData->DllBase;
			}
			for (ULONG i = 0; i < sizeof(BLOCK) / 8; i++)
			{
				((PULONG64)CodeBlock)[i] ^= BLOCK_KEY;
			}
		}
	}

	return Status;

#ifdef BUG
	VMProtectEnd();
#endif
}