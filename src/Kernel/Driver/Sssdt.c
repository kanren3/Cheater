#include "Sword.h"

PSYSTEM_SERVICE_DESCRIPTOR_TABLE
NTAPI
GetSSSDTTable(
	VOID
)
{
	ULONG Sizeof = 0;
	PUCHAR ntosBase = ImgGetBaseAddress(NULL, &Sizeof);

	if (!ntosBase)
		return NULL;

	PIMAGE_NT_HEADERS pHdr = RtlImageNtHeader(ntosBase);
	PIMAGE_SECTION_HEADER pFirstSec = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++)
	{
		if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
			pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
			!(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
			(*(PULONG)pSec->Name != 'TINI') &&
			(*(PULONG)pSec->Name != 'EGAP'))
		{
			PVOID pFound = NULL;

			UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
			NTSTATUS status = SearchPattern(pattern, 0xCC, sizeof(pattern) - 1, ntosBase + pSec->VirtualAddress, pSec->Misc.VirtualSize, &pFound);
			pFound = (PUCHAR)pFound + 7;
			if (NT_SUCCESS(status))
			{
				return (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
			}
		}
	}
	return NULL;
}

PVOID
NTAPI
GetSSSDTProcAddress64(
	IN PSYSTEM_SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTableShadow,
	IN ULONG64 Index
)
{
	ULONG64 W32pServiceTable = 0, qwTemp = 0;
	LONG dwTemp = 0;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE	pWin32k;
	pWin32k = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((ULONG64)KeServiceDescriptorTableShadow + sizeof(SYSTEM_SERVICE_DESCRIPTOR_TABLE));
	W32pServiceTable = (ULONG64)(pWin32k->ServiceTableBase);
	qwTemp = W32pServiceTable + 4 * (Index - 0x1000);
	dwTemp = *(PLONG)qwTemp;
	dwTemp = dwTemp >> 4;
	qwTemp = W32pServiceTable + (LONG64)dwTemp;
	return (PVOID)qwTemp;
}