#ifndef _RELOAD_H_
#define _RELOAD_H_

typedef struct _GPBLOCK
{
	VOID
	(NTAPI* ExQueueWorkItem)(
		__inout PWORK_QUEUE_ITEM WorkItem,
		__in WORK_QUEUE_TYPE QueueType
		);

	USHORT OffsetKProcessThreadListHead;
	USHORT OffsetKThreadThreadListEntry;
	USHORT OffsetKThreadWin32StartAddress;

} GPBLOCK, * PGPBLOCK;

#endif
