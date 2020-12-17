#include "Sword.h"

ULONG64 CapstoneHandle = 0;
ULONG64 DecomposeCount = 0;
cs_insn* Decompose = NULL;
JCC_JUMP_TABLE JccJumpTable = { 0 };


ULONG
NTAPI
InitCapstone(
	IN PVOID ShellCode,
	IN ULONG Size,
	OUT cs_insn** Decompose
)
{
	ULONG Count = 0;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &CapstoneHandle) == CS_ERR_OK)
	{
		if (cs_option(CapstoneHandle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK)
		{
			Count = cs_disasm(
				CapstoneHandle,
				ShellCode,
				Size,
				(ULONG64)ShellCode,
				0,
				Decompose);
		}
	}

	return Count;
}


BOOLEAN
NTAPI
IsJump(
	IN cs_insn* Decompose
)
{
	if (cs_insn_group(CapstoneHandle, Decompose, CS_GRP_JUMP))
	{
		if (cs_op_count(CapstoneHandle, Decompose, X86_OP_IMM))
		{
			return TRUE;
		}
	}

	return FALSE;
}


VOID
NTAPI
WriteRandData(
	IN PSEPARATE_BLOCK SeparateBlock
)
{
	PUCHAR Block = (PUCHAR)SeparateBlock;

	if (Block)
	{
		for (ULONG i = 0; i < sizeof(SEPARATE_BLOCK); i++)
		{
			*(Block + i) = __rdtsc() % 0xFF;
		}
	}
}

VOID
NTAPI
WriteJumpCode(
	IN ULONG64 Destination,
	IN ULONG64 JumpAddress
)
{
	UCHAR JUMP[] = {
	0x68, 0x22, 0x22, 0x22, 0x22,
	0xC7, 0x44, 0x24, 0x04, 0x11, 0x11, 0x11, 0x11,
	0xC3
	};

	*(ULONG*)&JUMP[1] = *(PULONG)((ULONG64)(&JumpAddress));
	*(ULONG*)&JUMP[9] = *(PULONG)((ULONG64)(&JumpAddress) + 4);

	RtlCopyMemory(
		(PVOID)Destination,
		JUMP,
		sizeof(JUMP));
}


PSEPARATE_BLOCK
NTAPI
AddSeparateBlock(
	IN PSEPARATE_BLOCK CurrentSeparateBlock,
	IN PUCHAR Bytes,
	IN ULONG SizeOfbytes
)
{
	PSEPARATE_BLOCK SeparateBlock = NULL;
	ULONG64 InstructionsStart = 0;

	SeparateBlock = ExAllocatePool(NonPagedPool, sizeof(SEPARATE_BLOCK));
	if (SeparateBlock)
	{
		WriteRandData(SeparateBlock);
		RtlCopyMemory(
			SeparateBlock->Instructions + (InstructionsSizeMax - SizeOfbytes),
			Bytes,
			SizeOfbytes);
	}
	if (CurrentSeparateBlock)
	{
		InstructionsStart = (ULONG64)SeparateBlock->Instructions + (InstructionsSizeMax - SizeOfbytes);
		WriteJumpCode(
			(ULONG64)CurrentSeparateBlock->JUMPInstructions,
			InstructionsStart);
	}

	return SeparateBlock;
}


ULONG64
NTAPI
InitSeparateBlockTable(
	IN PVOID ShellCode,
	IN ULONG Size
)
{
	PSEPARATE_BLOCK CurrentSeparateBlock = NULL;
	ULONG64 CurrentInstructionsAddress = 0;
	ULONG64 ShellCodeHead = 0;
	ULONG Index = 0;
	LONG64 Offset = 0;

	DecomposeCount = InitCapstone(ShellCode, Size, &Decompose);
	
	if (DecomposeCount)
	{
		for (ULONG i = 0; i < DecomposeCount; i++)
		{
			if (IsJump(&Decompose[i]))
			{
				JccJumpTable.Block[JccJumpTable.Count].OldJCCJUMPAddress = Decompose[i].detail->x86.operands[0].imm;
				JccJumpTable.Count++;
			}
		}

		for (ULONG i = 0; i < DecomposeCount; i++)
		{
			CurrentSeparateBlock = AddSeparateBlock(
				CurrentSeparateBlock,
				Decompose[i].bytes,
				Decompose[i].size);

			CurrentInstructionsAddress = (ULONG64)CurrentSeparateBlock->Instructions + (InstructionsSizeMax - Decompose[i].size);

			if (!ShellCodeHead)
			{
				ShellCodeHead = CurrentInstructionsAddress;
			}

			for (ULONG j = 0; j < JccJumpTable.Count; j++)
			{
				if (JccJumpTable.Block[j].OldJCCJUMPAddress == Decompose[i].address)
				{
					JccJumpTable.Block[j].NewJCCJUMPAddress = CurrentInstructionsAddress;
				}
			}

			if (IsJump(&Decompose[i]))
			{
				Offset = (LONG64)CurrentSeparateBlock->JCCJUMPInstructions
					- (LONG64)CurrentInstructionsAddress
					- Decompose[i].size;

				RtlCopyMemory(
					(PVOID)(CurrentInstructionsAddress + Decompose[i].detail->x86.encoding.imm_offset),
					&Offset,
					Decompose[i].detail->x86.encoding.imm_size);

				JccJumpTable.Block[Index].InstructionsAddress = (ULONG64)CurrentSeparateBlock->JCCJUMPInstructions;
				Index++;
			}
		}

		for (ULONG i = 0; i < JccJumpTable.Count; i++)
		{
			WriteJumpCode(
				JccJumpTable.Block[i].InstructionsAddress,
				JccJumpTable.Block[i].NewJCCJUMPAddress);
		}

		return ShellCodeHead;
	}

	return 0;
}
