#ifndef _MUTATION_H_
#define _MUTATION_H_

#define RandInstructionsCount	0x2
#define InstructionsSizeMax		0x18
#define JccJmpCountMax			0x1000

#pragma pack(1)

typedef struct _SEPARATE_BLOCK
{
	UCHAR	Instructions[InstructionsSizeMax];
	UCHAR	JUMPInstructions[14];
	ULONG64	RandInstructions[RandInstructionsCount];
	UCHAR	JCCJUMPInstructions[14];
}SEPARATE_BLOCK, * PSEPARATE_BLOCK;

#pragma pack()

typedef struct _JCC_JUMP_BLOCK
{
	ULONG64	InstructionsAddress;
	ULONG64	OldJCCJUMPAddress;
	ULONG64	NewJCCJUMPAddress;
}JCC_JUMP_BLOCK, * PJCC_JUMP_BLOCK;

typedef struct _JCC_JUMP_TABLE
{
	ULONG Count;
	JCC_JUMP_BLOCK Block[JccJmpCountMax];
}JCC_JUMP_TABLE, * PJCC_JUMP_TABLE;


ULONG64
NTAPI
InitSeparateBlockTable(
	IN PVOID ShellCode,
	IN ULONG Size
);

#endif
