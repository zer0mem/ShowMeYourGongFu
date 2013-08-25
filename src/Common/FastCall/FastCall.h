/**
 * @file FastCall.h
 * @author created by: Peter Hlavaty
 */

#ifndef __FASTCALL_H__
#define __FASTCALL_H__

#include "../base/Shared.h"

enum 
{
	FAST_CALL = 0x666,
	SYSCALL_TRACE_FLAG = 0x200,
	SYSCALL_HOOK,
	SYSCALL_PATCH_MEMORY,
	SYSCALL_DUMP_MEMORY,
	SYSCALL_GET_CONTEXT,
	SYSCALL_SET_CONTEXT,
	SYSCALL_TRACE_RET,
	SYSCALL_ENUM_NEXT,
	SYSCALL_MMU_NOACC,
};

enum
{
	DBI_IOCALL = RBP,

	DBI_FUZZAPP_PROC_ID = RCX,
	DBI_IRET = RCX,
	DBI_MEM2WATCH = RCX,

	DBI_FUZZAPP_THREAD_ID = RSI,
	DBI_RETURN = RSI,
	DBI_SIZE2WATCH = RSI,

	DBI_ACTION = RAX,

	DBI_SEMAPHORE = RBX,

	DBI_R3TELEPORT = RDI,

	DBI_INFO_OUT = RDX,
};

#define DBI_FLAGS REG_COUNT

#define SIZEOF_DBI_FASTCALL 3 //mov eax, [ebp]

enum EnumSYSENTER
{
	SReturn = RCX,
	SFlags = R11
};

enum EnumIRET
{
	IReturn = 0,
	ICodeSegment,
	IFlags,
	IRetCount
};

#pragma pack(push, 1)

struct BRANCH_INFO 
{
	const void* DstEip;
	const void* SrcEip;
	const ULONG_PTR* StackPtr;
	BYTE* Cr2;
	ULONG64 Flags;
};

struct MEMORY_ACCESS
{
	const void* Memory;
	ULONG Access;
	const void* Begin;
	size_t Size;
};

struct DBI_OUT_CONTEXT
{
	ULONG64 GeneralPurposeContext[REG_COUNT + 1];
	BRANCH_INFO LastBranchInfo;
	MEMORY_ACCESS MemoryInfo;
};

template<class TYPE>
struct TYPE_X86COMPATIBLE
{
	union
	{
		ULONG64 uValue;
		TYPE Value;
	};
};

struct CID_ENUM
{
	TYPE_X86COMPATIBLE<HANDLE> ProcId;
	TYPE_X86COMPATIBLE<HANDLE> ThreadId;
};

struct MEMORY_ENUM
{
	TYPE_X86COMPATIBLE<const void*> Begin;
	TYPE_X86COMPATIBLE<size_t> Size;
	TYPE_X86COMPATIBLE<ULONG> Flags;
};

#pragma pack(pop)

#endif //__FASTCALL_H__
