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
};

enum
{
	DBI_IOCALL = RBP,
	DBI_FUZZAPP_PROC_ID = RCX,
	DBI_IRET = RCX,
	DBI_FUZZAPP_THREAD_ID = RSI,
	DBI_RETURN = RSI,
	DBI_ACTION = RAX,
	DBI_SEMAPHORE = RBX,
	DBI_R3TELEPORT = RDI,
	DBI_INFO_OUT = RDX,
};

#define DBI_FLAGS REG_COUNT

#define SIZEOF_DBI_FASTCALL 3 //mov eax, [ebp]

#pragma pack(push, 1)

struct BRANCH_INFO 
{
	const void* DstEip;
	const void* SrcEip;
	const ULONG_PTR* StackPtr;
	ULONG64 Flags;
};

struct MEMORY_ACCESS
{
	void* Memory;
	ULONG Access;
};

struct DBI_OUT_CONTEXT
{
	ULONG64 GeneralPurposeContext[REG_COUNT + 1];
	BRANCH_INFO LastBranchInfo;
	MEMORY_ACCESS MemoryInfo;
};

struct CID_ENUM
{
	union
	{
		ULONG64 uProcId;
		HANDLE ProcId;
	};
	union
	{
		ULONG64 uThreadId;
		HANDLE ThreadId;
	};
};

#pragma pack(pop)

#endif //__FASTCALL_H__
