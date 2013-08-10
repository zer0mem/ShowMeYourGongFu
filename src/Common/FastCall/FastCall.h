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
	SYSCALL_INFO_FLAG,
	SYSCALL_HOOK,
	SYSCALL_PATCH_MEMORY,
	SYSCALL_TRACE_RET,
	SYSCALL_ENUM_NEXT,
};

enum
{
	DBI_IOCALL = RBP,
	DBI_FUZZAPP_PROC_ID = RCX,
	DBI_FUZZAPP_THREAD_ID = RSI,
	DBI_RETURN = RSI,
	DBI_ACTION = RAX,
	DBI_SEMAPHORE = RBX,
	DBI_R3TELEPORT = RDI,
	DBI_INFO_OUT = RDX,
};

#define DBI_FLAGS REG_COUNT

#pragma pack(push, 1)

struct BRANCH_INFO 
{
	const void* DstEip;
	const void* SrcEip;
	ULONG_PTR Flags;
};

struct MEMORY_ACCESS
{
	void* Memory;
	ULONG Access;
};

struct DBI_OUT_CONTEXT
{
	ULONG_PTR GeneralPurposeContext[REG_COUNT + 1];
	BRANCH_INFO LastBranchInfo;
	MEMORY_ACCESS MemoryInfo;
};

struct CID_ENUM
{
	HANDLE ProcId;
	HANDLE ThreadId;
};

#pragma pack(pop)

#endif //__FASTCALL_H__
