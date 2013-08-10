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
	SYSCALL_MAIN,
	SYSCALL_PATCH_MEMORY,
};

enum
{
	DBI_IOCALL = RBP,
	DBI_FUZZAPP_PROC_ID = RCX,
	DBI_FUZZAPP_THREAD_ID = RSI,
	DBI_ACTION = RAX,
	DBI_SEMAPHORE = RBX,
	DBI_R3TELEPORT = RDI,
	DBI_FUZZAPP_INFO_OUT = RDX,
};


#pragma pack(push, 1)

struct BRANCH_INFO 
{
	const void* DstEip;
	const void* SrcEip;
};

struct MEMORY_ACCESS
{
	void* Memory;
	ULONG Access;
};

struct DBI_OUT_CONTEXT
{
	ULONG_PTR GeneralPurposeContext;
	BRANCH_INFO BranchInfo;
	MEMORY_ACCESS MemoryInfo;
};

#pragma pack(pop)

#endif //__FASTCALL_H__
