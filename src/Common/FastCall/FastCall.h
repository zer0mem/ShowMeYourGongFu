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

	SYSCALL_ENUM_THREAD,
	SYSCALL_ENUM_MODULES,
	SYSCALL_ENUM_MEMORY,

	SYSCALL_GETPROCADDR,

	SYSCALL_SET_ADDRESS_BP,
	SYSCALL_UNSET_ADDRESS_BP,

	SYSCALL_SET_ACCESS_BP,
	SYSCALL_UNSET_ACCESS_BP,
	SYSCALL_SET_WRITE_BP,
	SYSCALL_UNSET_WRITE_BP,
	SYSCALL_SET_EXEC_BP,
	SYSCALL_UNSET_EXEC_BP,

	SYSCALL_INIT,
	

	SYSCALL_FREEZE_THREAD,
};

enum
{
//per reg INFO
	SYSCALL_ID = RAX,
	DBI_SYSCALL = RBX,

	//DBI_SEMAPHORE = RCX, -> semapthore is on IRET->StackPtr, in other word first ptr on stack is semaphore
	DBI_FUZZAPP_PROC_ID = RDX,

	DBI_FUZZAPP_THREAD_ID = R8, 
	DBI_PARAMS = R9,
};

#define DBI_FLAGS REG_COUNT

#define SYSCAL_CS_SEGEMENT 0x33 //by default intel -> rdmsr 0xC0000082 check few instructions {swapgs, swap r3 with r0 stack pointer, push [ss, r3:rsp, rflags, cs, r3:rip] }
#define SYSCAL_SS_SEGEMENT 0x2B //-||-

enum EnumSYSENTER
{
	SReturn = RCX,
	SFlags = R11
};

enum EnumTraceReason
{
	BranchTraceFlag = 0,
	SingleTraceFlag,
	Hook,
	MemoryAcces,
	ThreadSuspended,
	MemoryTouchByKernel
};

#pragma pack(push, 1)

typedef struct _TRACE_INFO 
{
	PFIRET StateInfo;
	BYTE Btf;
	const void* PrevEip;
	ULONG_PTR Reason;
} TRACE_INFO;

typedef struct _MEMORY_ACCESS
{
	const void* Memory;
	const void* Begin;
	size_t Size;
	ULONG Flags;
	ULONG_PTR OriginalValue;
} MEMORY_ACCESS;

typedef struct _DBI_OUT_CONTEXT
{
	ULONG_PTR GeneralPurposeContext[REG_COUNT + 1];
	TRACE_INFO TraceInfo;
	MEMORY_ACCESS MemoryInfo;
} DBI_OUT_CONTEXT;

typedef struct _CID_ENUM
{
	HANDLE ProcId;
	HANDLE ThreadId;
} CID_ENUM;

typedef struct _MEMORY_ENUM
{
	const void* Begin;
	size_t Size;
	ULONG Flags;
} MEMORY_ENUM;

typedef struct _MODULE_ENUM
{
	const void* ImageBase;
	size_t ImageSize;
	bool Is64;
	WCHAR ImageName[0x100];
} MODULE_ENUM;

typedef struct _PARAM_API
{
	const void* ApiAddr;
	const void* ModuleBase;
	CHAR ApiName[0x100];
} PARAM_API;

typedef struct _PARAM_MEMCOPY
{
	const void* Src;
	void* Dst;
	size_t Size;
} PARAM_MEMCOPY;

typedef struct _PARAM_HOOK
{
	void* HookAddr;
} PARAM_HOOK;

typedef struct _PARAM_MEM2WATCH
{
	const void* Memory;
	size_t Size;
} PARAM_MEM2WATCH;

#pragma pack(pop)

#endif //__FASTCALL_H__
