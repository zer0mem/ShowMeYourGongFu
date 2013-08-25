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

	SYSCALL_WATCH_MEMORY,
	SYSCALL_GETPROCADDR,
	SYSCALL_SET_EIP,
	SYSCALL_SET_HOOK,
	SYSCALL_RUN,

	SYSCALL_INIT,
};

enum
{
//per reg INFO
	DBI_ACTION = RAX,

	DBI_IOCALL = RCX, //x86 compatibility ...

	DBI_R3TELEPORT = RDI,

	DBI_SEMAPHORE = RBX,

	DBI_FUZZAPP_PROC_ID = RBP, //monitor
	DBI_IRET = RBP, //target

	DBI_FUZZAPP_THREAD_ID = RSI, //monitor
	DBI_RETURN = RSI, //target

//optional parameter!
	DBI_PARAMS = RDX,
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

template<class TYPE>
struct TYPE_X86COMPATIBLE
{
	union
	{
		ULONG64 uValue;
		TYPE Value;
	};
};

struct BRANCH_INFO 
{
	TYPE_X86COMPATIBLE<const void*> DstEip;
	TYPE_X86COMPATIBLE<const void*> SrcEip;
	TYPE_X86COMPATIBLE<const ULONG_PTR*> StackPtr;
	TYPE_X86COMPATIBLE<BYTE*> Cr2;
	TYPE_X86COMPATIBLE<ULONG64> Flags;
};

struct MEMORY_ACCESS
{
	TYPE_X86COMPATIBLE<const void*> Memory;
	TYPE_X86COMPATIBLE<ERROR_CODE> Access;
	TYPE_X86COMPATIBLE<const void*> Begin;
	TYPE_X86COMPATIBLE<size_t> Size;
	TYPE_X86COMPATIBLE<ULONG> Flags;
	TYPE_X86COMPATIBLE<ULONG_PTR> OriginalValue;
};

struct DBI_OUT_CONTEXT
{
	ULONG_PTR GeneralPurposeContext[REG_COUNT + 1];
	BRANCH_INFO LastBranchInfo;
	MEMORY_ACCESS MemoryInfo;
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

struct MODULE_ENUM
{
	TYPE_X86COMPATIBLE<const void*> ImageBase;
	TYPE_X86COMPATIBLE<size_t> ImageSize;
	TYPE_X86COMPATIBLE<WCHAR[0x100]> ImageName;
};

struct PARAM_API
{
	TYPE_X86COMPATIBLE<const void*> ApiAddr;
	TYPE_X86COMPATIBLE<const void*> ModuleBase;
	TYPE_X86COMPATIBLE<CHAR[0x100]> ApiName;
};

struct PARAM_MEMCOPY
{
	TYPE_X86COMPATIBLE<const void*> Src;
	TYPE_X86COMPATIBLE<void*> Dst;
	TYPE_X86COMPATIBLE<size_t> Size;
};

struct PARAM_HOOK
{
	TYPE_X86COMPATIBLE<void*> HookAddr;
};

struct PARAM_MEM2WATCH
{
	TYPE_X86COMPATIBLE<const void*> Memory;
	TYPE_X86COMPATIBLE<size_t> Size;
};

#pragma pack(pop)

#endif //__FASTCALL_H__
