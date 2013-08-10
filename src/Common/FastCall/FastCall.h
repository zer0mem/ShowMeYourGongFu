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
	DBI_IOCALL = RAX,
	DBI_REG_CONTEXT = RBX,
	DBI_ACTION = RCX,
	DBI_SEMAPHORE = RDX,
	DBI_R3TELEPORT = RDI
};

#endif //__FASTCALL_H__
