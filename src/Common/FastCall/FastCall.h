/**
 * @file FastCall.h
 * @author created by: Peter Hlavaty
 */

#ifndef __FASTCALL_H__
#define __FASTCALL_H__

enum 
{
	FAST_CALL = 0x666,
	SYSCALL_TRACE_FLAG = 0x200,
	SYSCALL_INFO_FLAG,
	SYSCALL_MAIN,
	SYSCALL_PATCH_MEMORY,
};

#endif //__FASTCALL_H__
