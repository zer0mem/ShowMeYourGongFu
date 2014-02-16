/**
 * @file GoHeaders.h
 * @author created by: Peter Hlavaty
 */

#ifndef __GOHEADERS_H__
#define __GOHEADERS_H__

typedef unsigned char bool;
typedef unsigned short WCHAR;

#include "../FastCall/FastCall.h"
/*
void SmartTrace(
	__in CID_ENUM* cid,
	__inout DBI_OUT_CONTEXT* dbiOut
	);

void GetNextFuzzThread(
	__inout CID_ENUM* cid
	);

void Init(
	__in CID_ENUM* cid,
	__inout DBI_OUT_CONTEXT* dbiOut
	);

void DbiEnumModules(
	__in HANDLE procId,
	__inout MODULE_ENUM* dbiOut
	);

void DbiEnumMemory(
	__in HANDLE procId,
	__inout MEMORY_ENUM* dbiOut
	);

void DbiGetProcAddress(
	__in HANDLE procId,
	__inout PARAM_API* dbiParams
	);

void DbiDumpMemory(
	__in HANDLE procId,
	__in_bcount(size) const void* src,
	__in_bcount(size) void* dst,
	__in size_t size
	);

void DbiPatchMemory(
	__in HANDLE procId,
	__in_bcount(size) void* dst,
	__in_bcount(size) const void* src,
	__in size_t size
	);

void DbiSetHook(
	__in HANDLE procId,
	__in PARAM_HOOK* dbiParams
	);

void DbiUnsetAddressBreakpoint(
	__in HANDLE procId,
	__in PARAM_HOOK* dbiParams
	);

void DbiWatchMemoryAccess(
	__in HANDLE procId,
	__inout PARAM_MEM2WATCH* dbiParams
	);

void DbiUnsetMemoryBreakpoint(
	__in HANDLE procId,
	__inout PARAM_MEM2WATCH* dbiParams
	);

void DbiSetMemoryWrite(
	__in HANDLE procId,
	__inout PARAM_MEM2WATCH* dbiParams
	);

void DbiUnSetMemoryWrite(
	__in HANDLE procId,
	__inout PARAM_MEM2WATCH* dbiParams
	);

void DbiSetMemoryExec(
	__in HANDLE procId,
	__inout PARAM_MEM2WATCH* dbiParams
	);
                               
void DbiUnSetMemoryExec(
	__in HANDLE procId,
	__inout PARAM_MEM2WATCH* dbiParams
	);

void DbiSuspendThread(
	__in const CID_ENUM* cid
	);
*/
#endif //__GOHEADERS_H__
