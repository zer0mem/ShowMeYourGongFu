/**
 * @file InAppFuzzDbiModule.cpp
 * @author created by: Peter Hlavaty
 */

#include "stdafx.h"
#include "InAppFuzzDbiModule.h"

#include "../../Common/FastCall/FastCall.h"
#include "../../Common/base/Shared.h"

#define DLLEXPORT extern "C" __declspec(dllexport) 

extern "C" void fast_call_monitor(
	__in ULONG_PTR fastCall,
	__in HANDLE procId,
	__in HANDLE threadId,
	__inout void* info
	);

extern "C" void fast_call_monitor_wait(
	__in ULONG_PTR fastCall,
	__in HANDLE procId,
	__in HANDLE threadId,
	__inout void* info
	);

#define FastCallMonitor fast_call_monitor
#define FastCallMonitorWait fast_call_monitor_wait


EXTERN_C __declspec(dllexport) 
void SmartTrace(
	__in HANDLE procId,
	__in HANDLE threadId,
	__inout DBI_OUT_CONTEXT* dbiOut
	)
{
	FastCallMonitorWait(SYSCALL_TRACE_FLAG, procId, threadId, dbiOut);
}

EXTERN_C __declspec(dllexport) 
void GetNextFuzzThread(
	__inout CID_ENUM* cid
	)
{
	HANDLE proc_id = cid->ProcId.Value;
	HANDLE thread_id = cid->ThreadId.Value;
	FastCallMonitor(SYSCALL_ENUM_THREAD, cid->ProcId.Value, cid->ThreadId.Value, cid);
}

EXTERN_C __declspec(dllexport) 
void Init(
	__in HANDLE procId,
	__in HANDLE threadId,
	__inout DBI_OUT_CONTEXT* dbiOut
	)
{
	FastCallMonitor(SYSCALL_INIT, procId, threadId, dbiOut);
}

EXTERN_C __declspec(dllexport) 
void DbiEnumModules(
	__in HANDLE procId,
	__inout MODULE_ENUM* dbiOut
	)
{
	FastCallMonitor(SYSCALL_ENUM_MODULES, procId, 0, dbiOut);
}

EXTERN_C __declspec(dllexport) 
void DbiEnumMemory(
	__in HANDLE procId,
	__inout MEMORY_ENUM* dbiOut
	)
{
	FastCallMonitor(SYSCALL_ENUM_MEMORY, procId, 0, dbiOut);
}

EXTERN_C __declspec(dllexport) 
void DbiGetProcAddress(
	__in HANDLE procId,
	__inout PARAM_API* dbiParams
	)
{
	FastCallMonitor(SYSCALL_GETPROCADDR, procId, 0, dbiParams);
}

EXTERN_C __declspec(dllexport) 
void DbiDumpMemory(
	__in HANDLE procId,
	__in_bcount(size) const void* src,
	__in_bcount(size) void* dst,
	__in size_t size
	)
{
	PARAM_MEMCOPY mem_cpy;
	RtlZeroMemory(&mem_cpy, sizeof(mem_cpy));
	mem_cpy.Src.Value = src;
	mem_cpy.Dst.Value = dst;
	mem_cpy.Size.Value = size;
	FastCallMonitor(SYSCALL_DUMP_MEMORY, procId, 0, &mem_cpy);
}

EXTERN_C __declspec(dllexport) 
void DbiPatchMemory(
	__in HANDLE procId,
	__in_bcount(size) void* dst,
	__in_bcount(size) const void* src,
	__in size_t size
	)
{
	PARAM_MEMCOPY mem_cpy;
	RtlZeroMemory(&mem_cpy, sizeof(mem_cpy));
	mem_cpy.Src.Value = src;
	mem_cpy.Dst.Value = dst;
	mem_cpy.Size.Value = size;
	FastCallMonitor(SYSCALL_PATCH_MEMORY, procId, 0, &mem_cpy);
}

EXTERN_C __declspec(dllexport) 
void DbiSetHook(
	__in HANDLE procId,
	__inout PARAM_HOOK* dbiParams
	)
{
	FastCallMonitor(SYSCALL_SET_ADDRESS_BP, procId, 0, dbiParams);
}

EXTERN_C __declspec(dllexport) 
void DbiWatchMemoryAccess(
	__in HANDLE procId,
	__inout PARAM_MEM2WATCH* dbiParams
	)
{
	FastCallMonitor(SYSCALL_SET_MEMORY_BP, procId, 0, dbiParams);
}
