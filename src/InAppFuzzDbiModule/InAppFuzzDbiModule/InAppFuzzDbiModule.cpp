/**
 * @file InAppFuzzDbiModule.cpp
 * @author created by: Peter Hlavaty
 */

#include "stdafx.h"
#include "InAppFuzzDbiModule.h"

#include "../../Common/FastCall/FastCall.h"
#include "../../Common/base/Shared.h"

#define SIZE_REL_CALL (sizeof(ULONG) + sizeof(BYTE))

#ifdef _WIN64

#define DLLEXPORT extern "C" __declspec(dllexport) 

extern "C" void fast_call_event(
	__in ULONG_PTR fastCall
	);

extern "C" void fast_call_monitor(
	__in ULONG_PTR fastCall
	);

#define FastCallEvent fast_call_event
#define FastCallMonitor fast_call_monitor

#else

#define DLLEXPORT extern "C" __declspec(dllexport, naked) 

__declspec(naked)
void __stdcall FastCallEvent(
	__in ULONG_PTR fastCall,
	__in void* retHookAddr
	)
{
	//stdcall stack => 0:[pushf] 1:[ret1] 2:[fastCall] 3:[Reserved] 4:[ret2 except hook it should be rnd]
	__asm
	{
		;[push fastCall]
		;[push unused for segment]
		;[ret from call FastCallEvent]

		pushfd
		pushad

		lea ebp, [esp + REG_X86_COUNT * 4]; ebp points to flags -> push ebp in classic prologue

		mov eax, esp
		xor ebx, ebx
		push ebx				; push semaphore onto stack
		mov ebx, esp

		;set information for dbi
		pushad
		mov dword ptr [esp + DBI_IOCALL * 4], FAST_CALL

		mov dword ptr [esp + DBI_PARAMS * 4], eax

		;SYSCALL_HOOK specific {
		lea eax, [ebp + 1 * 4] ; ebp : 0:[pushf] 1:[ret1] 2:[fastCall] 3:[ret2 / retHookAddr]
		mov dword ptr [esp + DBI_IRET * 4], eax
		mov eax, retHookAddr;dword ptr [ebp + 3 * 4]
		mov dword ptr [esp + DBI_RETURN * 4], eax
		;} SYSCALL_HOOK specific

		mov ecx, fastCall
		mov dword ptr [esp + DBI_ACTION * 4], ecx ;fastCall

		mov dword ptr [esp + DBI_SEMAPHORE * 4], ebx

		lea eax, [_WaitForFuzzEvent]
		mov dword ptr [esp + DBI_R3TELEPORT * 4], eax
		popad

		;invoke fast call
		mov eax, [ecx] ; DBI_IOCALL

_WaitForFuzzEvent:
		cmp byte ptr[esp], 0	; thread friendly :P
		jz _WaitForFuzzEvent

		pop eax
		popad

		popfd
		iretd
	}
}

__declspec(naked)
void __cdecl FastCallMonitorWait(
	__in ULONG_PTR fastCall,
	__in HANDLE procId,
	__in HANDLE threadId,
	__inout void* info
	)
{
	__asm
	{
		pushfd
		pushad

		lea ebp, [esp + REG_X86_COUNT * 4]; ebp points to flags -> push ebp in classic prologue

		xor ebx, ebx

		push ebx				; push semaphore onto stack
		mov ebx, esp

		;set information for dbi
		pushad
		mov dword ptr [esp + DBI_IOCALL * 4], FAST_CALL

		mov ecx, fastCall
		mov dword ptr [esp + DBI_ACTION * 4], ecx ;fastCall

		mov edx, procId
		mov dword ptr [esp + DBI_FUZZAPP_PROC_ID * 4], edx ;procdId

		mov edx, threadId
		mov dword ptr [esp + DBI_FUZZAPP_THREAD_ID * 4], edx ;threadId

		mov dword ptr [esp + DBI_SEMAPHORE * 4], ebx

		lea eax, [_WaitForFuzzEvent]
		mov dword ptr [esp + DBI_R3TELEPORT * 4], eax

		mov eax, info
		mov dword ptr [esp + DBI_PARAMS * 4], eax

		popad
		;invoke fast call
		mov eax, [ecx] ; DBI_IOCALL
		
_WaitForFuzzEvent:
		cmp byte ptr[esp], 0	; thread friendly :P
		jz _WaitForFuzzEvent

		pop eax
		popad
		popfd


		retn
	}
}

__declspec(naked)
	void __cdecl FastCallMonitor(
	__in ULONG_PTR fastCall,
	__in HANDLE procId,
	__in HANDLE threadId,
	__inout void* info
	)
{
	__asm
	{
		pushfd
		pushad

		lea ebp, [esp + REG_X86_COUNT * 4]; ebp points to flags -> push ebp in classic prologue

		;set information for dbi
		pushad
		mov dword ptr [esp + DBI_IOCALL * 4], FAST_CALL

		mov ecx, fastCall
		mov dword ptr [esp + DBI_ACTION * 4], ecx ;fastCall

		mov edx, procId
		mov dword ptr [esp + DBI_FUZZAPP_PROC_ID * 4], edx ;procdId

		mov edx, threadId
		mov dword ptr [esp + DBI_FUZZAPP_THREAD_ID * 4], edx ;threadId

		lea eax, [_WaitForFuzzEvent]
		mov dword ptr [esp + DBI_R3TELEPORT * 4], eax

		mov eax, info
		mov dword ptr [esp + DBI_PARAMS * 4], eax

		popad
		;invoke fast call
		mov eax, [ecx] ; DBI_IOCALL

_WaitForFuzzEvent:
		popad
		popfd


		retn
	}
}
#endif // _WIN64

DLLEXPORT
void ExtTrapTrace()
{
	__asm
	{
		push [esp] ;in case of CALL FAR
		push SYSCALL_TRACE_FLAG
		call FastCallEvent
	}
}

DLLEXPORT
void ExtMain()
{
	__asm
	{
		;push retHookAddr <- current ret
		push SYSCALL_HOOK
		call FastCallEvent
	}
}

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
bool GetNextFuzzThread(
	__inout CID_ENUM* cid
	)
{
	HANDLE proc_id = cid->ProcId.Value;
	HANDLE thread_id = cid->ThreadId.Value;
	FastCallMonitor(SYSCALL_ENUM_THREAD, cid->ProcId.Value, cid->ThreadId.Value, cid);
	return (proc_id != cid->ProcId.Value || thread_id != cid->ThreadId.Value);
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
	__in HANDLE threadId,
	__inout MODULE_ENUM* dbiOut
	)
{
	FastCallMonitor(SYSCALL_ENUM_MODULES, procId, threadId, dbiOut);
}

EXTERN_C __declspec(dllexport) 
void DbiEnumMemory(
	__in HANDLE procId,
	__in HANDLE threadId,
	__inout MEMORY_ENUM* dbiOut
	)
{
	FastCallMonitor(SYSCALL_ENUM_MEMORY, procId, threadId, dbiOut);
}

EXTERN_C __declspec(dllexport) 
void DbiGetProcAddress(
	__in HANDLE procId,
	__in HANDLE threadId,
	__inout PARAM_API* dbiParams
	)
{
	FastCallMonitor(SYSCALL_GETPROCADDR, procId, threadId, dbiParams);
}

EXTERN_C __declspec(dllexport) 
void DbiDumpMemory(
	__in HANDLE procId,
	__in HANDLE threadId,
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
	FastCallMonitor(SYSCALL_DUMP_MEMORY, procId, threadId, &mem_cpy);
}

EXTERN_C __declspec(dllexport) 
void DbiPatchMemory(
	__in HANDLE procId,
	__in HANDLE threadId,
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
	FastCallMonitor(SYSCALL_PATCH_MEMORY, procId, threadId, &mem_cpy);
}

EXTERN_C __declspec(dllexport) 
void DbiSetHook(
	__in HANDLE procId,
	__in HANDLE threadId,
	__inout PARAM_HOOK* dbiParams
	)
{
	FastCallMonitor(SYSCALL_SET_HOOK, procId, threadId, dbiParams);
}

EXTERN_C __declspec(dllexport) 
void DbiWatchMemoryAccess(
	__in HANDLE procId,
	__in HANDLE threadId,
	__inout PARAM_MEM2WATCH* dbiParams
	)
{
	FastCallMonitor(SYSCALL_WATCH_MEMORY, procId, threadId, dbiParams);
} 