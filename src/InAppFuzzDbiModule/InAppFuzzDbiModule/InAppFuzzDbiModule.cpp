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
	__in ULONG_PTR fastCall
	)
{
	__asm
	{
		pushfd
		pushad

		lea ebp, [esp + REG_X86_COUNT * 4]; ebp points to flags -> push ebp in classic prologue

		mov eax, esp
		push eax				; push semaphore onto stack
		mov ebx, esp

		;set information for dbi
		pushad
		mov dword ptr [esp + DBI_IOCALL * 4], FAST_CALL

		mov dword ptr [esp + DBI_FUZZAPP_INFO_OUT * 4], eax

		mov ecx, fastCall
		mov dword ptr [esp + DBI_ACTION * 4], ecx ;fastCall

		mov dword ptr [esp + DBI_SEMAPHORE * 4], ebx

		lea eax, [_WaitForFuzzEvent]
		mov dword ptr [esp + DBI_R3TELEPORT * 4], eax
		popad

		;invoke fast call
		mov eax, [ebp] ; DBI_IOCALL

_WaitForFuzzEvent:
		cmp byte ptr[esp], 0	; thread friendly :P
		;jz _WaitForFuzzEvent

		pop eax
		popad

		pushad
		mov dword ptr [esp + DBI_IOCALL * 4], FAST_CALL
		mov dword ptr [esp + DBI_ACTION * 4], SYSCALL_TRACE_RET
		popad
		popfd

		add esp, 2 * 4; pop ret and param from stack
		mov eax, [ebp] ; DBI_IOCALL
		int 3 ; not supossed to exec!
	}
}

__declspec(naked)
void __fastcall FastCallMonitor(
	__in ULONG_PTR fastCall,
	__in HANDLE procId,
	__in HANDLE threadId,
	__inout void* info
	)
{
	__asm
	{
		push ebp
		mov ebp, esp
		pushad
		
		mov eax, esp
		push eax				; push semaphore onto stack
		mov ebx, esp

		pushad
		mov dword ptr [esp + DBI_IOCALL * 4], FAST_CALL

		;mov ecx, fastCall
		mov dword ptr [esp + DBI_ACTION * 4], ecx ;fastCall

		;mov edx, procdId
		mov dword ptr [esp + DBI_FUZZAPP_PROC_ID * 4], edx ;procdId

		mov edx, threadId
		mov dword ptr [esp + DBI_FUZZAPP_THREAD_ID * 4], edx ;threadId

		mov dword ptr [esp + DBI_SEMAPHORE * 4], ebx

		lea eax, [_WaitForFuzzEvent]
		mov dword ptr [esp + DBI_R3TELEPORT * 4], eax

		mov eax, info
		mov dword ptr [esp + DBI_FUZZAPP_INFO_OUT * 4], eax
		popad
		mov eax, [ebp]

_WaitForFuzzEvent:
		int 3
		cmp dword ptr[esp], 0	; thread friendly :P
		;jz _WaitForFuzzEvent

		add esp, 4		
		popad
		pop ebp
		ret
	}
}

#endif // _WIN64

DLLEXPORT
void ExtTrapTrace()
{
	FastCallEvent(SYSCALL_TRACE_FLAG);
}

DLLEXPORT
void ExtInfo()
{
	FastCallEvent(SYSCALL_INFO_FLAG);
}

DLLEXPORT
void ExtMain()
{
	FastCallEvent(SYSCALL_MAIN);
}

EXTERN_C __declspec(dllexport) 
ULONG_PTR TrapTrace(
	__inout DBI_OUT_CONTEXT* dbiOut
	)
{
	FastCallMonitor(SYSCALL_TRACE_FLAG, (HANDLE)NULL, (HANDLE)NULL, dbiOut);
	return (ULONG_PTR)(dbiOut->BranchInfo.DstEip);
}
