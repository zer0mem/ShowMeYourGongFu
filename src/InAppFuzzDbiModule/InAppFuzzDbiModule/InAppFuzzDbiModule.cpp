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
void __fastcall FastCallEvent(
	__in ULONG_PTR fastCall
	)
{
	__asm
	{
					; on stack already return eip
		push cs		; push place for target segment
		pushfd		; push place for flags

		pushad
		mov ebx, esp

		xor eax, eax
		push eax

		lea edi, [_WaitForFuzzEvent]
		mov edx, esp ; set semaphore
		mov eax, FAST_CALL
		mov eax, [eax]

_WaitForFuzzEvent:
		int 3
		cmp byte ptr[esp], 0	; thread friendly :P
		;jz _WaitForFuzzEvent

		add esp, 4
		;mov dword ptr [esp + RAX * 4], eax
		popad

		retf		; perform far ret, due to pop flags -> further trap flag tracing...
	}
}

__declspec(naked)
void __fastcall FastCallMonitor(
	__in HANDLE threadId,
	__in ULONG_PTR fastCall,
	__inout ULONG_PTR* reg,
	__inout ULONG_PTR* addr
	)
{
	__asm
	{
		push cs
		pushf
		pushad

		mov ecx, esp
		mov eax, FAST_CALL
		mov eax, [FAST_CALL]

		xor eax, eax
		push eax

_WaitForFuzzEvent:
		cmp dword ptr[esp], 0	; thread friendly :P
		jz _WaitForFuzzEvent

		pop eax
		mov dword ptr[addr], eax ; return eip of fuzzed process

		;copy context
		mov edi, reg
		mov esi, esp
		mov ecx, REG_X86_COUNT
		rep movsd

		popad
		add esp, 4
		popf

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
	__inout ULONG_PTR* reg
	)
{
	ULONG_PTR ret;
	FastCallMonitor(NULL, SYSCALL_TRACE_FLAG, reg, &ret);
	return ret;
}
