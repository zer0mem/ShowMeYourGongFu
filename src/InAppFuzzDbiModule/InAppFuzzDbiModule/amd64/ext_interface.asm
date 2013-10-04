include ..\..\Common\amd64\common.inc
include ..\..\Common\FastCall\FastCall.inc

.code

fast_call_event proc	
;
;
		;[push fastCall]
		;[push unused for segment]
		;[ret from call FastCallEvent]

		pushfq
		pushaq

		lea rbp, [rsp + DBI_FLAGS * sizeof(qword)]; ebp points to flags -> push ebp in classic prologue

		mov rax, rsp
		xor rbx, rbx
		push rbx				; push semaphore onto stack
		mov rbx, rsp

		;set information for dbi
		pushaq
		mov qword ptr [rsp + DBI_IOCALL * sizeof(qword)], FAST_CALL

		mov qword ptr [rsp + DBI_PARAMS * sizeof(qword)], rax

		;SYSCALL_HOOK specific {
		lea rax, [rbp + 1 * sizeof(qword)] ; ebp : 0:[pushf] 1:[ret1] 2:[fastCall] 3:[ret2 / retHookAddr]
		mov qword ptr [rsp + DBI_IRET * sizeof(qword)], rax
		mov rax, qword ptr [rbp + 3 * sizeof(qword)];retHookAddr;qword ptr [rbp + 3 * sizeof(qword)]
		mov qword ptr [rsp + DBI_RETURN * sizeof(qword)], rax
		;} SYSCALL_HOOK specific

		mov rcx, qword ptr [rbp + 2 * sizeof(qword)];fastCall
		mov qword ptr [rsp + DBI_ACTION * sizeof(qword)], rcx ;fastCall

		mov qword ptr [rsp + DBI_SEMAPHORE * sizeof(qword)], rbx

		lea rax, [_WaitForFuzzEvent]
		mov qword ptr [rsp + DBI_R3TELEPORT * sizeof(qword)], rax
		popaq

		;invoke fast call
		;mov rax, [rcx] ; DBI_IOCALL
		syscall

_WaitForFuzzEvent:
		cmp byte ptr[rsp], 0	; thread friendly :P
		jz _WaitForFuzzEvent

		pop rax
		popaq

		popfq
		iretq
fast_call_event endp

fast_call_monitor_wait proc
		pushfq
		pushaq

		lea rbp, [rsp + DBI_FLAGS * sizeof(qword)]; rbp points to flags -> push ebp in classic prologue

		xor rbx, rbx

		push rbx				; push semaphore onto stack
		mov rbx, rsp

		;set information for dbi
		pushaq
		mov qword ptr [rsp + DBI_IOCALL * sizeof(qword)], FAST_CALL

		mov qword ptr [rsp + DBI_ACTION * sizeof(qword)], rcx ;fastCall

		mov qword ptr [rsp + DBI_FUZZAPP_PROC_ID * sizeof(qword)], rdx ;procdId

		mov qword ptr [rsp + DBI_FUZZAPP_THREAD_ID * sizeof(qword)], r8 ;threadId

		mov qword ptr [rsp + DBI_SEMAPHORE * sizeof(qword)], rbx

		lea rax, [_WaitForFuzzEvent]
		mov qword ptr [rsp + DBI_R3TELEPORT * sizeof(qword)], rax

		mov qword ptr [rsp + DBI_PARAMS * sizeof(qword)], r9

		popaq
		;invoke fast call
		syscall
		
_WaitForFuzzEvent:
		cmp byte ptr[rsp], 0	; thread friendly :P
		jz _WaitForFuzzEvent

		pop rax
		popaq
		popfq
		ret
fast_call_monitor_wait endp

fast_call_monitor proc
		pushfq
		pushaq

		lea rbp, [rsp + DBI_FLAGS * sizeof(qword)]; ebp points to flags -> push ebp in classic prologue

		;set information for dbi
		pushaq
		mov dword ptr [rsp + DBI_IOCALL * sizeof(qword)], FAST_CALL

		mov qword ptr [rsp + DBI_ACTION * sizeof(qword)], rcx ;fastCall

		mov qword ptr [rsp + DBI_FUZZAPP_PROC_ID * sizeof(qword)], rdx ;procdId

		mov qword ptr [rsp + DBI_FUZZAPP_THREAD_ID * sizeof(qword)], r8 ;threadId

		lea rax, [_WaitForFuzzEvent]
		mov qword ptr [rsp + DBI_R3TELEPORT * sizeof(qword)], rax

		mov qword ptr [rsp + DBI_PARAMS * sizeof(qword)], r9

		popaq
		;invoke fast call
		syscall

_WaitForFuzzEvent:
		popaq
		popfq

		ret
fast_call_monitor endp

ExtTrapTrace proc
	push [rsp]
	push [rsp]
	push [rsp] ;in case of CALL FAR
	push SYSCALL_TRACE_FLAG
	call fast_call_event
ExtTrapTrace endp

ExtMain proc
	;push retHookAddr <- current ret
	push [rsp]
	push [rsp]
	push SYSCALL_HOOK
	call fast_call_event
ExtMain endp

end
