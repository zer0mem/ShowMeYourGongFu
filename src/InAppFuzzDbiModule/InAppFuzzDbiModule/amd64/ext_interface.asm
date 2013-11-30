include ..\..\Common\amd64\common.inc

extrn ExtMain:proc

.code

fast_call_monitor_wait proc
	push rbx
	mov rbx, 0666h ;

	xor rax, rax
	push rax
	lea rax, [rsp]

	xchg rax, rcx ; rcx is volatile to syscall end is with r11 automaticly rewritten
	syscall
		
_WaitForFuzzEvent:
	cmp byte ptr[rsp], 0	; thread friendly waitforevent
	jz _WaitForFuzzEvent

	pop rax

	pop rbx
	ret
fast_call_monitor_wait endp

fast_call_monitor proc
	push rbx
	mov rbx, 0666h ;

	mov rax, rcx
	syscall

	pop rbx
	ret
fast_call_monitor endp

ExtTrapTrace proc
	;sub rsp, 5 * sizeof(qword) ; IRETQ
	;sub rsp, 010h * sizoef(qword) ; popaq 
	;sub rsp, 1 * sizeof(qword) ; semaphore
	
_WaitForFuzzEvent:
	;cmp byte ptr[rsp], 0	; thread friendly :P
	;jz _WaitForFuzzEvent

	;add rsp, sizeof(qword) ; semaphore
	;popaq ; load context
	;iretq ; set rip & rsp and continue with tracing
	int 3
	ENTER_HOOK_PROLOGUE	
	ENTER_HOOK ExtMain
	ENTER_HOOK_EPILOGUE
	
	add rsp, sizeof(qword) ; hook tmp	
	int 3
	iretq
ExtTrapTrace endp

end
