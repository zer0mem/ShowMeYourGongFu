extrn SysCallCallback:proc
extrn RdmsrHook:proc
extrn PageFault:proc
extrn PatchGuardHook:proc

include ..\..\Common\amd64\common.inc

.code

;OS INTERCEPTING
sysenter proc
	swapgs
	mov qword ptr gs:[Ring3RSP],rsp
	mov rsp,qword ptr gs:[Ring0RSP]

_hook:
	ENTER_HOOK_PROLOGUE
	ENTER_HOOK SysCallCallback
	
	cmp rax, 0
	jz @syscall_skip

	add rax, _hook - sysenter
	ENTER_HOOK_EPILOGUE
	ret

@syscall_skip:
	ENTER_HOOK_EPILOGUE

	mov rsp, qword ptr gs:[Ring3RSP]	
	swapgs	
	sysretq ; return back to user mode
sysenter endp

pagafault_hook proc
;previous mode kernel mode ??
	test byte ptr [rsp + 2 * sizeof(QWORD)], 1
	je @noswap_prolog
	swapgs

@noswap_prolog:
	ENTER_HOOK_PROLOGUE	
	ENTER_HOOK PageFault
	
	test byte ptr  [rsp + 3 * sizeof(QWORD)], 1
	je @noswap_epilog
	swapgs

@noswap_epilog:
	cmp rax, 0
	ENTER_HOOK_EPILOGUE
	jz @access_allowed	
	
	ret 

@access_allowed:
	popptr;pop original nt!kipagefault
	popptr;previous mode
	iretq ; return back to user mode
pagafault_hook endp

;PATCHGUARD related
rdmsr_hook proc
	ENTER_HOOK_PROLOGUE
	ENTER_HOOK RdmsrHook
	ENTER_HOOK_EPILOGUE
	ret
rdmsr_hook endp

patchguard_hook proc
	ENTER_HOOK_PROLOGUE
	ENTER_HOOK PatchGuardHook
	ENTER_HOOK_EPILOGUE

	pop r11
	add r11, rsp
	mov rbx, [r11+38h]
	mov rsi, [r11+40h]
	mov rdi, [r11+48h]
	mov rsp, r11
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbp

	add rsp, 050h
	ret
patchguard_hook endp


;TEMP
get_ring3_rsp proc
	mov rax, qword ptr gs:[Ring3RSP]
	ret
get_ring3_rsp endp

disable_branchtrace proc
	int 3
	mov rax, dr7
	and eax, not ((1 shl 8) or (1 shl 9)) ;~0300h
	mov dr7, rax
	ret
disable_branchtrace endp

drx_test proc
	mov rax, dr7
	mov dr7, rax
	ret
drx_test endp

rtdsc_check proc
	push rsi
	lea rsi, [rsp + 066h]
	mov rdx, 0123h
	mov rax, 0666h
	rdtsc
	pop rsi
	ret
rtdsc_check endp

end