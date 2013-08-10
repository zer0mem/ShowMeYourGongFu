.code

ext_trap_trace proc
	int 3
	mov rax, 0200h
	syscall
	int 3
ext_trap_trace endp

ext_info proc
	int 3
	mov rax, 0201h
	syscall
	int 3
ext_info endp

end
