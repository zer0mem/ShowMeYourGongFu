/**
* @file CSysCall.cpp
* @author created by: Peter Hlavaty
*/

#include "StdAfx.h"

#include "DbiMonitor.h"
#include "../../Common/Kernel/IRQL.hpp"
#include "../../Common/CPU/msr.h"
#include "../../Common/Kernel/MemoryMapping.h"

#include "../../Common/utils/Undoc.hpp"
#include "Common/Constants.h"
#include "../../Common/FastCall/FastCall.h"

EXTERN_C void sysenter();
EXTERN_C void rdmsr_hook();
EXTERN_C void pagafault_hook();


CDbiMonitor CDbiMonitor::m_instance;

CDbiMonitor::CDbiMonitor() 
	: CSingleton(m_instance)
{
	RtlZeroMemory(m_syscalls, sizeof(m_syscalls));
}

CDbiMonitor::~CDbiMonitor()
{
	BYTE core_id = 0;
	CProcessorWalker cpu_w;
	while (cpu_w.NextCore(&core_id, core_id))
	{
		KeSetSystemAffinityThread(PROCID(core_id));

		HookSyscallMSR(m_syscalls[core_id]);

		DbgPrint("Unhooked. procid [%x] <=> syscall addr [%p]\n", core_id, m_syscalls[core_id]);

		core_id++;//follow with next core
	}
}

//----------------------------------------------------------------
// ****************** INSTALLATION - HV + HOOKS ******************
//----------------------------------------------------------------

void CDbiMonitor::Install()
{
	ASSERT(CUndoc::IsInitialized());

	if (CCRonos::EnableVirtualization())
	{
		CVirtualizedCpu* v_cpu = m_vCpu;
		for (BYTE i = 0; i < m_vCpuCount; i++, v_cpu++)
		{

#if HYPERVISOR

			if (v_cpu->VirtualizationON())

#endif

			{
				int CPUInfo[4] = {0};
				int InfoType = 0;
				__cpuid(CPUInfo, InfoType);
				DbgPrint("\r\n~~~~~~~~~~~ CPUID (%i) : %s ~~~~~~~~~~~\r\n", i, CPUInfo);

				HookSyscallMSR(sysenter);
				DbgPrint("II. procid [%x] <=> syscall addr [%p]\n\n", i, (ULONG_PTR)rdmsr(IA64_SYSENTER_EIP));		
			}
		}
	}

}

__checkReturn 
bool CDbiMonitor::SetVirtualizationCallbacks()
{
	DbgPrint("CSysCall::SetVirtualizationCallbacks\n");

	if (!CCRonos::SetVirtualizationCallbacks())
		return false;

	m_traps[VMX_EXIT_RDMSR] = (ULONG_PTR)HookProtectionMSR;
	m_traps[VMX_EXIT_EXCEPTION] = (ULONG_PTR)TrapHandler;
	
	//m_traps[VMX_EXIT_EPT_VIOLATION] = (ULONG_PTR)PageFaultHandler;

	return RegisterCallback(m_callbacks, CPUIDCALLBACK);
}

void CDbiMonitor::PerCoreAction( 
	__in BYTE coreId 
	)
{
	CCRonos::PerCoreAction(coreId);

	if (coreId < sizeof(m_syscalls))
	{
		KeSetSystemAffinityThread(PROCID(coreId));

		//set branching on basig blocks!!! + turn on last branch stack!
		wrmsr(IA32_DEBUGCTL, (rdmsr(IA32_DEBUGCTL) | BTF | LBR));
		//rdmsr / wrmsr dont affect guest MSR!!!!!!!

		GDT	idtr;
		sidt(&idtr);

		{
			CApcLvl irql;
			CMdl mdl((void*)idtr.base, IDT_SIZE);
			GATE_DESCRIPTOR* idt = (GATE_DESCRIPTOR*)mdl.Map();
			if (idt)
			{
				PageFaultHandlerPtr[coreId] = reinterpret_cast<void*>(
												((((ULONG_PTR)idt[TRAP_page_fault].ExtendedOffset) << 32) | 
												(((ULONG)idt[TRAP_page_fault].Selector) << 16) | 
												idt[TRAP_page_fault].Offset));

				//hook ...
				idt[TRAP_page_fault].ExtendedOffset = (((ULONG_PTR)pagafault_hook) >> 32);
				idt[TRAP_page_fault].Offset = (WORD)(ULONG_PTR)pagafault_hook;
				idt[TRAP_page_fault].Selector = (WORD)(((DWORD)(ULONG_PTR)pagafault_hook) >> 16);
			}
		}

		m_syscalls[coreId] = (void*)rdmsr(IA64_SYSENTER_EIP);
		HookSyscallMSR(sysenter);
		DbgPrint("Hooked. procid [%x] <=> syscall addr [%p]\n", coreId, m_syscalls[coreId]);
	}
}



//----------------------------------------------
// ****************** GETTERS ******************
//----------------------------------------------

void* CDbiMonitor::GetSysCall( 
	__in BYTE coreId 
	)
{
	if (coreId > MAX_PROCID)
		return NULL;

	return CDbiMonitor::m_syscalls[coreId];
}

void CDbiMonitor::HookSyscallMSR(
	__in const void* hook
	)
{
	CDisableInterrupts idis;
	wrmsr(IA64_SYSENTER_EIP, (ULONG_PTR)hook);
}


void* CDbiMonitor::GetPFHandler( 
	__in BYTE coreId 
	)
{
	if (coreId > MAX_PROCID)
		return NULL;

	return CDbiMonitor::PageFaultHandlerPtr[coreId];
}

//getter
__checkReturn
bool CDbiMonitor::GetProcess( 
	__in HANDLE processId,
	__inout CProcess2Fuzz** process
	)
{
	return m_procMonitor.GetProcessWorker().GetProcess(processId, process);
}

//dbgprint helper
CStack<BRANCH_INFO>& CDbiMonitor::GetBranchStack()
{
	return m_branchStack;
}


//-----------------------------------------------------------
// ****************** MONITORING CALLBACKS ******************
//-----------------------------------------------------------


//handle virtual protection / allocation methods
EXTERN_C void* SysCallCallback( 
	__inout ULONG_PTR reg [REG_COUNT]
	)
{
	CProcess2Fuzz* fuzzed_proc;
	if (CDbiMonitor::GetInstance().GetProcess(PsGetCurrentProcessId(), &fuzzed_proc))
	{
		if (fuzzed_proc->Syscall(reg))
			return NULL;
	}

	ULONG core_id = KeGetCurrentProcessorNumber();
	if (core_id > MAX_PROCID)
		core_id = 0;//incorrect ... TODO ...
	
	return CDbiMonitor::GetInstance().GetSysCall((BYTE)core_id);
}

//handle acces to protected memory
EXTERN_C void* PageFault(
	__inout ULONG_PTR reg[REG_COUNT]
	)
{
	BYTE* fault_addr = reinterpret_cast<BYTE*>(readcr2());
#define USER_MODE_CS 0x1
	IRET* iret = PPAGE_FAULT_IRET(reg);

	for (int i = 0; !CDbiMonitor::GetInstance().PrintfStack.IsEmpty() && i < 0x10; i++)
	{
		ULONG_PTR info = CDbiMonitor::GetInstance().PrintfStack.Pop();
		DbgPrint("\n >>PrintfStack : %p\n", info);
	}

	//in kernelmode can cause another PF and skip recursion handling :P

	//previous mode == usermode ?
	if (iret->CodeSegment & USER_MODE_CS)//btf HV callback
	{
		CProcess2Fuzz* fuzzed_proc;
		if (CDbiMonitor::GetInstance().GetProcess(PsGetCurrentProcessId(), &fuzzed_proc))
		{
			if (fuzzed_proc->PageFault(fault_addr, reg))
				return NULL;
		}
		else
		{
			if (FAST_CALL == reg[DBI_IOCALL])
			{
				KeBreak();
				if ((ULONG_PTR)PsGetCurrentProcessId() != reg[DBI_FUZZAPP_PROC_ID])
				{
					fuzzed_proc = NULL;
					(void)CDbiMonitor::GetInstance().GetProcess((HANDLE)reg[DBI_FUZZAPP_PROC_ID], &fuzzed_proc);
					if (fuzzed_proc)
					{
						if (fuzzed_proc->PageFault(fault_addr, reg))
							return NULL;
					}
					return NULL;//enum procid - threadid; but nothing monitored yet ...
				}
			}
		}
	}

	ULONG core_id = KeGetCurrentProcessorNumber();
	if (core_id > MAX_PROCID)
		core_id = 0;//incorrect ... TODO ...

	return CDbiMonitor::GetInstance().GetPFHandler((BYTE)core_id);
}

//trace code -> on branches ==> hypervisor mode!
void CDbiMonitor::TrapHandler( 
	__inout ULONG_PTR reg[REG_COUNT]
	)
{
	size_t ins_len;
	if (!vmread(VMX_VMCS32_RO_EXIT_INSTR_LENGTH, &ins_len))
	{
		ULONG_PTR ins_addr;
		if (!vmread(VMX_VMCS64_GUEST_RIP, &ins_addr))//original 'ret'-addr
		{
			ins_addr -= ins_len;

			ULONG_PTR src = 0;
			for (BYTE i = (BYTE)rdmsr(MSR_LASTBRANCH_TOS); i >= 0; i--)
			{
				if (rdmsr(MSR_LASTBRANCH_0_TO_IP + i) == ins_addr)
				{
					src = rdmsr(MSR_LASTBRANCH_0_FROM_IP + i);

					break;
				}
			}

			//set-up next BTF hook
			ULONG_PTR rflags = 0;
			if (!vmread(VMX_VMCS_GUEST_RFLAGS, &rflags))
			{					
				if (rflags & TRAP)
				{
					if (CRange<void>(MM_LOWEST_USER_ADDRESS, MM_HIGHEST_USER_ADDRESS).IsInRange(reinterpret_cast<void*>(src)))
					{
						CDbiMonitor::GetInstance().PrintfStack.Push(0x87654321);
						CDbiMonitor::GetInstance().PrintfStack.Push(src);
						CDbiMonitor::GetInstance().PrintfStack.Push(ins_addr);
						CDbiMonitor::GetInstance().PrintfStack.Push(rflags);
						CDbiMonitor::GetInstance().PrintfStack.Push(rdmsr(MSR_LASTBRANCH_TOS));

						BRANCH_INFO branch_i;
						branch_i.DstEip = reinterpret_cast<const void*>(ins_addr);
						branch_i.SrcEip = reinterpret_cast<const void*>(src);
						branch_i.Flags = rflags;
						CDbiMonitor::GetInstance().GetBranchStack().Push(branch_i);
						ins_addr = FAST_CALL;

						//disable trap flag and let handle it by PageFault Hndlr
						vmwrite(VMX_VMCS_GUEST_RFLAGS, (rflags & (~TRAP)));
					}
				}
			}

			vmwrite(VMX_VMCS64_GUEST_RIP, ins_addr);
		}
	}
}

//-----------------------------------------------------------
// ****************** PATCHGUARD CALLBACKS ******************
//-----------------------------------------------------------

//I. little bit another kind of hook -virtualization-based- :P
EXTERN_C void* RdmsrHook( 
	__inout ULONG_PTR reg[REG_COUNT]
	)
{
	void* ret = (void*)reg[RCX];
	DbgPrint("\nRdmsrHook %p [pethread : %p] -> dst = %p\n", ret, PsGetCurrentThread(), reg[RAX]);
	reg[RCX] = IA64_SYSENTER_EIP;
	//KeBreak();
	return ret;
}

//II. TODO : patchguard drx callback
///...

//-----------------------------------------------------------
// ****************** HYPERVISOR CALLBACKS ******************
//-----------------------------------------------------------

//pageguard - alice in wonderland

//I. rdmsr
void CDbiMonitor::HookProtectionMSR( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	ULONG_PTR syscall;
	if (IA64_SYSENTER_EIP == reg[RCX])
	{
		syscall = (ULONG_PTR)CDbiMonitor::GetInstance().GetSysCall(CVirtualizedCpu::GetCoreId(reg));

		ULONG_PTR ins_len;
		vmread(VMX_VMCS32_RO_EXIT_INSTR_LENGTH, &ins_len);
		vmread(VMX_VMCS64_GUEST_RIP, &reg[RCX]);//original 'ret'-addr
		//m_sRdmsrRips.Push(reg[RCX] - ins_len);

		vmwrite(VMX_VMCS64_GUEST_RIP, rdmsr_hook);//rdmsr_hook is trampolie to RdmsrHook
	}
	else
	{
		syscall = rdmsr((ULONG)reg[RCX]);
	}

	reg[RAX] = (ULONG_PTR)(syscall);
	reg[RDX] = (ULONG)(syscall >> (sizeof(ULONG) << 3));
}

//II. TODO : drx acces for avoiding detection of IDT[PageFault] hook 
//...


//----------------------------------------------------------------
// ****************** R3 -> HYPERVISOR FASTCALL ******************
//----------------------------------------------------------------

void CDbiMonitor::CPUIDCALLBACK( 
	__inout ULONG_PTR reg[REG_COUNT]
	)
{
	ULONG_PTR ExitReason;
	vmread(VMX_VMCS32_RO_EXIT_REASON, &ExitReason);

	if (VMX_EXIT_CPUID == ExitReason)
	{
		if (0xBADF00D0 == (ULONG)reg[RAX])
		{
			reg[RBX] = 0xBADF00D0;

			//CDbiMonitor::GetInstance().PrintfStack.Push(0xDEADCAFE);

			ULONG_PTR rflags = 0;
			vmread(VMX_VMCS_GUEST_RFLAGS, &rflags);
			vmwrite(VMX_VMCS_GUEST_RFLAGS, (rflags | TRAP));
		}
	}
}
