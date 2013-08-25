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
EXTERN_C void patchguard_hook();


CDbiMonitor CDbiMonitor::m_instance;

CDbiMonitor::CDbiMonitor() :
	CSingleton(m_instance),
	m_branchInfo(KeQueryActiveProcessorCount(NULL))
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
		for (BYTE i = 0; i < m_branchInfo.GetCount(); i++, v_cpu++)
		{

#if HYPERVISOR

			if (v_cpu->VirtualizationON())

#endif

			{
				int CPUInfo[4] = {0};
				int InfoType = 0;
				__cpuid(CPUInfo, InfoType);
				DbgPrint("\r\n~~~~~~~~~~~ CPUID (%i) : %s ~~~~~~~~~~~\r\n", i, CPUInfo);
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
	m_traps[VMX_EXIT_WRMSR] = (ULONG_PTR)DisableBTF;
	m_traps[VMX_EXIT_EXCEPTION] = (ULONG_PTR)TrapHandler;
	m_traps[VMX_EXIT_DRX_MOVE] = (ULONG_PTR)AntiPatchGuard;
	
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
/*
//hook after PG disabled ....
		GDT	idtr;
		sidt(&idtr);

		{
			CMdl mdl(reinterpret_cast<void*>(idtr.base), IDT_SIZE);
			GATE_DESCRIPTOR* idt = reinterpret_cast<GATE_DESCRIPTOR*>(mdl.WritePtr());
			if (idt)
			{
				PageFaultHandlerPtr[coreId] = reinterpret_cast<void*>(
					((((ULONG_PTR)idt[TRAP_page_fault].ExtendedOffset) << 32) | 
					(((ULONG)idt[TRAP_page_fault].Selector) << 16) | 
					idt[TRAP_page_fault].Offset));

				{
					//hook ...
					CDisableInterrupts cli_sti;
					idt[TRAP_page_fault].ExtendedOffset = (((ULONG_PTR)pagafault_hook) >> 32);
					idt[TRAP_page_fault].Offset = (WORD)(ULONG_PTR)pagafault_hook;
					idt[TRAP_page_fault].Selector = (WORD)(((DWORD)(ULONG_PTR)pagafault_hook) >> 16);
				}

			}
		}
*/
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
	if (coreId < MAX_PROCID)
		return CDbiMonitor::PageFaultHandlerPtr[coreId];
	return NULL;
}

void CDbiMonitor::SetPFHandler( 
	__in BYTE coreId,
	__in void* pfHndlr 
	)
{
	if (coreId < MAX_PROCID)
		CDbiMonitor::PageFaultHandlerPtr[coreId] = pfHndlr;
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
CStack<TRACE_INFO>& CDbiMonitor::GetBranchStack()
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
	TRACE_INFO branch_info = *CDbiMonitor::GetInstance().BranchInfoUnsafe(KeGetCurrentProcessorNumber());

	CProcess2Fuzz* fuzzed_proc;
	if (CDbiMonitor::GetInstance().GetProcess(PsGetCurrentProcessId(), &fuzzed_proc))
	{
		if (fuzzed_proc->Syscall(reg, &branch_info))
			return NULL;
	}
	else
	{
		if (FAST_CALL == reg[DBI_IOCALL] && (ULONG_PTR)PsGetCurrentProcessId() != reg[DBI_FUZZAPP_PROC_ID])
		{
			if (CDbiMonitor::GetInstance().GetProcess((HANDLE)reg[DBI_FUZZAPP_PROC_ID], &fuzzed_proc))
			{
				if (fuzzed_proc->Syscall(reg))
					return NULL;
			}
		}
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
	//PageFault hooked == BranchInfo have to find valid ptr
	TRACE_INFO branch_info = *CDbiMonitor::GetInstance().BranchInfoUnsafe(KeGetCurrentProcessorNumber());

	BYTE* fault_addr = reinterpret_cast<BYTE*>(readcr2());
	PFIRET* iret = PPAGE_FAULT_IRET(reg);

	//in kernelmode can cause another PF and skip recursion handling :P

	//previous mode == usermode ?
#define USER_MODE_CS 0x1
	if (iret->CodeSegment & USER_MODE_CS)//btf HV callback
	{
		CProcess2Fuzz* fuzzed_proc;
		if (CDbiMonitor::GetInstance().GetProcess(PsGetCurrentProcessId(), &fuzzed_proc))
		{
			//DbgPrint("\nPageFault in monitored process %p %x\n", fault_addr, PsGetCurrentProcessId());
			if (fuzzed_proc->PageFault(fault_addr, reg, &branch_info))
				return NULL;
		}
		else
		{
			if (FAST_CALL == reg[DBI_IOCALL] && (ULONG_PTR)PsGetCurrentProcessId() != reg[DBI_FUZZAPP_PROC_ID])
			{
				if (CDbiMonitor::GetInstance().GetProcess((HANDLE)reg[DBI_FUZZAPP_PROC_ID], &fuzzed_proc))
				{
					if (fuzzed_proc->PageFault(fault_addr, reg))
						return NULL;
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
			//set-up next BTF hook
			ULONG_PTR rflags = 0;
			if (!vmread(VMX_VMCS_GUEST_RFLAGS, &rflags))
			{
				if (rflags & TRAP)
				{
					ins_addr -= ins_len;

					ULONG_PTR src = (ULONG_PTR)MM_LOWEST_USER_ADDRESS;
					ULONG_PTR msr_btf_part;
					vmread(VMX_VMCS_GUEST_DEBUGCTL_FULL, &msr_btf_part);
					if (msr_btf_part & BTF)
					{
						for (BYTE i = (BYTE)rdmsr(MSR_LASTBRANCH_TOS); i >= 0; i--)
						{
							if (rdmsr(MSR_LASTBRANCH_0_TO_IP + i) == ins_addr)
							{
								src = rdmsr(MSR_LASTBRANCH_0_FROM_IP + i);
								break;
							}
						}
					}
					else
					{
						vmwrite(VMX_VMCS_GUEST_DEBUGCTL_FULL, (msr_btf_part | BTF | LBR));
					}

					if (CRange<void>(MM_LOWEST_USER_ADDRESS, MM_HIGHEST_USER_ADDRESS).IsInRange(reinterpret_cast<void*>(src)))
					{
						TRACE_INFO* branch_i = CDbiMonitor::GetInstance().BranchInfoUnsafe(CVirtualizedCpu::GetCoreId(reg));
						if (branch_i)
						{
							if (!vmread(VMX_VMCS64_GUEST_RSP, &branch_i->StackPtr))
							{
								branch_i->Eip.Value = reinterpret_cast<const void*>(ins_addr);
								branch_i->PrevEip.Value = reinterpret_cast<const void*>(src);

								branch_i->Flags.Value = rflags;

								//disable trap flag and let handle it by PageFault Hndlr
								vmwrite(VMX_VMCS_GUEST_RFLAGS, (rflags & (~TRAP)));
								//set eip to non-exec mem for quick recognization by PageFault handler
								vmwrite(VMX_VMCS64_GUEST_RIP, branch_i->StackPtr.Value);
								return;
							}
						}
					}
				}
			}
		}
	}

	ULONG_PTR rflags = 0;
	vmread(VMX_VMCS_GUEST_RFLAGS, &rflags);
	vmwrite(VMX_VMCS_GUEST_RFLAGS, (rflags & (~TRAP)));
	vmwrite(VMX_VMCS64_GUEST_RIP, FAST_CALL);
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
	KeBreak();

	WORD ebfe = 0xFEEB;
	memcpy(ret, &ebfe, sizeof(ebfe));

	BYTE core_id = 0;
	CProcessorWalker cpu_w;
	while (cpu_w.NextCore(&core_id, core_id))
	{

		KeSetSystemAffinityThread(PROCID(core_id));

		GDT	idtr;
		sidt(&idtr);

		{
			CMdl mdl(reinterpret_cast<void*>(idtr.base), IDT_SIZE);
			GATE_DESCRIPTOR* idt = reinterpret_cast<GATE_DESCRIPTOR*>(mdl.WritePtr());
			if (idt)
			{
				CDbiMonitor::GetInstance().SetPFHandler( core_id, reinterpret_cast<void*>(
					((((ULONG_PTR)idt[TRAP_page_fault].ExtendedOffset) << 32) | 
					(((ULONG)idt[TRAP_page_fault].Selector) << 16) | 
					idt[TRAP_page_fault].Offset)) );

				//hook ...
				{
					CDisableInterrupts cli_sti;
					idt[TRAP_page_fault].ExtendedOffset = (((ULONG_PTR)pagafault_hook) >> 32);
					idt[TRAP_page_fault].Offset = (WORD)(ULONG_PTR)pagafault_hook;
					idt[TRAP_page_fault].Selector = (WORD)(((DWORD)(ULONG_PTR)pagafault_hook) >> 16);
				}
			}
		}

		core_id++;//follow with next core
	}

	return ret;
}

//II. TODO : patchguard drx callback
///...

//-----------------------------------------------------------
// ****************** HYPERVISOR CALLBACKS ******************
//-----------------------------------------------------------

void CDbiMonitor::DisableBTF( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	if (IA32_DEBUGCTL == reg[RCX])
	{
		//handle just dword-low
		ULONG_PTR msr_btf_part;
		vmread(VMX_VMCS_GUEST_DEBUGCTL_FULL, &msr_btf_part);
		reg[RAX] &= msr_btf_part;

		vmwrite(VMX_VMCS_GUEST_DEBUGCTL_FULL, reg[RAX]);
		vmread(VMX_VMCS_GUEST_DEBUGCTL_HIGH, &reg[RDX]);
	}

	wrmsr((ULONG)reg[RCX], (reg[RDX] << 32) | (ULONG)reg[RAX]);
}

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
EXTERN_C void* PatchGuardHook( 
	__inout ULONG_PTR reg[REG_COUNT]
	)
{
	DbgPrint("\n >>>>>> PatchGuardHook %p\n\n", reg);
	KeBreak();
	return NULL;
}

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

void CDbiMonitor::AntiPatchGuard( 
	__inout ULONG_PTR reg[REG_COUNT] 
)
{
	/*
	ULONG_PTR ins_len;
	vmread(VMX_VMCS32_RO_EXIT_INSTR_LENGTH, &ins_len);
	vmread(VMX_VMCS64_GUEST_RIP, &reg[RCX]);//original 'ret'-addr
	*/
	vmwrite(VMX_VMCS64_GUEST_RIP, patchguard_hook);//trampoline to 	PatchGuardHook
}
