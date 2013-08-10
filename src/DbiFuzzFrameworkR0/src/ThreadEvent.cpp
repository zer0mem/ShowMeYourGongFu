/**
 * @file ThreadEvent.cpp
 * @author created by: Peter Hlavaty
 */

#include "stdafx.h"

#include "ThreadEvent.h"
#include "../../Common/FastCall/FastCall.h"
#include "../../Common/Kernel/Process.hpp"
#include "../../Common/Kernel/MemoryMapping.h"

#include "../../HyperVisor/Common/base/HVCommon.h"

EXTERN_C void syscall_instr_prologue();
EXTERN_C void syscall_instr_epilogue();

//need to call _dynamic_initializer_for__cSyscallSize_
//static const size_t cSyscallSize = (ULONG_PTR)syscall_instr_epilogue - (ULONG_PTR)syscall_instr_prologue;
#define cSyscallSize ((ULONG_PTR)syscall_instr_epilogue - (ULONG_PTR)syscall_instr_prologue)

EXTERN_C ULONG_PTR* get_ring3_rsp();

CThreadEvent::CThreadEvent() : 
	THREAD_INFO(PsGetCurrentThreadId(), NULL),
	m_currentThreadInfo(NULL),
	m_monitorThreadInfo(NULL)
{
	WaitForSyscallCallback = false;
}

CThreadEvent::CThreadEvent(
	__in HANDLE threadId, 
	__in HANDLE parentProcessId /* = NULL */
	) : THREAD_INFO(threadId, parentProcessId),
		m_currentThreadInfo(PsGetCurrentProcessId()),
		m_monitorThreadInfo(parentProcessId)
{
	WaitForSyscallCallback = false;
}

__checkReturn
	bool CThreadEvent::WaitForSyscallEpilogue()
{
	return WaitForSyscallCallback;
}

void CThreadEvent::SetCallbackEpilogue( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in void* memory, 
	__in size_t size, 
	__in bool write, 
	__in_opt void* pageFault /*= NULL */ 
	)
{
	WaitForSyscallCallback = true;

	*GeneralPurposeContext = *reg;
	LastMemoryInfo.SetInfo(memory, size, write);

	//invoke SYSCALL again after syscall is finished!
	reg[RCX] -= cSyscallSize;
	/*
	ULONG_PTR* r3stack = get_ring3_rsp();
	//set return againt to SYSCALL instr
	*r3stack -= cSyscallSize;
	*/
}

void CThreadEvent::EpilogueProceeded()
{
	WaitForSyscallCallback = false;
}

//invoked from monitor
__checkReturn
bool CThreadEvent::MonitorFastCall( 
	__in LOADED_IMAGE* img,
	__in ULONG_PTR reg[REG_COUNT] 
	)
{
	KeBreak();
	DbgPrint("\nMonitorFastCall\n");
	switch(reg[RCX])
	{
	case SYSCALL_TRACE_FLAG:
		break;
	case SYSCALL_INFO_FLAG:
		break;
	default:
		return false;
	}

	//m_monitorThreadInfo.SetContext(reg);
	return FlipSemaphore(m_currentThreadInfo);
}

#include "DbiMonitor.h"
__checkReturn
bool CThreadEvent::EventCallback( 
	__in LOADED_IMAGE* img,
	__in ULONG_PTR reg[REG_COUNT],
	__in CLockedAVL<LOADED_IMAGE>& imgs
	)
{
	BRANCH_INFO* branch_info = NULL;
	MEMORY_ACCESS* mem_info = NULL;

	IRET* iret = PPAGE_FAULT_IRET(reg);
	//DbgPrint("\n >>> @CallbackEvent!! %p %p [& %p]\n", reg[DBI_IOCALL], reg[DBI_ACTION], iret->Return);

	size_t ctx_size = (img->Is64 ? sizeof(ULONG_PTR) * (REG_X64_COUNT + 1) : sizeof(ULONG) * (REG_X86_COUNT + 1));

	switch(reg[DBI_ACTION])
	{
	case SYSCALL_TRACE_RET:
		{
			reg[DBI_IOCALL] = m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_IOCALL];
			reg[DBI_ACTION] = m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_ACTION];

			//routine params regs
			reg[RCX] = m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[RCX];
			reg[RDX] = m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[RDX];

			iret->Return = m_currentThreadInfo.DbiOutContext.BranchInfo.DstEip;
			iret->Flags = (m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS] | TRAP);

			DbgPrint("\n > !SYSCALL_TRACE_RET : %p %p %p %p %p [%x]\n", 
				iret->Return,
				iret->Flags,
				reg[DBI_IOCALL],
				reg[DBI_ACTION],
				reg[RCX],
				reg[RAX]);

			//if fastcall implemented by page fault handler!!
			return true;
		}
		break;
	case SYSCALL_TRACE_FLAG:
		if (!CDbiMonitor::GetInstance().GetBranchStack().IsEmpty())
		{
			CMdl r_auto_context(reinterpret_cast<const void*>(reg[DBI_FUZZAPP_INFO_OUT]), ctx_size);
			void* r_context = r_auto_context.Map();
			if (r_context)
			{
				CRegXType regsx(img->Is64, r_context);

				BRANCH_INFO branch_i = CDbiMonitor::GetInstance().GetBranchStack().Pop();
				branch_info = &branch_i;

				if (!CDbiMonitor::GetInstance().GetBranchStack().IsEmpty())
					KeBreak();

				//TODO : disable trap flag in host when EIP is patched not here!!!!					
				/*
				* swap return & flags for RETF in ring3 [original order is knowingly bad]
				* set RETF to the DstEip
				*/
				/*
				ULONG_PTR flags = regsx.GetFLAGS();
				regsx.SetFLAGS(flags | TRAP);
				regsx.SetRET((ULONG_PTR)branch_i.DstEip);
				*/
				LOADED_IMAGE* dst_img;
				imgs.Find(LOADED_IMAGE(branch_i.DstEip), &dst_img);
				LOADED_IMAGE* src_img;
				imgs.Find(LOADED_IMAGE(branch_i.SrcEip), &src_img);

				//regsx.SetFLAGS(branch_i.Trap);

				iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);
				m_currentThreadInfo.SetContext(reg, regsx, branch_info, mem_info);

				DbgPrint("\n EventCallback <SYSCALL_TRACE_FLAG : [%p] %p %p %p (%p)> : \n >> %p [%ws] %p [%ws] [-> %p] %p %ws\n", 
					branch_i.Info, branch_i.Trap, regsx.GetFLAGS(), m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS], regsx.GetRSP(),
					branch_i.SrcEip, src_img->ImgName, 
					branch_i.DstEip, dst_img->ImgName, 
					reg[DBI_R3TELEPORT], reg, img->ImgName);

				if (0xCCCC == (0xFFFF & m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS]))
				{
					for (size_t i = 0; i < REG_COUNT + 1; i++)
					{
						DbgPrint("\n->%p %x %x\n", reg[i], regsx.GetReg(i), m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[i]);
					}
				}
				//if fastcall implemented by page fault handler!!
				return true;
			}
			break;
		}
		//return false//default handle it ...
	default:
		return false;
	case SYSCALL_PATCH_MEMORY:
		break;
	case SYSCALL_MAIN:
		{
			CMdl r_auto_context(reinterpret_cast<const void*>(reg[DBI_FUZZAPP_INFO_OUT]), ctx_size);
			void* r_context = r_auto_context.Map();
			if (r_context)
			{
				CRegXType regsx(img->Is64, r_context);
				DbgPrint("\n 1. EventCallback <SYSCALL_MAIN> : [-> %p] %p [%p]\n", reg[DBI_R3TELEPORT], reg, regsx.GetFLAGS());

				BRANCH_INFO branch_i;
				branch_i.SrcEip = reinterpret_cast<void*>((ULONG_PTR)img->ImageBase() + img->EntryPoint);//reinterpret_cast<void*>(regsx.GetRET() - SIZE_REL_CALL);
				branch_i.DstEip = branch_i.SrcEip;
				branch_info = &branch_i;

				regsx.SetRDI(0);

				iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);
				m_currentThreadInfo.SetContext(reg, regsx, branch_info, mem_info);

				DbgPrint("\n 2. EventCallback <SYSCALL_MAIN> :[-> %p] %p [%p (%p) vs %p]\n", branch_info->DstEip, reg, regsx.GetFLAGS(), regsx.GetRSP(), m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS]);
				//if fastcall implemented by page fault handler!!
				return true;
			}
		}
		break;
	}

	//if fastcall implemented by page fault handler!!
	return false;
	//m_currentThreadInfo.SetContext(reg);
	return FlipSemaphore(m_monitorThreadInfo);
}

__checkReturn 
bool CThreadEvent::FlipSemaphore( 
	__in const EVENT_THREAD_INFO& eventThreadInfo
	)
{
	CEProcess eprocess(eventThreadInfo.ProcessId);
	CAutoProcessAttach process(eprocess.GetEProcess());
	if (process.IsAttached())
	{
		CMdl event_semaphor(eventThreadInfo.EventSemaphor, sizeof(BYTE));
		volatile CHAR* semaphor = reinterpret_cast<volatile CHAR*>(event_semaphor.Map());
		if (semaphor)
		{
			return (0 == InterlockedExchange8(semaphor, 1));
		}
	}
	return false;
}
