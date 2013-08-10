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
	__in CImage* img,
	__in ULONG_PTR reg[REG_COUNT],
	__in CLockedAVL<CIMAGEINFO_ID>& imgs
	)
{
	IRET* iret = PPAGE_FAULT_IRET(reg);
	DbgPrint("\n >>> @CallbackEvent!! %p %p [& %p]\n", reg[DBI_IOCALL], reg[DBI_ACTION], iret->Return);

	switch(reg[DBI_ACTION])
	{
	case SYSCALL_HOOK:
		{
			void* ret = reinterpret_cast<void*>(reg[DBI_RETURN] - SIZE_REL_CALL);
			DbgPrint("\n\ncheck hook : %p\n\n", ret);
			if (img->IsHooked(ret))
				img->UninstallHook(ret);

			BRANCH_INFO branch;
			branch.SrcEip = ret;
			branch.DstEip = ret;
			if (m_currentThreadInfo.SetContext(img->Is64(), reg, &branch))
			{
				iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

				DbgPrint("\n 1. EventCallback <SYSCALL_MAIN> : [%ws -> %p] <- %p [%p] %x\n", img->ImageName().Buffer, ret, reg[DBI_R3TELEPORT], reg, m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS]);
				break;
			}
			DbgPrint("\nEROOR\n");
			KeBreak();
		}
		return false;

	case SYSCALL_TRACE_FLAG:
		{
			BRANCH_INFO branch = CDbiMonitor::GetInstance().GetBranchStack().Pop();
			if (!CDbiMonitor::GetInstance().GetBranchStack().IsEmpty())
				KeBreak();

			if (m_currentThreadInfo.SetContext(img->Is64(), reg, &branch))
			{
				m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS] = branch.Flags;
				iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

				//temporary dbg info
				CIMAGEINFO_ID* img_id;
				CImage* dst_img;
				imgs.Find(CIMAGEINFO_ID(CRange<void>(branch.DstEip)), &img_id);
				dst_img = img_id->Value;
				CImage* src_img;
				imgs.Find(CIMAGEINFO_ID(CRange<void>(branch.SrcEip)), &img_id);
				src_img = img_id->Value;


				DbgPrint("\n EventCallback <SYSCALL_TRACE_FLAG : %p)> : >> %p [%ws] %p [%ws] [-> %p] %p | dbg -> %ws\n", 
					branch.Flags,
					branch.SrcEip, src_img->ImageName().Buffer, 
					branch.DstEip, dst_img->ImageName().Buffer, 
					reg[DBI_R3TELEPORT], reg, img->ImageName().Buffer);


				break;
			}
			DbgPrint("\nEROOR\n");
			KeBreak();
		}
		return false;

	case SYSCALL_TRACE_RET:
		{
			reg[DBI_IOCALL] = m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_IOCALL];
			reg[DBI_ACTION] = m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_ACTION];

			//routine params regs
			reg[RCX] = m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[RCX];
			reg[RDX] = m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[RDX];

			iret->Return = m_currentThreadInfo.DbiOutContext.LastBranchInfo.DstEip;
			iret->Flags = (m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS] | TRAP);

			DbgPrint("\n > !SYSCALL_TRACE_RET : %p %p %p %p %p [%x]\n", 
				iret->Return,
				iret->Flags,
				reg[DBI_IOCALL],
				reg[DBI_ACTION],
				reg[RCX],
				reg[RAX]);
			break;
		}
	case SYSCALL_PATCH_MEMORY:
	default:
		DbgPrint("\n >>> @CallbackEvent!! UNSUPPORTED");
		return false;
	}

	return true;

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
