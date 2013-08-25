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

CThreadEvent::CThreadEvent(
	__in HANDLE threadId, 
	__in HANDLE parentProcessId
	) : THREAD_INFO(threadId, parentProcessId),
		m_currentThreadInfo(PsGetCurrentProcessId()),
		m_monitorThreadInfo(parentProcessId),
		m_ethread(threadId)
{
}


void CThreadEvent::SetMemoryAccess( 
	__in const BYTE* faultAddr,
	__in ULONG access,
	__in const void* begin,
	__in size_t size

	)
{
	m_currentThreadInfo.DbiOutContext.MemoryInfo.Memory = faultAddr;
	m_currentThreadInfo.DbiOutContext.MemoryInfo.Access = access;
	m_currentThreadInfo.DbiOutContext.MemoryInfo.Begin = begin;
	m_currentThreadInfo.DbiOutContext.MemoryInfo.Size = size;
}

//--------------------------------------------------------
// ****************** DBI TRACE HELPERS ******************
//--------------------------------------------------------

__checkReturn 
bool CThreadEvent::FlipSemaphore( 
	__in const EVENT_THREAD_INFO& eventThreadInfo
	)
{
	if (eventThreadInfo.EventSemaphor)
	{
		CEProcess eprocess(eventThreadInfo.ProcessId);
		CAutoEProcessAttach process(eprocess);
		if (eprocess.IsAttached())
		{
			CMdl event_semaphor(eventThreadInfo.EventSemaphor, sizeof(BYTE));
			volatile CHAR* semaphor = reinterpret_cast<volatile CHAR*>(event_semaphor.Map());
			if (semaphor)
			{
				return (0 == InterlockedExchange8(semaphor, 1));
			}
		}
	}
	return false;
}

void CThreadEvent::SetIret( 
	__in bool is64, 
	__inout void* iretAddr, 
	__in const void* iret, 
	__in ULONG_PTR segSel, 
	__in ULONG_PTR flags 
	)
{
	size_t iret_size = IRetCount * (is64 ? sizeof(ULONG_PTR) : sizeof(ULONG));
	CMdl r_auto_context(reinterpret_cast<const void*>(iretAddr), iret_size);
	void* iret_ctx = r_auto_context.Map();
	if (iret_ctx)
	{
		if (is64)
			SetIret<ULONG_PTR>(reinterpret_cast<ULONG_PTR*>(iret_ctx), iret, segSel, flags);
		else
			SetIret<ULONG>(reinterpret_cast<ULONG*>(iret_ctx), iret, segSel, flags);
	}
}


//----------------------------------------------------------------------
// ****************** MONITOR DLL INJECTED DBI HELPER ******************
//----------------------------------------------------------------------

__checkReturn
bool CThreadEvent::HookEvent(
	__in CImage* img, 
	__in ULONG_PTR reg[REG_COUNT],
	CLockedAVL<CMemoryRange>* m_nonWritePages
	)
{
	PFIRET* iret = PPAGE_FAULT_IRET(reg);
	void* ret = reinterpret_cast<void*>(reg[DBI_RETURN] - SIZE_REL_CALL);
	DbgPrint("\n\ncheck hook : %p\n\n", ret);
	
	if (img->IsHooked(ret))
	{
		img->UninstallHook(ret);
		DbgPrint("\nunhooked! %p\n", ret);
	}

	BRANCH_INFO branch;
	branch.SrcEip = ret;
	branch.DstEip = ret;
	if (m_currentThreadInfo.SetContext(img->Is64(), reg, &branch))
	{
		iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);
		
		SetIret(img->Is64(), reinterpret_cast<void*>(reg[DBI_IRET]), ret, iret->CodeSegment, m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS] | TRAP);

		DbgPrint("\n 1. EventCallback <SYSCALL_MAIN> : [%ws -> %p] <- %p [%p] %x\n", img->ImageName().Buffer, ret, reg[DBI_R3TELEPORT], reg, m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS]);

		if (!FlipSemaphore(m_monitorThreadInfo))
		{
			DbgPrint("\nUnFlipped semaphore ...\n");
		}

		return true;
	}

	KeBreak();
	DbgPrint("\nEROOR\n");
	return false;
}

__checkReturn
bool CThreadEvent::SmartTraceEvent( 
	__in CImage* img, 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const BRANCH_INFO& branchInfo
	)
{
	PFIRET* iret = PPAGE_FAULT_IRET(reg);

	BRANCH_INFO branch = branchInfo;

	if (m_currentThreadInfo.SetContext(img->Is64(), reg, &branch))
	{
		m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS] = branch.Flags;
		iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

		SetIret(img->Is64(), reinterpret_cast<void*>(reg[DBI_IRET]), branch.DstEip, iret->CodeSegment, branch.Flags);
	
		if (!FlipSemaphore(m_monitorThreadInfo))
		{
			DbgPrint("\nUnFlipped semaphore ...\n");
		}

		return true;
	}

	KeBreak();
	DbgPrint("\nEROOR\n");
	return false;
}


//----------------------------------------------------------
// ****************** MONITOR DLL DBI API ******************
//----------------------------------------------------------

//invoked from monitor
__checkReturn
bool CThreadEvent::SmartTrace( 
	__in ULONG_PTR reg[REG_COUNT]
)
{
	PFIRET* iret = PPAGE_FAULT_IRET(reg);
	m_monitorThreadInfo.ProcessId = PsGetCurrentProcessId();
	m_monitorThreadInfo.EventSemaphor = reinterpret_cast<void*>(reg[DBI_SEMAPHORE]);

	m_currentThreadInfo.DumpContext(reg);

	iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

	bool dbg_cont = FlipSemaphore(m_currentThreadInfo);
	if (!dbg_cont)
		KeBreak();
	return true;
}

void CThreadEvent::MemoryProtectionEvent( 
	__in void* memory, 
	__in size_t size, 
	__in bool write, 
	__in ULONG_PTR reg[REG_COUNT] 
	)
{
}
