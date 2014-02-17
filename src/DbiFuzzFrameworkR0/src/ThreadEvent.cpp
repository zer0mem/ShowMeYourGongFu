/**
 * @file ThreadEvent.cpp
 * @author created by: Peter Hlavaty
 */

#include "drv_common.h"

#include "ThreadEvent.h"
#include "../../Common/FastCall/FastCall.h"
#include "../../Common/Kernel/Process.hpp"
#include "../../Common/Kernel/MemoryMapping.h"

#include "../../minihypervisor/MiniHyperVisorProject/HyperVisor/Common/base/HVCommon.h"

EXTERN_C void syscall_instr_prologue();
EXTERN_C void syscall_instr_epilogue();

#include "DbiMonitor.h"

CThreadEvent::CThreadEvent(
	__in HANDLE threadId, 
	__in HANDLE parentProcessId
	) : THREAD_INFO(threadId, parentProcessId),
		m_dbgThreadInfo(PsGetCurrentProcessId()),
		m_dbiThreadInfo(parentProcessId),
		m_ethread(threadId),
		m_resolved(false)
{
	CDbiMonitor::CreateThread();
}

CThreadEvent::~CThreadEvent()
{
	CDbiMonitor::RemoveThread();
}

//--------------------------------------------------------
// ****************** DBI TRACE HELPERS ******************
//--------------------------------------------------------

__checkReturn 
bool EVENT_THREAD_INFO::FlipSemaphore()
{
/*
//when trace r0
			KeBreak();
			KeResetEvent(&m_dbgThreadInfo.SyncEvent);
			KeSetEvent(&m_dbiThreadInfo.SyncEvent, MAXIMUM_PRIORITY, TRUE);
			KeWaitForSingleObject(&m_dbgThreadInfo.SyncEvent, Executive, KernelMode, FALSE, 0);
*/
	if (EventSemaphor)
	{
		CAutoProcessIdAttach eprocess(ProcessId);
		if (eprocess.IsAttached())
		{
			CMdl event_semaphor(EventSemaphor, sizeof(BYTE));
			volatile CHAR* semaphor = static_cast<volatile CHAR*>(event_semaphor.WritePtr());
			if (semaphor)
				return (0 == InterlockedExchange8(semaphor, 1));
		}
	}
	return false;
}


//----------------------------------------------------------------------
// ****************** MONITOR DLL INJECTED DBI HELPER ******************
//----------------------------------------------------------------------

__checkReturn
bool CThreadEvent::RegisterMemoryAccess( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const BYTE* faultAddr, 
	__in CMemoryRange* mem,
	__in PFIRET* pfIRet 
	)
{
	if (m_dbgThreadInfo.LoadPFContext(reg, mem, pfIRet, faultAddr))
	{
		m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo);
		return m_dbiThreadInfo.FlipSemaphore();//if no monitor-thread set fot this target-thread, then just freeze target-thread		
	}
	return false;
}

__checkReturn
bool DBG_THREAD_EVENT::LoadPFContext( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in CMemoryRange* mem, 
	__in PFIRET* pfIRet,
	__in const BYTE* faultAddr
	)
{
	RtlZeroMemory(&DbiOutContext, sizeof(DbiOutContext));
	DbgPrint("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n@@ MEMORY BP : %p [%x   / %p]\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n", mem->Begin(), mem->GetSize(), mem->GetFlags());
	DbiOutContext.TraceInfo.StateInfo = *pfIRet;
	DbiOutContext.MemoryInfo.Memory = faultAddr;
	DbiOutContext.MemoryInfo.Begin = mem->Begin();
	DbiOutContext.MemoryInfo.Size = mem->GetSize();
	DbiOutContext.MemoryInfo.Flags = static_cast<ULONG>(mem->GetFlags());
	DbiOutContext.MemoryInfo.OriginalValue = 0;
	DbiOutContext.TraceInfo.Reason = MemoryAcces;

	if (CMMU::IsAccessed(faultAddr) && !CMMU::IsValid(faultAddr))
	{
		CMMU::SetValid(mem->Begin(), mem->GetSize());

		CApcLvl irql;
		CMdl mdl(faultAddr, sizeof(ULONG_PTR));
		const ULONG_PTR* val = static_cast<const ULONG_PTR*>(mdl.ForceReadPtrUser());
		if (val)
			DbiOutContext.MemoryInfo.OriginalValue = *val;

		DbgPrint("\nafter read %p\n", *val);

		CMMU::SetInvalid(faultAddr, sizeof(ULONG_PTR));
	}

	pfIRet->IRet.StackPointer = &pfIRet->IRet.StackPointer[-(IRetCount + REG_COUNT + 1)];
	pfIRet->IRet.Flags &= ~TRAP;
	return LoadContext(reg);
}

__checkReturn
bool CThreadEvent::SmartTraceEvent( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const TRACE_INFO* branchInfo, 
	__in const PFIRET* pfIRet 
	)
{
	if (m_dbgThreadInfo.LoadTrapContext(reg, branchInfo, pfIRet))
	{
		m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo);
		//return m_dbiThreadInfo.FlipSemaphore();//if no monitor-thread set for this target-thread, then just freeze target-thread
		m_dbiThreadInfo.FlipSemaphore();//if no monitor-thread set for this target-thread, then just freeze target-thread
		return true;
	}
	return false;
}

__checkReturn
bool DBG_THREAD_EVENT::LoadTrapContext( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const TRACE_INFO* branchInfo, 
	__in const PFIRET* pfIRet 
	)
{
	RtlZeroMemory(&DbiOutContext, sizeof(DbiOutContext));
	//save info from VMM trap handler
	DbiOutContext.TraceInfo = *branchInfo;
	//cs and ss obtain here, exec as few instructions in VMM as possible ...
	DbiOutContext.TraceInfo.StateInfo.IRet.CodeSegment = pfIRet->IRet.CodeSegment;
	DbiOutContext.TraceInfo.StateInfo.IRet.StackSegment = pfIRet->IRet.StackSegment;

	if (branchInfo->StateInfo.IRet.Flags & TRAP)
		DbiOutContext.TraceInfo.Reason = branchInfo->PrevEip ? BranchTraceFlag : SingleTraceFlag;
	else
	{
		KeBreak();
		DbgPrint("\n--------------------------------------\n## DBG_THREAD_EVENT::LoadTrapContext HOOK!!\n----------------------------------------\n");
		DbiOutContext.TraceInfo.Reason = Hook;
	}

	RtlZeroMemory(&DbiOutContext.MemoryInfo, sizeof(DbiOutContext.MemoryInfo));
	return LoadContext(reg);
}


__checkReturn
bool CThreadEvent::IsNecessaryToFreeze()
{
	return (m_resolved && m_dbgThreadInfo.FreezeRequested);
}

void CThreadEvent::FreezeThreadRequest(
	__in ULONG_PTR reason
	)
{
	m_dbgThreadInfo.FreezeReason = reason;
	m_dbgThreadInfo.FreezeRequested = true;
}

__checkReturn
bool CThreadEvent::FreezeThread( 
	__in ULONG_PTR reg[REG_COUNT],
	__in PFIRET* pfIRet
	)
{
	if (m_dbgThreadInfo.LoadFreezedContext(reg, pfIRet))
	{
		m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo);
		(void)m_dbiThreadInfo.FlipSemaphore();//if no monitor-thread set fot this target-thread, then just freeze target-thread
		return true;
	}
	return false;
}

__checkReturn
bool DBG_THREAD_EVENT::LoadFreezedContext( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in PFIRET* pfIRet 
	)
{	
	RtlZeroMemory(&DbiOutContext, sizeof(DbiOutContext));

	DbiOutContext.TraceInfo.StateInfo = *pfIRet;
	DbiOutContext.TraceInfo.Reason = FreezeReason;

	//TODO : rethink -> probably this shoud be by defaul in func 'LoadContext', and kick it out from HV TrapHandler !
	pfIRet->IRet.StackPointer = &pfIRet->IRet.StackPointer[-(IRetCount + REG_COUNT + 1)];

	if (LoadContext(reg))
		FreezeRequested = false;

	return !FreezeRequested;
}

//----------------------------------------------------------
// ****************** MONITOR DLL DBI API ******************
//----------------------------------------------------------

bool CThreadEvent::Init( 
	__in ULONG_PTR reg[REG_COUNT]
	)
{
	if (m_dbiThreadInfo.LoadContext(reg))
	{
		m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo);//enter monitor-thread to the game
		return true;
	}
	return false;
}

//invoked from monitor
__checkReturn
bool CThreadEvent::SmartTrace( 
	__in ULONG_PTR reg[REG_COUNT]
	)
{
	if (m_dbiThreadInfo.LoadContext(reg))
		if (m_dbgThreadInfo.UpdateContext(reg, m_dbiThreadInfo))
			return m_dbgThreadInfo.FlipSemaphore();

	return false;
}

__checkReturn
bool DBI_THREAD_EVENT::LoadContext( 
	__in ULONG_PTR reg[REG_COUNT] 
	)
{
	ProcessId = PsGetCurrentProcessId();
	//semaphore should be on the top of the stack!
	EventSemaphor = reinterpret_cast<void*>(HOOK_ORIG_RSP(reg));
	ContextOnStack = reinterpret_cast<void*>(reg[DBI_PARAMS]);

	//load to dbioutcontext var
	CApcLvl irql;
	CMdl r_auto_context(ContextOnStack, sizeof(DbiOutContext));
	const DBI_OUT_CONTEXT* dbi_out_context = static_cast<const DBI_OUT_CONTEXT*>(r_auto_context.ReadPtrUser());
	if (dbi_out_context)
	{
		DbiOutContext = *dbi_out_context;
		return true;
	}

	return false;
}

bool DBI_THREAD_EVENT::UpdateContext( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const EVENT_THREAD_INFO& cthreadInfo 
	)
{
	CAutoProcessIdAttach eprocess(ProcessId);
	if (eprocess.IsAttached())
	{
		CMdl dbi_auto_context(ContextOnStack, sizeof(cthreadInfo.DbiOutContext));
		DBI_OUT_CONTEXT* dbi_context = static_cast<DBI_OUT_CONTEXT*>(dbi_auto_context.ForceWritePtrUser());
		if (dbi_context)
			*dbi_context = cthreadInfo.DbiOutContext;
	}
	return true;
}

__checkReturn
bool DBG_THREAD_EVENT::LoadContext( 
	__in ULONG_PTR reg[REG_COUNT]
	)
{
	//save context
	memcpy(DbiOutContext.GeneralPurposeContext, reg, sizeof(ULONG_PTR) * REG_X64_COUNT);

	ProcessId = PsGetCurrentProcessId(); // for sure here ??

	//usermode based offset -> ext_interface.asm responsible!!
	IRet = &DbiOutContext.TraceInfo.StateInfo.IRet.StackPointer[-IRetCount];
	ContextOnStack = &DbiOutContext.TraceInfo.StateInfo.IRet.StackPointer[-(IRetCount + REG_COUNT)];
	EventSemaphor = &DbiOutContext.TraceInfo.StateInfo.IRet.StackPointer[-(IRetCount + REG_COUNT + 1)];

	//flip semaphore to wait state!
	CApcLvl irql;
	CMdl semaphore_mdl(EventSemaphor, sizeof(ULONG_PTR));//semaphore
	ULONG_PTR* semaphore = static_cast<ULONG_PTR*>(semaphore_mdl.ForceWritePtrUser());
	if (semaphore)
	{
		*semaphore = 0;
		return true;
	}

	KeBreak();
	return false;
}

__checkReturn
bool DBG_THREAD_EVENT::UpdateContext( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const EVENT_THREAD_INFO& cthreadInfo 
	)
{
	CAutoProcessIdAttach eprocess(ProcessId);
	if (eprocess.IsAttached())
	{
		CMdl reg_auto_context(ContextOnStack, sizeof(DbiOutContext.GeneralPurposeContext));
		void* reg_context = reg_auto_context.WritePtr();
		if (reg_context)
		{
			//not necessary copy also DBI_FLAGS, because it is unused and rewriten by IRET in trace_event case ...
			memcpy(reg_context, cthreadInfo.DbiOutContext.GeneralPurposeContext, sizeof(ULONG_PTR) * REG_X64_COUNT);
			
			CMdl r_auto_context(IRet, sizeof(IRET));
			IRET* iret = static_cast<IRET*>(r_auto_context.ForceWritePtrUser());
			if (iret)
			{
				if (!cthreadInfo.DbiOutContext.TraceInfo.Btf)
					//disable BTF : not wrmsr but instead DEBUG REGISTERS!! -> per thread!
					//disable_branchtrace(); //-> VMX.cpp initialize vmm : vmwrite(VMX_VMCS64_GUEST_DR7, 0x400);
					wrmsr(IA32_DEBUGCTL, ~(BTF | LBR));//disable BTF -> special handling for wrmsr in HV
				else
					wrmsr(IA32_DEBUGCTL, (BTF | LBR));//enable BTF -> special handling for wrmsr in HV

				*iret = cthreadInfo.DbiOutContext.TraceInfo.StateInfo.IRet;

				//up to caller, if was thread in freezed state caller should now already about it ...
				//TODO -> FreezeRequested should to be member of DbiOutContext
				FreezeRequested = false;
			}

			return true;
		}
	}
	return false;
}
