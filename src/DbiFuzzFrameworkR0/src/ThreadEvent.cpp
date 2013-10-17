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

#include "DbiMonitor.h"

//need to call _dynamic_initializer_for__cSyscallSize_
//static const size_t cSyscallSize = (ULONG_PTR)syscall_instr_epilogue - (ULONG_PTR)syscall_instr_prologue;
#define cSyscallSize ((ULONG_PTR)syscall_instr_epilogue - (ULONG_PTR)syscall_instr_prologue)

CThreadEvent::CThreadEvent(
	__in HANDLE threadId, 
	__in HANDLE parentProcessId,
	__in CVadScanner& vad
	) : THREAD_INFO(threadId, parentProcessId),
		m_dbgThreadInfo(PsGetCurrentProcessId()),
		m_dbiThreadInfo(parentProcessId),
		m_ethread(threadId),
		m_initialized(false),
		m_vad(vad)
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
		CEProcess eprocess(ProcessId);
		CAutoEProcessAttach process(eprocess);
		if (eprocess.IsAttached())
		{
			CMdl event_semaphor(EventSemaphor, sizeof(BYTE));
			volatile CHAR* semaphor = reinterpret_cast<volatile CHAR*>(event_semaphor.WritePtr());
			if (semaphor)
			{
				return (0 == InterlockedExchange8(semaphor, 1));
			}
		}
	}
	return false;
}


//----------------------------------------------------------------------
// ****************** MONITOR DLL INJECTED DBI HELPER ******************
//----------------------------------------------------------------------

void CThreadEvent::RegisterMemoryAccess( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const BYTE* faultAddr, 
	__in CMemoryRange* mem,
	__in PFIRET* pfIRet 
	)
{
	if (m_dbgThreadInfo.LoadPFContext(reg, mem, pfIRet, faultAddr))
		if (m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo))
			(void)m_dbiThreadInfo.FlipSemaphore();//if no monitor-thread set fot this target-thread, then just freeze target-thread
}

__checkReturn
bool DBG_THREAD_EVENT::LoadPFContext( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in CMemoryRange* mem, 
	__in PFIRET* pfIRet,
	__in const BYTE* faultAddr
	)
{
	pfIRet->IRet.StackPointer = &pfIRet->IRet.StackPointer[-(IRetCount + REG_COUNT + 1)];
	DbiOutContext.TraceInfo.StateInfo = *pfIRet;
	DbiOutContext.MemoryInfo.Memory.Value = faultAddr;
	DbiOutContext.MemoryInfo.Begin.Value = mem->Begin();
	DbiOutContext.MemoryInfo.Size.Value = mem->GetSize();
	DbiOutContext.MemoryInfo.Flags.Value = static_cast<ULONG>(mem->GetFlags());
	DbiOutContext.MemoryInfo.OriginalValue.Value = 0;
	DbiOutContext.TraceInfo.Reason.Value = MemoryAcces;

	if (CMMU::IsAccessed(faultAddr))
	{
		CMMU::SetValid(faultAddr, sizeof(ULONG_PTR));

		CMdl mdl(faultAddr, sizeof(ULONG_PTR));
		const ULONG_PTR* val = reinterpret_cast<const ULONG_PTR*>(mdl.ReadPtr());
		if (val)
			DbiOutContext.MemoryInfo.OriginalValue.Value = *val;

		CMMU::SetInvalid(faultAddr, sizeof(ULONG_PTR));
	}

	return LoadContext(reg);
}

void CThreadEvent::HookEvent(
	__in ULONG_PTR reg[REG_COUNT], 
	__in PFIRET* pfIRet 
	)
{
	if (m_dbgThreadInfo.LoadHookContext(reg, pfIRet))
		if (m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo))
			(void)m_dbiThreadInfo.FlipSemaphore();//if no monitor-thread set fot this target-thread, then just freeze target-thread
}

__checkReturn
bool DBG_THREAD_EVENT::LoadHookContext( 
	__in ULONG_PTR reg[REG_COUNT],  
	__in PFIRET* pfIRet 
	)
{
	pfIRet->IRet.StackPointer = &pfIRet->IRet.StackPointer[-(IRetCount + REG_COUNT + 1)];
	DbiOutContext.TraceInfo.StateInfo = *pfIRet;
	DbiOutContext.TraceInfo.PrevEip.Value = 0;
	DbiOutContext.TraceInfo.Reason.Value = Hook;
	RtlZeroMemory(&DbiOutContext.MemoryInfo, sizeof(DbiOutContext.MemoryInfo));
	return LoadContext(reg);
}

__checkReturn
void CThreadEvent::SmartTraceEvent( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const TRACE_INFO* branchInfo, 
	__in const PFIRET* pfIRet 
	)
{
	if (m_dbgThreadInfo.LoadTrapContext(reg, branchInfo, pfIRet))
		if (m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo))
			(void)m_dbiThreadInfo.FlipSemaphore();//if no monitor-thread set fot this target-thread, then just freeze target-thread
}

__checkReturn
bool DBG_THREAD_EVENT::LoadTrapContext( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const TRACE_INFO* branchInfo, 
	__in const PFIRET* pfIRet 
	)
{
	//save info from VMM trap handler
	DbiOutContext.TraceInfo = *branchInfo;
	//cs and ss obtain here, exec as few instructions in VMM as possible ...
	DbiOutContext.TraceInfo.StateInfo.IRet.CodeSegment = pfIRet->IRet.CodeSegment;
	DbiOutContext.TraceInfo.StateInfo.IRet.StackSegment = pfIRet->IRet.StackSegment;

	if (DbiOutContext.TraceInfo.StateInfo.IRet.Flags & TRAP)
		DbiOutContext.TraceInfo.Reason.Value = branchInfo->PrevEip.Value ? BranchTraceFlag : SingleTraceFlag;
	else
	{
		KeBreak();
		DbiOutContext.TraceInfo.Reason.Value = Hook;
	}

	RtlZeroMemory(&DbiOutContext.MemoryInfo, sizeof(DbiOutContext.MemoryInfo));
	return LoadContext(reg);
}


//----------------------------------------------------------
// ****************** MONITOR DLL DBI API ******************
//----------------------------------------------------------

bool CThreadEvent::Init( 
	__in ULONG_PTR reg[REG_COUNT]
	)
{
	reinterpret_cast<EVENT_THREAD_INFO&>(m_dbiThreadInfo).LoadContext(reg);
	m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo);//enter monitor-thread to the game

	return m_initialized;
}

//invoked from monitor
__checkReturn
bool CThreadEvent::SmartTrace( 
	__in ULONG_PTR reg[REG_COUNT]
	)
{
	if (m_dbiThreadInfo.LoadContext(reg))
		if (m_dbgThreadInfo.UpdateContext(reg, m_dbiThreadInfo))
			return m_dbgThreadInfo.FlipSemaphore();//if no target-thread ready then invoke exc to the monitor-thread!

	return false;
}

__checkReturn
bool DBI_THREAD_EVENT::LoadContext( 
	__in ULONG_PTR reg[REG_COUNT]
	)
{
	ProcessId = PsGetCurrentProcessId();
	EventSemaphor = reinterpret_cast<void*>(reg[DBI_SEMAPHORE]);
	ContextOnStack = reinterpret_cast<void*>(reg[DBI_PARAMS]);

	//load to dbioutcontext var
	CMdl r_auto_context(ContextOnStack, sizeof(DbiOutContext));
	const DBI_OUT_CONTEXT* dbi_out_context = reinterpret_cast<const DBI_OUT_CONTEXT*>(r_auto_context.ReadPtrUser());
	if (dbi_out_context)
	{
		DbiOutContext = *dbi_out_context;
		return true;
	}

	return false;
}

__checkReturn
bool DBI_THREAD_EVENT::UpdateContext( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const EVENT_THREAD_INFO& cthreadInfo 
	)
{
	CEProcess eprocess(ProcessId);
	CAutoEProcessAttach attach2process(eprocess);
	if (eprocess.IsAttached())
	{
		CMdl dbi_auto_context(ContextOnStack, sizeof(cthreadInfo.DbiOutContext));
		DBI_OUT_CONTEXT* dbi_context = reinterpret_cast<DBI_OUT_CONTEXT*>(dbi_auto_context.WritePtrUser());
		if (dbi_context)
		{
			*dbi_context = cthreadInfo.DbiOutContext;
			return true;
		}
	}
	KeBreak();
	return true;//codecoverme.exe ohack
	return false;
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
	CMdl semaphore_mdl(EventSemaphor, sizeof(ULONG_PTR));//semaphore
	ULONG_PTR* semaphore = static_cast<ULONG_PTR*>(semaphore_mdl.WritePtr());
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
	CEProcess eprocess(ProcessId);
	CAutoEProcessAttach attach2process(eprocess);
	if (eprocess.IsAttached())
	{
		CMdl reg_auto_context(ContextOnStack, sizeof(DbiOutContext.GeneralPurposeContext));
		void* reg_context = reg_auto_context.WritePtr();
		if (reg_context)
		{
			//not necessary copy also DBI_FLAGS, because it is unused and rewriten by IRET in trace_event case ...
			memcpy(reg_context, cthreadInfo.DbiOutContext.GeneralPurposeContext, sizeof(ULONG_PTR) * REG_X64_COUNT);
			
			CMdl r_auto_context(IRet, sizeof(IRET));
			IRET* iret = static_cast<IRET*>(r_auto_context.WritePtr());
			if (iret)
			{
				if (!cthreadInfo.DbiOutContext.TraceInfo.Btf.Value)
					//disable BTF : not wrmsr but instead DEBUG REGISTERS!! -> per thread!
					//disable_branchtrace(); //-> VMX.cpp initialize vmm : vmwrite(VMX_VMCS64_GUEST_DR7, 0x400);
					wrmsr(IA32_DEBUGCTL, ~(BTF | LBR));//disable BTF -> special handling for wrmsr in HV
				else
					wrmsr(IA32_DEBUGCTL, (BTF | LBR));//enable BTF -> special handling for wrmsr in HV

				*iret = cthreadInfo.DbiOutContext.TraceInfo.StateInfo.IRet;				
			}

			return true;
		}
	}
	return false;
}
