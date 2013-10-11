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
	__in HANDLE parentProcessId
	) : THREAD_INFO(threadId, parentProcessId),
		m_dbgThreadInfo(PsGetCurrentProcessId()),
		m_dbiThreadInfo(parentProcessId),
		m_ethread(threadId),
		m_initialized(false)
{
	CDbiMonitor::CreateThread();
}

CThreadEvent::~CThreadEvent()
{
	CMemoryRange* mem = NULL;
	m_mem2watch.Find(CMemoryRange(NULL, 1), &mem);
	if (mem)
	{
		do
		{
			CMMU::SetValid(mem->Begin(), mem->GetSize());
		} while(m_mem2watch.GetNext(*mem, &mem));
	}

	CDbiMonitor::RemoveThread();
}

void CThreadEvent::RegisterMemoryAccess( 
	__in const BYTE* faultAddr,
	__in const ERROR_CODE& access,
	__in const void* begin,
	__in size_t size,
	__in ULONG_PTR flags

	)
{
	m_dbgThreadInfo.DbiOutContext.MemoryInfo.Memory.Value = faultAddr;
	m_dbgThreadInfo.DbiOutContext.MemoryInfo.Access.Value = access;
	m_dbgThreadInfo.DbiOutContext.MemoryInfo.Begin.Value = begin;
	m_dbgThreadInfo.DbiOutContext.MemoryInfo.Size.Value = size;
	m_dbgThreadInfo.DbiOutContext.MemoryInfo.Flags.Value = (ULONG)flags;

	if (CMMU::IsAccessed(faultAddr))
	{
		CMMU::SetValid(faultAddr, sizeof(ULONG_PTR));

		if (access.WriteAccess)
		{
			CMdl mdl(faultAddr, sizeof(ULONG_PTR));
			const ULONG_PTR* val = reinterpret_cast<const ULONG_PTR*>(mdl.ReadPtr());
			if (val)
				m_dbgThreadInfo.DbiOutContext.MemoryInfo.OriginalValue.Value = *val;
		}
	}
	else
	{
		m_dbgThreadInfo.DbiOutContext.MemoryInfo.OriginalValue.Value = 0;
	}
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

__checkReturn
bool CThreadEvent::HookEvent(
	__in CImage* img, 
	__in ULONG_PTR reg[REG_COUNT]
	)
{
	void* ret = reinterpret_cast<void*>(reg[DBI_RETURN] - FARCALL_INST_SIZE);

//missing check if is hook target also this thread -> if not, then freeze other thread, unhook, trace after hook (or closest event), freeze thread, hook back, and unfreeze freezed threads

	if (img->IsHooked(ret))
		img->UninstallHook(ret);

	m_dbgThreadInfo.DbiOutContext.TraceInfo.PrevEip.Value = ret;
	m_dbgThreadInfo.DbiOutContext.TraceInfo.Eip.Value = ret;
	m_dbgThreadInfo.DbiOutContext.TraceInfo.StackPtr.Value = reinterpret_cast<ULONG_PTR*>(reg[RSP]) + (DBI_FLAGS + 1)/*reg context*/ + 1 /*semaphore*/ + 5 /*(4-1) parameters + 2 calls*/ + 2/*syscall smth?*/;
	m_dbgThreadInfo.DbiOutContext.TraceInfo.Flags.Value = reg[DBI_FLAGS]; //not accurate, flags was meanwhile modified by shellcode from inappfuzzdbi.dll module .. 

	if (m_dbgThreadInfo.LoadContext(reg))
	{
		//(void) because of init is called after main ep hook ..
		(void)m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo);
		(void)FlipSemaphore(m_dbiThreadInfo);

/*
//when trace r0
		KeBreak();
		KeResetEvent(&m_dbgThreadInfo.SyncEvent);
		KeSetEvent(&m_dbiThreadInfo.SyncEvent, MAXIMUM_PRIORITY, TRUE);
		KeWaitForSingleObject(&m_dbgThreadInfo.SyncEvent, Executive, KernelMode, FALSE, 0);
*/
		return true;
	}

	return false;
}

__checkReturn
bool CThreadEvent::SmartTraceEvent( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const TRACE_INFO& branchInfo
	)
{
	if (m_dbgThreadInfo.LoadTrapContext(reg, branchInfo))
		if (m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo))
			//return FlipSemaphore(m_dbiThreadInfo);//codecoverme.exe ohack
		{
			FlipSemaphore(m_dbiThreadInfo);
			
/*
//when trace r0
			KeBreak();
			KeResetEvent(&m_dbgThreadInfo.SyncEvent);
			KeSetEvent(&m_dbiThreadInfo.SyncEvent, MAXIMUM_PRIORITY, TRUE);
			KeWaitForSingleObject(&m_dbgThreadInfo.SyncEvent, Executive, KernelMode, FALSE, 0);
*/
			return true;
		}

	return false;
}


//----------------------------------------------------------
// ****************** MONITOR DLL DBI API ******************
//----------------------------------------------------------

bool CThreadEvent::Init( 
	__in ULONG_PTR reg[REG_COUNT]
	)
{
	reinterpret_cast<EVENT_THREAD_INFO&>(m_dbiThreadInfo).LoadContext(reg);
	m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo);

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
		{
			FlipSemaphore(m_dbgThreadInfo);
			
/*
//when trace r0
			KeBreak();
			KeResetEvent(&m_dbiThreadInfo.SyncEvent);
			KeSetEvent(&m_dbgThreadInfo.SyncEvent, MAXIMUM_PRIORITY, TRUE);
			KeWaitForSingleObject(&m_dbiThreadInfo.SyncEvent, Executive, KernelMode, FALSE, 0);
*/
			return true;
		}

	return false;
}

__checkReturn
bool CThreadEvent::EnumMemory( 
	__in ULONG_PTR reg[REG_COUNT] 
	)
{
	CMdl auto_mem(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(MEMORY_ENUM));
	MEMORY_ENUM* mem = reinterpret_cast<MEMORY_ENUM*>(auto_mem.WritePtrUser());
	if (mem)
	{
		CVadNodeMemRange vad_mem;
		//NULL is equivalent getlowerbound
		if (m_ethread.VadScanner().GetNextVadMemoryRange(mem->Begin.Value, &vad_mem))
		{
			mem->Begin.Value = vad_mem.Begin();
			mem->Size.Value = vad_mem.GetSize();
			mem->Flags.Value = vad_mem.GetFlags().UFlags;
		}

		return true;
	}

	return false;
}

__checkReturn
bool CThreadEvent::WatchMemoryAccess( 
	__in ULONG_PTR reg[REG_COUNT] 
	)
{
	PARAM_MEM2WATCH params;
	if (ReadParamBuffer<PARAM_MEM2WATCH>(reg, &params))
	{
		//for now support just aligned watching .. in other case more processing needed ...
		BYTE* mem2watch = reinterpret_cast<BYTE*>(PAGE_ALIGN(params.Memory.Value));
		size_t size = ALIGN((params.Size.Value + ((ULONG_PTR)params.Memory.Value - (ULONG_PTR)mem2watch) + PAGE_SIZE), PAGE_SIZE);

		CVadNodeMemRange vad_mem;
		if (m_ethread.VadScanner().FindVadMemoryRange(mem2watch, &vad_mem))
		{
			if (m_mem2watch.Push(CMemoryRange(mem2watch, size, vad_mem.GetFlags().UFlags | DIRTY_FLAG)))
			{
				for (size_t page_walker = 0; page_walker < size; page_walker += PAGE_SIZE)
					if (CMMU::IsAccessed(mem2watch + page_walker))
						CMMU::SetInvalid(mem2watch + page_walker, PAGE_SIZE);
			}
		}
		return true;
	}
	return false;
}

__checkReturn
bool DBI_THREAD_EVENT::LoadContext( 
	__in ULONG_PTR reg[REG_COUNT]
	)
{
	EVENT_THREAD_INFO::LoadContext(reg);

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

			if (dbi_context->TraceInfo.PrevEip.Value == dbi_context->TraceInfo.Eip.Value)
				dbi_context->TraceInfo.Reason.Value = Hook;
			else if (dbi_context->TraceInfo.PrevEip.Value == MM_LOWEST_USER_ADDRESS)
				dbi_context->TraceInfo.Reason.Value = MemoryAcces;
			else
				dbi_context->TraceInfo.Reason.Value = BranchTraceFlag;

			return true;
		}
	}
	return true;//codecoverme.exe ohack
	return false;
}

__checkReturn
bool DBG_THREAD_EVENT::LoadTrapContext(
	__in ULONG_PTR reg[REG_COUNT], 
	__in TRACE_INFO branchInfo 
	)
{
	DbiOutContext.TraceInfo = branchInfo;
	memcpy(DbiOutContext.GeneralPurposeContext, reg, sizeof(ULONG_PTR) * REG_COUNT);

	ProcessId = PsGetCurrentProcessId(); // for sure here ??

	m_iret = &branchInfo.StackPtr.Value[-IRetCount];
	ContextOnStack = &branchInfo.StackPtr.Value[-(IRetCount + REG_COUNT)];
	EventSemaphor = &branchInfo.StackPtr.Value[-(IRetCount + REG_COUNT + 1)];

	CMdl semaphore_mdl(EventSemaphor, sizeof(ULONG_PTR));//semaphore
	ULONG_PTR* semaphore = reinterpret_cast<ULONG_PTR*>(semaphore_mdl.WritePtr());
	if (semaphore)
	{
		*semaphore = 0;
		return true;
	}

	KeBreak();
	return false;
}

__checkReturn
bool DBG_THREAD_EVENT::LoadContext( 
	__in ULONG_PTR reg[REG_COUNT]
	)
{
	m_iret = reinterpret_cast<void*>(reg[DBI_IRET]);
	EVENT_THREAD_INFO::LoadContext(reg);

	CMdl reg_auto_context(ContextOnStack, sizeof(DbiOutContext.GeneralPurposeContext));
	const void* reg_context = reg_auto_context.ReadPtr();
	if (reg_context)
	{
		memcpy(DbiOutContext.GeneralPurposeContext, reg_context, sizeof(DbiOutContext.GeneralPurposeContext));
		return true;
	}
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
			memcpy(reg_context, cthreadInfo.DbiOutContext.GeneralPurposeContext, sizeof(DbiOutContext.GeneralPurposeContext));
			
			CMdl r_auto_context(reinterpret_cast<void*>(m_iret), IRetCount * sizeof(ULONG_PTR));
			ULONG_PTR* iret = reinterpret_cast<ULONG_PTR*>(r_auto_context.WritePtr());
			if (iret)
			{
				iret[IReturn] = reinterpret_cast<ULONG_PTR>(cthreadInfo.DbiOutContext.TraceInfo.Eip.Value);
				iret[ICodeSegment] = SYSCAL_CS_SEGEMENT;//obtain from HV vie vmread(CS
				iret[IFlags] = (cthreadInfo.DbiOutContext.TraceInfo.Flags.Value);
				iret[IRsp] = reinterpret_cast<ULONG_PTR>(cthreadInfo.DbiOutContext.TraceInfo.StackPtr.Value);
				iret[IStackSegment] = SYSCAL_SS_SEGEMENT;//obtain from HV vie vmread(SS
			}

			return true;
		}
	}
	return false;
}
