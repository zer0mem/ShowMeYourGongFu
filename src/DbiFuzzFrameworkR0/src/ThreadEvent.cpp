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

CThreadEvent::CThreadEvent(
	__in HANDLE threadId, 
	__in HANDLE parentProcessId
	) : THREAD_INFO(threadId, parentProcessId),
		m_dbgThreadInfo(PsGetCurrentProcessId()),
		m_dbiThreadInfo(parentProcessId),
		m_ethread(threadId),
		m_initialized(false)
{
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
				return (0 == InterlockedExchange8(semaphor, 1));
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
	void* ret = reinterpret_cast<void*>(reg[DBI_RETURN] - SIZE_REL_CALL);	
	if (img->IsHooked(ret))
		img->UninstallHook(ret);

	m_dbgThreadInfo.DbiOutContext.TraceInfo.PrevEip.Value = ret;
	m_dbgThreadInfo.DbiOutContext.TraceInfo.Eip.Value = ret;
	m_dbgThreadInfo.DbiOutContext.TraceInfo.StackPtr.Value = HOOK_ORIG_RSP(reg);
	m_dbgThreadInfo.DbiOutContext.TraceInfo.Flags.Value = PPAGE_FAULT_IRET(reg)->Flags;//not correct -> correct map DBI_PARAMS and get pushf

	if (m_dbgThreadInfo.LoadContext(reg, img->Is64()))
	{
		//(void) because of init is called after main ep hook ..
		(void)m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo);
		(void)FlipSemaphore(m_dbiThreadInfo);
		return true;
	}

	return false;
}

__checkReturn
bool CThreadEvent::SmartTraceEvent( 
	__in CImage* img, 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const TRACE_INFO& branchInfo
	)
{
	m_dbgThreadInfo.DbiOutContext.TraceInfo = branchInfo;

	if (m_dbgThreadInfo.LoadContext(reg, img->Is64()))
		if (m_dbiThreadInfo.UpdateContext(reg, m_dbgThreadInfo))
			//return FlipSemaphore(m_dbiThreadInfo);//codecoverme.exe ohack
		{
			FlipSemaphore(m_dbiThreadInfo);
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
	PPAGE_FAULT_IRET(reg)->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

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
			return FlipSemaphore(m_dbgThreadInfo);

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

		PPAGE_FAULT_IRET(reg)->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);
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
		PPAGE_FAULT_IRET(reg)->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

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
bool DBG_THREAD_EVENT::LoadContext( 
	__in ULONG_PTR reg[REG_COUNT],
	__in bool is64
	)
{
	m_is64 = is64;
	m_iret = reinterpret_cast<void*>(reg[DBI_IRET]);
	EVENT_THREAD_INFO::LoadContext(reg);

	CMdl reg_auto_context(ContextOnStack, sizeof(DbiOutContext.GeneralPurposeContext));
	const void* reg_context = reg_auto_context.ReadPtr();
	if (reg_context)
	{
		//use just for read!
		CRegXType regs(m_is64, const_cast<void*>(reg_context));

		for (size_t i = 0; i < REG_COUNT; i++)
			DbiOutContext.GeneralPurposeContext[i] = regs.GetReg(i);

		DbiOutContext.GeneralPurposeContext[DBI_FLAGS] = regs.GetFLAGS();

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
			CRegXType regs(m_is64, reg_context);

			for (size_t i = 0; i < REG_COUNT; i++)
				regs.SetReg(i, cthreadInfo.DbiOutContext.GeneralPurposeContext[i]);

			regs.SetFLAGS(cthreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS]);


			CMdl r_auto_context(reinterpret_cast<void*>(m_iret), IRetCount * sizeof(ULONG_PTR));
			void* iret_ctx = r_auto_context.WritePtr();
			if (iret_ctx)
			{
				if (m_is64)
					SetIret<ULONG_PTR>(reinterpret_cast<ULONG_PTR*>(iret_ctx), 
						cthreadInfo.DbiOutContext.TraceInfo.Eip.Value, 
						PPAGE_FAULT_IRET(reg)->CodeSegment, 
						cthreadInfo.DbiOutContext.TraceInfo.Flags.Value);
				else
					SetIret<ULONG>(reinterpret_cast<ULONG*>(iret_ctx), 
						cthreadInfo.DbiOutContext.TraceInfo.Eip.Value, 
						PPAGE_FAULT_IRET(reg)->CodeSegment, 
						cthreadInfo.DbiOutContext.TraceInfo.Flags.Value);
			}

			return true;
		}
	}
	return false;
}
