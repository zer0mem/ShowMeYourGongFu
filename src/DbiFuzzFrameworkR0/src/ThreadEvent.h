/**
 * @file ThreadEvent.h
 * @author created by: Peter Hlavaty
 */

#ifndef __THREADEVENT_H__
#define __THREADEVENT_H__

#include "../../Common/base/Common.h"
#include "../../Common/utils/ProcessCtx.h"
#include "../../Common/utils/SyscallCallbacks.hpp"
#include "../../Common/utils/LockedContainers.hpp"
#include "../../Common/Kernel/MemoryMapping.h"

#include "../../Common/FastCall/FastCall.h"

#include "Common/Constants.h"
#include "ImageInfo.h"

struct EVENT_THREAD_INFO 
{
	HANDLE ProcessId;
	void* EventSemaphor;
	DBI_OUT_CONTEXT DbiOutContext;

	EVENT_THREAD_INFO(
		__in HANDLE processId
		) : ProcessId(processId),
			EventSemaphor(NULL)
	{
	}

	__checkReturn
	bool SetContext(
		__in bool is64,
		__in ULONG_PTR reg[REG_COUNT],
		__in BRANCH_INFO* branchInfo = NULL,
		__in MEMORY_ACCESS* memInfo = NULL
		)
	{
		size_t ctx_size = (is64 ? sizeof(ULONG_PTR) * (REG_X64_COUNT + 1) : sizeof(ULONG) * (REG_X86_COUNT + 1));
		CMdl r_auto_context(reinterpret_cast<const void*>(reg[DBI_INFO_OUT]), ctx_size);
		void* r_context = r_auto_context.Map();
		if (r_context)
		{
			CRegXType regsx(is64, r_context);

			for (size_t i = 0; i < REG_COUNT; i++)
				DbiOutContext.GeneralPurposeContext[i] = (ULONG_PTR)regsx.GetReg(i);

			DbiOutContext.GeneralPurposeContext[DBI_FLAGS] = (ULONG_PTR)regsx.GetFLAGS();

			if (branchInfo)
				DbiOutContext.LastBranchInfo = *branchInfo;

			if (memInfo)
				DbiOutContext.MemoryInfo = *memInfo;
			
			ProcessId = PsGetCurrentProcessId();

			EventSemaphor = reinterpret_cast<void*>(reg[DBI_SEMAPHORE]);
			return true;
		}

		return false;
	}

	void DumpContext(
		__in bool is64,
		__in ULONG_PTR reg[REG_COUNT]
		)
	{
		CMdl r_auto_context(reinterpret_cast<const void*>(reg[DBI_INFO_OUT]), sizeof(DBI_OUT_CONTEXT));
		DBI_OUT_CONTEXT* r_context = reinterpret_cast<DBI_OUT_CONTEXT*>(r_auto_context.Map());
		if (r_context)
		{
			for (size_t i = 0; i < REG_COUNT + 1; i++)
				r_context->GeneralPurposeContext[i] = DbiOutContext.GeneralPurposeContext[i];

			r_context->LastBranchInfo = DbiOutContext.LastBranchInfo;
			r_context->MemoryInfo = DbiOutContext.MemoryInfo;
		}
	}
};

class CThreadEvent :
	public THREAD_INFO
{
	enum EnumIRET
	{
		IReturn = 0,
		ICodeSegment,
		IFlags,
		IRetCount
	};
public:
	MEMORY_INFO LastMemoryInfo;
	ULONG_PTR GeneralPurposeContext[REG_COUNT];

	CThreadEvent();

	CThreadEvent(
		__in HANDLE threadId,
		__in HANDLE parentProcessId = NULL
		);

// VIRTUAL MEMORY HANDLER support routines
	__checkReturn
	bool WaitForSyscallEpilogue();

	void SetCallbackEpilogue(
		__in ULONG_PTR reg[REG_COUNT],
		__in void* memory,
		__in size_t size,
		__in bool write,
		__in_opt void* pageFault = NULL
		);

	void EpilogueProceeded();

// FUZZ MONITOR HANDLER support routines
	__checkReturn
	bool MonitorFastCall(
		__in CImage* img,
		__in ULONG_PTR reg[REG_COUNT]
		);

	__checkReturn
	bool EventCallback(
		__in CImage* img, 
		__in ULONG_PTR reg[REG_COUNT],
		__in CLockedAVL<CIMAGEINFO_ID>& imgs
	);

	__checkReturn
	bool IsTrapSet();

protected:
	__checkReturn 
	bool FlipSemaphore(
		__in const EVENT_THREAD_INFO& eventThreadInfo
		);

	void SetIret(
		__in bool is64,
		__inout void* iretAddr,
		__in const void* iret,
		__in ULONG_PTR segSel,
		__in ULONG_PTR flags
		);

private:
	template<class TYPE>
	__forceinline
		void SetIret(
		__inout TYPE* iret,
		__in const void* ret,
		__in ULONG_PTR segSel,
		__in ULONG_PTR flags
		)
	{
		iret[IReturn] = (TYPE)(ret);
		iret[ICodeSegment] = (TYPE)(segSel);
		iret[IFlags] = (TYPE)(flags);
	}

protected:
	bool WaitForSyscallCallback;

	EVENT_THREAD_INFO m_monitorThreadInfo;
	EVENT_THREAD_INFO m_currentThreadInfo;
};

#endif //__THREADEVENT_H__
