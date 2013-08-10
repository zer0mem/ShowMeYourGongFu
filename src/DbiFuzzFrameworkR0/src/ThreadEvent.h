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
		) : ProcessId(processId)
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

			EventSemaphor = reinterpret_cast<void*>(reg[DBI_SEMAPHORE]);
			return true;
		}
		return false;
	}
};

class CThreadEvent :
	public THREAD_INFO
{
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
		__in LOADED_IMAGE* img,
		__in ULONG_PTR reg[REG_COUNT]
		);

	__checkReturn
	bool EventCallback(
		__in CImage* img, 
		__in ULONG_PTR reg[REG_COUNT],
		__in CLockedAVL<CIMAGEINFO_ID>& imgs
	);

protected:
	__checkReturn 
	bool FlipSemaphore(
		__in const EVENT_THREAD_INFO& eventThreadInfo
		);

protected:
	bool WaitForSyscallCallback;

	EVENT_THREAD_INFO m_monitorThreadInfo;
	EVENT_THREAD_INFO m_currentThreadInfo;
};

#endif //__THREADEVENT_H__
