/**
 * @file ThreadEvent.h
 * @author created by: Peter Hlavaty
 */

#ifndef __THREADEVENT_H__
#define __THREADEVENT_H__

#include "../../Common/base/Common.h"
#include "../../Common/utils/ProcessCtx.h"
#include "../../Common/utils/SyscallCallbacks.hpp"

#include "Common/Constants.h"
#include "../../Common/FastCall/FastCall.h"

#include "../../Common/utils/LockedContainers.hpp"

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

	void SetContext(
		__in ULONG_PTR reg[REG_COUNT],
		__in CRegXType& regxtype,
		__in BRANCH_INFO* branchInfo = NULL,
		__in MEMORY_ACCESS* memInfo = NULL
		)
	{
		for (size_t i = 0; i < REG_COUNT; i++)
			DbiOutContext.GeneralPurposeContext[i] = (ULONG_PTR)regxtype.GetReg(i);

		DbiOutContext.GeneralPurposeContext[DBI_FLAGS] = (ULONG_PTR)regxtype.GetFLAGS();

		if (branchInfo)
			DbiOutContext.BranchInfo = *branchInfo;

		if (memInfo)
			DbiOutContext.MemoryInfo = *memInfo;

		EventSemaphor = reinterpret_cast<void*>(reg[DBI_SEMAPHORE]);
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
		__in LOADED_IMAGE* img, 
		__in ULONG_PTR reg[REG_COUNT],
		__in CLockedAVL<LOADED_IMAGE>& imgs
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
