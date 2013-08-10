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

enum Retf
{
	FLAGS = 0,
	SEGMENT_SEL,
	RETURN,
	CONTEXT_COUNT
};

class CRegXTypeRetf :
	public CRegXType
{
public:
	CRegXTypeRetf(
		__in bool is64,
		__in void* regs
		) : CRegXType(is64, regs) 
	{
	}

	ULONG_PTR GetRET() { return GetReg((m_is64 ? REG_X64_COUNT : REG_X86_COUNT) + RETURN); }
	ULONG_PTR GetSEG() { return GetReg((m_is64 ? REG_X64_COUNT : REG_X86_COUNT) + SEGMENT_SEL); }

	//switched flags with ret => because of iret : call smth; stmh : push cs, pushf ==> [ret, cs, flags] == reverse order
	void SetRET(__in ULONG_PTR ret) { SetReg((m_is64 ? REG_X64_COUNT : REG_X86_COUNT) + FLAGS, ret); }
	void SetFLAGS(__in ULONG_PTR flags) { SetReg((m_is64 ? REG_X64_COUNT : REG_X86_COUNT) + RETURN, flags); }

	void SetSEG(__in ULONG_PTR seg) { SetReg((m_is64 ? REG_X64_COUNT : REG_X86_COUNT) + SEGMENT_SEL, seg); }
};

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
		__in_bcount(ctxSize) void* generalPurposeContext,
		__in size_t ctxSize,
		__in BRANCH_INFO* branchInfo = NULL,
		__in MEMORY_ACCESS* memInfo = NULL
		)
	{
		if (ctxSize > sizeof(ULONG_PTR[REG_COUNT]))
		{
			KeBreak();
			return;
		}

		memcpy(&DbiOutContext.GeneralPurposeContext, generalPurposeContext, ctxSize);

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
		__in ULONG_PTR reg[REG_COUNT]
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
