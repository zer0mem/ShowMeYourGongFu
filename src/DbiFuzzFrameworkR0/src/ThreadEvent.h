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
#include "../../Common/utils/MemoryRange.h"

#include "../../Common/FastCall/FastCall.h"

#include "Common/Constants.h"
#include "ImageInfo.h"

#include "../../Common/Kernel/Process.hpp"

#include "../../Common/utils/VADWalker.h"

struct EVENT_THREAD_INFO 
{
	HANDLE ProcessId;
	void* EventSemaphor;
	void* ContextOnStack;
	DBI_OUT_CONTEXT DbiOutContext;

	//KEVENT SyncEvent;

	EVENT_THREAD_INFO(
		__in HANDLE processId
		) : ProcessId(processId),
			EventSemaphor(NULL),
			ContextOnStack(NULL)
	{
		RtlZeroMemory(&DbiOutContext, sizeof(DbiOutContext));

		//KeInitializeEvent(&SyncEvent, NotificationEvent, FALSE);
	}

	__checkReturn
	virtual
	bool LoadContext(
		__in ULONG_PTR reg[REG_COUNT]
		) = 0;

	__checkReturn
	virtual
	bool UpdateContext(
		__in ULONG_PTR reg[REG_COUNT],
		__in const EVENT_THREAD_INFO& cthreadInfo
		) = 0;

	__checkReturn 
	bool FlipSemaphore();
};

struct DBI_THREAD_EVENT :
	public EVENT_THREAD_INFO
{
	DBI_THREAD_EVENT(
		__in HANDLE processId
		) : EVENT_THREAD_INFO(processId) 
	{ }

	__checkReturn
	virtual
	bool LoadContext(
		__in ULONG_PTR reg[REG_COUNT]
		);

	__checkReturn
	virtual
	bool UpdateContext(
		__in ULONG_PTR reg[REG_COUNT],
		__in const EVENT_THREAD_INFO& cthreadInfo
		);
};

struct DBG_THREAD_EVENT :
	public EVENT_THREAD_INFO
{
	DBG_THREAD_EVENT(
		__in HANDLE processId
		) : EVENT_THREAD_INFO(processId) 
	{ }

	__checkReturn
	bool LoadTrapContext( 
		__in ULONG_PTR reg[REG_COUNT],
		__in const TRACE_INFO* branchInfo, 
		__in const PFIRET* pfIRet
		);

	__checkReturn
	bool LoadHookContext( 
		__in ULONG_PTR reg[REG_COUNT],
		__in PFIRET* pfIRet
		);

	__checkReturn
	bool LoadPFContext( 
		__in ULONG_PTR reg[REG_COUNT],
		__in CMemoryRange* mem, 
		__in PFIRET* pfIRet,
		__in const BYTE* faultAddr
		);

	__checkReturn
	virtual
	bool UpdateContext(
		__in ULONG_PTR reg[REG_COUNT],
		__in const EVENT_THREAD_INFO& cthreadInfo
		);

	void* IRet;

protected:
	__checkReturn
	virtual
	bool LoadContext(
		__in ULONG_PTR reg[REG_COUNT]
	);
};

class CThreadEvent :
	public THREAD_INFO
{
public:	
	CThreadEvent(
		__in HANDLE threadId,
		__in HANDLE parentProcessId,
		__in CVadScanner& vad
		);

	~CThreadEvent();

// FUZZ MONITOR HANDLER support routines
	void HookEvent( 
		__in ULONG_PTR reg[REG_COUNT], 
		__in PFIRET* pfIRet 
		);

	void SmartTraceEvent( 
		__in ULONG_PTR reg[REG_COUNT], 
		__in const TRACE_INFO* branchInfo,
		__in const PFIRET* pfIRet 
		);

	void RegisterMemoryAccess( 
		__in ULONG_PTR reg[REG_COUNT], 
		__in const BYTE* faultAddr, 
		__in CMemoryRange* mem, 
		__in PFIRET* pfIRret
		);

	bool Init(
		__in ULONG_PTR reg[REG_COUNT]
	);

	__checkReturn
	bool SmartTrace(
		__in ULONG_PTR reg[REG_COUNT]
	);

	__checkReturn
	__forceinline
	bool ResolveThread()
	{
		if (!m_initialized)
			m_initialized = m_ethread.Initialize();
		return m_initialized;
	}
	
	__forceinline
	CRange<ULONG_PTR>& GetStack()
	{
		return m_ethread.Stack();
	}

	__forceinline
	CEthread& GetEthread()
	{
		return m_ethread;
	}

protected:
	DBI_THREAD_EVENT m_dbiThreadInfo;
	DBG_THREAD_EVENT m_dbgThreadInfo;

	bool m_initialized;

private:
	//reference this ethread in m$
	CEthread m_ethread;
	CVadScanner& m_vad;
};

template<class TYPE>
__checkReturn
bool ReadParamBuffer(
	__in ULONG_PTR reg[REG_COUNT],
	__inout TYPE* paramsBuff
	)
{
	CMdl mdl(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(TYPE));
	const TYPE* params_buff = reinterpret_cast<const TYPE*>(mdl.ReadPtrUser());
	if (params_buff)
	{
		*paramsBuff = *params_buff;
		return true;
	}
	return false;
};

#endif //__THREADEVENT_H__
