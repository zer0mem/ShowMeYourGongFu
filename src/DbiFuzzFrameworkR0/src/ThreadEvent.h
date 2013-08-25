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

struct EVENT_THREAD_INFO 
{
	HANDLE ProcessId;
	void* EventSemaphor;
	void* ContextOnStack;
	DBI_OUT_CONTEXT DbiOutContext;

	EVENT_THREAD_INFO(
		__in HANDLE processId
		) : ProcessId(processId),
			EventSemaphor(NULL),
			ContextOnStack(NULL)
	{
		RtlZeroMemory(&DbiOutContext, sizeof(DbiOutContext));
	}

	void LoadContext(
		__in ULONG_PTR reg[REG_COUNT]
	)
	{
		ProcessId = PsGetCurrentProcessId();
		EventSemaphor = reinterpret_cast<void*>(reg[DBI_SEMAPHORE]);
		ContextOnStack = reinterpret_cast<void*>(reg[DBI_PARAMS]);

		PPAGE_FAULT_IRET(reg)->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);
	}


	__checkReturn
	virtual
	bool UpdateContext(
		__in ULONG_PTR reg[REG_COUNT],
		__in const EVENT_THREAD_INFO& cthreadInfo
		) = 0;
};

struct DBI_THREAD_EVENT :
	public EVENT_THREAD_INFO
{
	DBI_THREAD_EVENT(
		__in HANDLE processId
		) : EVENT_THREAD_INFO(processId) 
	{ }

	__checkReturn
	bool LoadContext(
		__in ULONG_PTR reg[REG_COUNT]
		);

	__checkReturn
	virtual
	bool UpdateContext(
		__in ULONG_PTR reg[REG_COUNT],
		__in const EVENT_THREAD_INFO& cthreadInfo
		) override;
};

struct DBG_THREAD_EVENT :
	public EVENT_THREAD_INFO
{
	DBG_THREAD_EVENT(
		__in HANDLE processId
		) : EVENT_THREAD_INFO(processId) 
	{ }

	__checkReturn
	bool LoadContext(
		__in ULONG_PTR reg[REG_COUNT],
		__in bool is64
	);

	__checkReturn
	virtual
	bool UpdateContext(
		__in ULONG_PTR reg[REG_COUNT],
		__in const EVENT_THREAD_INFO& cthreadInfo
		) override;

private:
	void* m_iret;
	bool m_is64;
};

class CThreadEvent :
	public THREAD_INFO
{
public:	
	CThreadEvent(
		__in HANDLE threadId,
		__in HANDLE parentProcessId
		);

	~CThreadEvent();

// FUZZ MONITOR HANDLER support routines
	__checkReturn
	bool HookEvent(
		__in CImage* img,
		__in ULONG_PTR reg[REG_COUNT]
	);

	__checkReturn
	bool SmartTraceEvent(
		__in CImage* img,
		__in ULONG_PTR reg[REG_COUNT],
		__in const TRACE_INFO& branchInfo
	);

	__checkReturn
	bool SmartTrace(
		__in ULONG_PTR reg[REG_COUNT]
		);
		
	__checkReturn
	bool EnumMemory(
		__in ULONG_PTR reg[REG_COUNT]
		);
		
	__checkReturn
	bool WatchMemoryAccess(
		__in ULONG_PTR reg[REG_COUNT]
		);

	void RegisterMemoryAccess( 
		__in const BYTE* faultAddr,
		__in const ERROR_CODE& access,
		__in const void* begin,
		__in size_t size,
		__in ULONG_PTR flags
		);

	bool Init(
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
	MEMORY_ACCESS& GetMemoryAccess()
	{
		return m_dbgThreadInfo.DbiOutContext.MemoryInfo;
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

	__checkReturn
	__forceinline
	bool IsMemory2Watch(
		__in const void* addr,
		__in size_t size
		)
	{
		return m_mem2watch.Find(CMemoryRange(reinterpret_cast<const BYTE*>(addr), size));
	}

	__checkReturn
	__forceinline
	bool GetMemory2Watch(
		__in const void* addr,
		__in size_t size,
		__inout CMemoryRange** mem
		)
	{
		return m_mem2watch.Find(CMemoryRange(reinterpret_cast<const BYTE*>(addr), size), mem);
	}

protected:
	__checkReturn 
	bool FlipSemaphore(
		__in const EVENT_THREAD_INFO& eventThreadInfo
		);

protected:
	DBI_THREAD_EVENT m_dbiThreadInfo;
	DBG_THREAD_EVENT m_dbgThreadInfo;

	bool m_initialized;
	CLockedAVL<CMemoryRange> m_mem2watch;

private:
	//reference this ethread in m$
	CEthread m_ethread;
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

#endif //__THREADEVENT_H__
