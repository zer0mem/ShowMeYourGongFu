/**
 * @file Process.h
 * @author created by: Peter Hlavaty
 */

#ifndef __PROCESSCTX_H__
#define __PROCESSCTX_H__

#include "../base/Common.h"

#include "../../Common/utils/Range.h"
#include "../../Common/base/ComparableId.hpp"

#include "../../Common/utils/PE.hpp"
#include "../../Common/Kernel/Process.hpp"
#include "../../Common/Kernel/Thread.hpp"
#include "../../Common/Kernel/IRQL.hpp"
#include "../../Common/utils/Undoc.hpp"

//define ext-interface
class CProcessContext
{
public:
	explicit CProcessContext(
		__inout PEPROCESS process,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		) : m_eprocess(processId), 
			m_processId(processId), 
			m_parentProcessId(createInfo ? createInfo->ParentProcessId : NULL)
	{
	}

	static
	__checkReturn
	bool WatchProcess(
		__inout PEPROCESS eprocess,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		)
	{
		return true;
	}

	void ProcessNotifyRoutineEx(
		__inout PEPROCESS eprocess,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		)
	{
	}

	void ChildProcessNotifyRoutineEx(
		__inout PEPROCESS eprocess,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		)
	{
	}

	void ImageNotifyRoutine(
		__in_opt UNICODE_STRING* fullImageName,
		__in HANDLE processId,
		__in IMAGE_INFO* imageInfo
		)
	{
	}

	void ThreadNotifyRoutine(
		__in HANDLE processId,
		__in HANDLE threadId,
		__in BOOLEAN create
		)
	{
	}

	void RemoteThreadNotifyRoutine(
		__in HANDLE parentProcessId,
		__in HANDLE threadId,
		__in BOOLEAN create
		)
	{
	}

	__checkReturn
	NTSTATUS RegisterCallback(
		__in void* CallbackContext,
		__in_opt void* Argument1,
		__in_opt void* Argument2
		)
	{
		return STATUS_SUCCESS;
	}

	static 
	__checkReturn
	bool ResolveImageName( 
		__in_ecount(len) const WCHAR* fullImagePath, 
		__in size_t len, 
		__out UNICODE_STRING* imageName 
		);

protected:
	HANDLE m_processId;
	//reference this eprocess in m$
	CEProcess m_eprocess;
	HANDLE m_parentProcessId;
};

/*
 * When a thread is created, the thread-notify routine runs in the context of the thread that created the new thread.
 * When a thread is deleted, the thread-notify routine runs in the context of this thread when the thread exits. 
 */
EXTERN_C NTKERNELAPI PVOID NTAPI PsGetThreadTeb( PETHREAD Thread );
EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process( PEPROCESS Process );

class THREAD_INFO : 
	public COMPARABLE_ID<HANDLE>
{
public:
	//find -> key ctor
	THREAD_INFO(
		__in HANDLE threadId
		) : COMPARABLE_ID(threadId),
			m_ethread(threadId)
	{
	}

	THREAD_INFO(
		__in HANDLE threadId,
		__in HANDLE parentProcessId
		) : COMPARABLE_ID(threadId),
			m_ethread(threadId),
			m_parentProcessId(parentProcessId),
			m_stack(NULL)
	{
	}

	HANDLE ThreadId()
	{
		return Id;
	}

	CRange<ULONG_PTR>& Stack()
	{
		if (!m_stack.Begin())
		{
			CEthread ethread(Id);
			if (ethread.GetEthread())
			{
				CPassiveLvl irql;
				void* teb;
				if (teb = GetWow64Teb(ethread.GetEthread()))
					ResolveThreadLimits<NT_TIB32>(reinterpret_cast<NT_TIB32*>(teb));
				else if (teb = PsGetThreadTeb(ethread.GetEthread()))
					ResolveThreadLimits<NT_TIB>(reinterpret_cast<NT_TIB*>(teb));
			}
		}
		DbgPrint("\nstack boundaries : %p %p\n", m_stack.Begin(), m_stack.End());
		return m_stack;
	}

private:
	template<class TYPE>
	__forceinline
	void ResolveThreadLimits(
		__in const TYPE* teb
		)
	{
		if (teb)
			m_stack.Set(reinterpret_cast<ULONG_PTR*>(*CUndoc::DeallocationStack<TYPE>(teb)), reinterpret_cast<ULONG_PTR*>(teb->StackBase));
		else
			m_stack.Set(NULL, NULL);
	}

	__checkReturn
	NT_TIB32* GetWow64Teb( 
		__in PETHREAD thread
		)
	{
		if(PsGetProcessWow64Process(IoThreadToProcess(thread)))
		{
			NT_TIB* teb = reinterpret_cast<NT_TIB*>(PsGetThreadTeb(thread));
			DbgPrint("\nTEB : %p\n", teb);
			if (teb)
			{
				NT_TIB32* teb32 = reinterpret_cast<NT_TIB32*>(teb->ExceptionList);
				if (teb32 && ((ULONG_PTR)teb32->Self == (ULONG_PTR)teb32))
					return teb32;
			}
		}
		return NULL;
	}

protected:
	HANDLE m_parentProcessId;
	CRange<ULONG_PTR> m_stack;

private:
	//reference this ethread in m$
	CEthread m_ethread;
};

/*
 * When a process is created, the process-notify routine runs in the context of the thread that created the new process. 
 * When a process is deleted, the process-notify routine runs in the context of the last thread to exit from the process.
 */
struct CHILD_PROCESS : 
	public COMPARABLE_ID<PEPROCESS>
{
	HANDLE ProcessId;
	HANDLE ThreadId;

	CHILD_PROCESS() : COMPARABLE_ID(NULL)
	{
	}

	CHILD_PROCESS(
		__in PEPROCESS eprocess,
		__in HANDLE processId = NULL
		) : COMPARABLE_ID(eprocess),
			ProcessId(processId),
			ThreadId(PsGetCurrentThreadId())
	{
	}

	PEPROCESS EProcess()
	{
		return Id;
	}
};

struct LOADED_IMAGE : 
	public COMPARABLE_ID< CRange<void> >
{
	LOADED_IMAGE() : COMPARABLE_ID(NULL)
	{
	}

	LOADED_IMAGE(
		__in const void* addr
		) : COMPARABLE_ID(addr)
	{
	}

	explicit LOADED_IMAGE(
		__in IMAGE_INFO* imgInfo
		) : COMPARABLE_ID(CRange<void>(imgInfo->ImageBase))
	{
		Id.SetSize(imgInfo->ImageSize);
	}

	CRange<void>& Image()
	{
		return Id;
	}

	__forceinline
	size_t ImageSize()
	{
		return ((size_t)Id.End() - (size_t)Id.Begin() + 1);
	}
};

#endif //__PROCESSCTX_H__
