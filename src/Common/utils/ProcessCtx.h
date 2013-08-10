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

//define ext-interface
class CProcessContext
{
public:
	explicit CProcessContext(
		__inout PEPROCESS process,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		) : m_eprocess(process), 
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
	PEPROCESS m_eprocess;
	HANDLE m_parentProcessId;
};

/*
 * When a thread is created, the thread-notify routine runs in the context of the thread that created the new thread.
 * When a thread is deleted, the thread-notify routine runs in the context of this thread when the thread exits. 
 */
struct THREAD_INFO : 
	public COMPARABLE_ID<HANDLE>
{
	HANDLE ParentProcessId;
	void* StackBase;
	CRange<ULONG_PTR> Stack;

	THREAD_INFO(
		__in HANDLE threadId,
		__in HANDLE parentProcessId
		) : COMPARABLE_ID(threadId),
			ParentProcessId(parentProcessId)
	{
		StackBase = IoGetInitialStack();

		ULONG_PTR begin;
		ULONG_PTR end;
		IoGetStackLimits(&begin, &end);
		Stack.Set((ULONG_PTR*)begin, (ULONG_PTR*)end);
	}

	HANDLE ThreadId()
	{
		return Id;
	}
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

	void* ImageBase()
	{
		return Id.Begin();
	}

	void* ImageLimit()
	{
		return Id.End();
	}

	size_t ImageSize()
	{
		return ((size_t)ImageLimit() - (size_t)ImageBase() + 1);
	}
};

#endif //__PROCESSCTX_H__
