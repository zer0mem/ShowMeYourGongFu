/**
 * @file Process.h
 * @author created by: Peter Hlavaty
 */

#ifndef __PROCESSCTX_H__
#define __PROCESSCTX_H__

#include "../base/Common.h"

#include "Range.h"
#include "../base/ComparableId.hpp"

#include "../Kernel/Thread.hpp"
#include "LockedContainers.hpp"

#include "../../Common/utils/VADWalker.h"

//define ext-interface
template<class THRD, class PROC, class IMG>
class CProcessContext
{
protected:
	typedef COMPARABLE_ID_PTR<HANDLE, THRD> THREAD;
	typedef COMPARABLE_ID_PTR<HANDLE, PROC> PROCESS;
	typedef COMPARABLE_ID_PTR<CRange<void>, IMG> IMAGE;
public:
	explicit CProcessContext(
		__inout PEPROCESS process,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		) : m_processId(processId), 
			m_parentProcessId(createInfo ? createInfo->ParentProcessId : NULL),
			m_mainImg(NULL),
			m_internalError(false),
			m_vad(process)
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
		);

	void ChildProcessNotifyRoutineEx(
		__inout PEPROCESS eprocess,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		);

	void ImageNotifyRoutine(
		__in_opt UNICODE_STRING* fullImageName,
		__in HANDLE processId,
		__in IMAGE_INFO* imageInfo
		);

	void ThreadNotifyRoutine(
		__in HANDLE processId,
		__in HANDLE threadId,
		__in BOOLEAN create
		);

	void RemoteThreadNotifyRoutine(
		__in HANDLE parentProcessId,
		__in HANDLE threadId,
		__in BOOLEAN create
		);

	__checkReturn
	NTSTATUS RegisterCallback(
		__in void* CallbackContext,
		__in_opt void* Argument1,
		__in_opt void* Argument2
		);

	static 
	__checkReturn
	bool ResolveImageName( 
		__in_ecount(len) const WCHAR* fullImagePath, 
		__in size_t len, 
		__out UNICODE_STRING* imageName 
		);

protected:
	HANDLE m_processId;
	HANDLE m_parentProcessId;

	CVadScanner m_vad;

	CLockedAVL<HANDLE> m_unresolvedThreads;

	IMG* m_mainImg;
	CLockedAVL<THREAD> m_threads;
	CLockedAVL<PROCESS> m_childs;
	CLockedAVL<IMAGE> m_loadedImgs;

private:
	bool m_internalError;
};

//------------------------------------------------------------
// ****************** BASIC INFO CONTAINERS ******************
//------------------------------------------------------------

/*
 * When a thread is created, the thread-notify routine runs in the context of the thread that created the new thread.
 * When a thread is deleted, the thread-notify routine runs in the context of this thread when the thread exits. 
 */
struct THREAD_INFO : 
	public COMPARABLE_ID<HANDLE>
{
	HANDLE ParentProcessId;

	THREAD_INFO(
		__in HANDLE threadId,
		__in HANDLE parentProcessId
		) : COMPARABLE_ID(threadId),
			ParentProcessId(parentProcessId)
	{
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
	public COMPARABLE_ID<HANDLE>
{
	HANDLE ThreadId;

	CHILD_PROCESS(
		__in PEPROCESS eprocess,
		__in HANDLE processId,
		__in HANDLE threadId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		) : COMPARABLE_ID(processId),
			ThreadId(threadId)
	{
	}

	HANDLE ProcessId()
	{
		return Id;
	}
};

struct LOADED_IMAGE : 
	public COMPARABLE_ID< CRange<void> >
{
	explicit LOADED_IMAGE(
		__in_opt UNICODE_STRING* fullImageName, 
		__in HANDLE processId, 
		__in IMAGE_INFO* imageInfo 
		) : COMPARABLE_ID(CRange<void>(imageInfo->ImageBase))
	{
		Id.SetSize(imageInfo->ImageSize);
	}

	CRange<void>& Image()
	{
		return Id;
	}
};

//http://www.codeproject.com/Articles/48575/How-to-define-a-template-class-in-a-h-file-and-imp
#include "ProcessCtx.cpp"

#endif //__PROCESSCTX_H__
