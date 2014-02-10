/**
 * @file Process.h
 * @author created by: Peter Hlavaty
 */

#include "StdAfx.h"

#include "ProcessCtx.h"

template<class THRD, class PROC, class IMG>
void CProcessContext<THRD, PROC, IMG>::ProcessNotifyRoutineEx( 
	__inout PEPROCESS eprocess, 
	__in HANDLE processId, 
	__inout_opt PS_CREATE_NOTIFY_INFO* createInfo 
	)
{
	UNREFERENCED_PARAMETER(eprocess);
	UNREFERENCED_PARAMETER(processId);
	UNREFERENCED_PARAMETER(createInfo);
}

template<class THRD, class PROC, class IMG>
void CProcessContext<THRD, PROC, IMG>::ChildProcessNotifyRoutineEx( 
	__inout PEPROCESS eprocess,
	__in HANDLE processId,
	__inout_opt PS_CREATE_NOTIFY_INFO* createInfo 
	)
{
	PROCESS proc_info(processId);
	if (createInfo)
	{
		proc_info.Obj = new PROC(eprocess, processId, PsGetCurrentThreadId(), createInfo);
		if (proc_info.Obj)
		{
			if (m_childs.Push(proc_info))
				proc_info.Obj = NULL;//avoid deleting
		}
	}
	else
	{
		m_childs.Pop(proc_info);
	}
}

template<class THRD, class PROC, class IMG>
void CProcessContext<THRD, PROC, IMG>::ImageNotifyRoutine(
	__in_opt UNICODE_STRING* fullImageName, 
	__in HANDLE processId, 
	__in IMAGE_INFO* imageInfo 
	)
{
	if (m_internalError)
		return;

	if (!imageInfo->SystemModeImage)
	{
		IMAGE img(CRange<void>(imageInfo->ImageBase, imageInfo->ImageSize));

		//drop overlapped images; handle unhook in ~coldpatch -> now it is unloaded img, unhooking == badidea
		m_loadedImgs.Pop(img);

		img.Obj = new IMG(fullImageName, processId, imageInfo);
		if (img.Obj)
		{
			if (m_loadedImgs.Push(img))
			{
				if (!m_mainImg)
					m_mainImg = img.Obj;

				//avoid deleting
				img.Obj = NULL;
			}
			else
			{
				KeBreak();
				if (!m_mainImg)
					m_internalError = true;
			}
		}
	}
}

template<class THRD, class PROC, class IMG>
void CProcessContext<THRD, PROC, IMG>::ThreadNotifyRoutine( 
	__in HANDLE processId, 
	__in HANDLE threadId, 
	__in BOOLEAN create 
	)
{
	THREAD thread_info(threadId);
	if (!!create)
	{
		thread_info.Obj = new THRD(threadId, processId);
		if (thread_info.Obj)
		{
			if (m_threads.Push(thread_info))
			{
				m_unresolvedThreads.Push(threadId);
				thread_info.Obj = NULL;//avoid deleting
			}
		}
	}
	else
	{
		//TODO : AVOID calling ~destructors in SPIN_LOCK!!
		m_threads.Pop(thread_info);//invoke THREAD.~ -> which is performance fail!
		m_unresolvedThreads.Pop(threadId);
	}
}

template<class THRD, class PROC, class IMG>
void CProcessContext<THRD, PROC, IMG>::RemoteThreadNotifyRoutine(
	__in HANDLE parentProcessId, 
	__in HANDLE threadId,
	__in BOOLEAN create 
	)
{
	ThreadNotifyRoutine(parentProcessId, threadId, create);
}

template<class THRD, class PROC, class IMG>
__checkReturn
NTSTATUS CProcessContext<THRD, PROC, IMG>::RegisterCallback( 
	__in void* CallbackContext,
	__in_opt void* Argument1, 
	__in_opt void* Argument2 
	)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument1);
	UNREFERENCED_PARAMETER(Argument2);
	return STATUS_SUCCESS;
}

template<class THRD, class PROC, class IMG>
__checkReturn
bool CProcessContext<THRD, PROC, IMG>::ResolveImageName( 
	__in_ecount(len) const WCHAR* fullImagePath, 
	__in size_t len, 
	__out UNICODE_STRING* imageName 
	)
{
	const WCHAR* name = fullImagePath;

	if (0 != len)
	{
		const WCHAR* resolved_name = wcschrn(fullImagePath, L'\\', len, (int)(len - 1), true);
		if (NULL != resolved_name)
		{
			name = resolved_name + 1;
			DbgPrint("\nProcess launched (Loadlib) : %ws", resolved_name);
			len -= (name - fullImagePath);
			InitUnicodeSubstring(name, len, imageName);

			return true;
		}
	}

	return false;
}
