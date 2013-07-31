/**
 * @file ProcessMonitor.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __PROCESSMONITOR_H__
#define __PROCESSMONITOR_H__

#include "../base/Common.h"
#include "../Kernel/IRQL.hpp"
#include "../utils/AVL.hpp"
#include "../utils/ProcessCtxWorker.hpp"

/*
 * for future developement, use better callbacks :P
 * http://msdn.microsoft.com/en-us/library/windows/hardware/hh998966.aspx
 * http://msdn.microsoft.com/en-us/library/windows/hardware/ff540402(v=vs.85).aspx
 */

template<class TYPE>
class CProcessMonitor
{
//prohibit outside init
	void operator=(const CProcessMonitor&);

public:
	CProcessMonitor()
	{
		m_processWorker = new CProcessCtxWorker<TYPE>;
		if (!m_processWorker)
			return;

		//registry callback
		UNICODE_STRING altitude;
		RtlInitUnicodeString(&altitude, L"360055");//FSFilter Activity Monitor
		{
			CPassiveLvl irql;

			NTSTATUS status;
			status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
			ASSERT(STATUS_SUCCESS == status);

			status = PsSetLoadImageNotifyRoutine(ImageNotifyRoutine);
			ASSERT(STATUS_SUCCESS == status);

			status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
			ASSERT(STATUS_SUCCESS == status);

			status = CmRegisterCallbackEx(RegisterCallback, &altitude, gDriverObject, NULL, &m_cookie, NULL);
			ASSERT(STATUS_SUCCESS == status);
		}
	}
	
	~CProcessMonitor()
	{
		if (!m_processWorker)
			return;

		PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
		PsRemoveLoadImageNotifyRoutine(ImageNotifyRoutine);
		PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);

		CmUnRegisterCallback(m_cookie);
	}
	
	static
	CProcessCtxWorker<TYPE>& GetProcessWorker()
	{
		return *m_processWorker;
	}

protected:
	static
	void ProcessNotifyRoutineEx(
		__inout PEPROCESS eprocess,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		)
	{
		if (createInfo)
		{
			TYPE* process;
			if (m_processWorker->GetProcess(createInfo->ParentProcessId, &process))
				process->ChildProcessNotifyRoutineEx(eprocess, processId, createInfo);

			if (TYPE::WatchProcess(eprocess, processId, createInfo))
				m_processWorker->RegisterProcess(eprocess, processId, createInfo);
		}
		else
		{
			m_processWorker->UnregisterProcess(eprocess, processId);
		}
	}

	/*
	 * The operating system does not call load-image notify routines when sections created with 
	 * the SEC_IMAGE_NO_EXECUTE attribute are mapped to virtual memory.
	 *
	 * ... the operating system holds an internal system lock during calls to load-image notify routines 
	 * for images loaded in user process address space (user space).
	 * To avoid deadlocks, load-image notify routines must not call system routines that map, allocate, 
	 * query, free, or perform other operations on user-space virtual memory.
	 */
	static
	void ImageNotifyRoutine(
		__in_opt UNICODE_STRING* fullImageName,
		__in HANDLE processId,
		__in IMAGE_INFO* imageInfo
		)
	{
		TYPE* process;
		if (m_processWorker->GetProcess(processId, &process))
 			process->ImageNotifyRoutine(fullImageName, processId, imageInfo);
	}

	static
	void ThreadNotifyRoutine(
		__in HANDLE processId,
		__in HANDLE threadId,
		__in BOOLEAN create
		)
	{
		TYPE* process;
		if (m_processWorker->GetProcess(processId, &process))
		{
			if (processId == PsGetCurrentProcessId())
				process->ThreadNotifyRoutine(processId, threadId, create);
			else
				process->RemoteThreadNotifyRoutine(PsGetCurrentProcessId(), threadId, create);
		}
	}

	static
	NTSTATUS RegisterCallback(
		__in void* CallbackContext,
		__in_opt void* Argument1,
		__in_opt void* Argument2
		)
	{
		NTSTATUS status = STATUS_SUCCESS;
		
		TYPE* process;
		if (m_processWorker->GetProcess(PsGetCurrentProcessId(), &process))
			status = process->RegisterCallback(CallbackContext, Argument1, Argument2);

		return status;
	}
	
private:
	LARGE_INTEGER m_cookie;

	static CProcessCtxWorker<TYPE>* m_processWorker;
};

template<class TYPE>
CProcessCtxWorker<TYPE>* CProcessMonitor<TYPE>::m_processWorker;

#endif //__PROCESSMONITOR_H__
