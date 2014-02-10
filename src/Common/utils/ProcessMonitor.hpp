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
	typedef CAutoRef< CRefObjWorker<HANDLE, TYPE>, HANDLE, TYPE> CAutoProcWorkerRef;

//prohibit outside init
	void operator=(const CProcessMonitor&);

public:
	CProcessMonitor()
	{
		if (NT_VERIFY(KeGetCurrentIrql() == PASSIVE_LEVEL))
		{
			m_processWorker = new CRefObjWorker<HANDLE, TYPE>;
			if (m_processWorker)
			{
				//registry callback
				UNICODE_STRING altitude;
				RtlInitUnicodeString(&altitude, L"360055");//FSFilter Activity Monitor
				{

					NTSTATUS status = NULL;
					status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);

					ASSERT(STATUS_SUCCESS == status);

					status = PsSetLoadImageNotifyRoutine(ImageNotifyRoutine);
					ASSERT(STATUS_SUCCESS == status);

					status = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
					ASSERT(STATUS_SUCCESS == status);

					ASSERT(gDriverObject);
					status = CmRegisterCallbackEx(RegisterCallback, &altitude, gDriverObject, NULL, &m_cookie, NULL);
					ASSERT(STATUS_SUCCESS == status);
				}
			}
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

		delete m_processWorker;
	}
	
	static
	CRefObjWorker<HANDLE, TYPE>* GetProcessWorker()
	{
		return m_processWorker;
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
			CAutoProcWorkerRef parent(m_processWorker, createInfo->ParentProcessId);
			if (parent.IsReferenced() && parent.GetObj())
				parent.GetObj()->ChildProcessNotifyRoutineEx(eprocess, processId, createInfo);

			if (TYPE::WatchProcess(eprocess, processId, createInfo))
			{
				if (m_processWorker->Push(processId))
				{
					bool initialized = false;
					m_processWorker->Initialize(processId, new TYPE(eprocess, processId, createInfo), &initialized);
					if (!initialized)
						m_processWorker->Drop(processId);
				}
			}
		}
		else
		{
			m_processWorker->Drop(processId);
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
		CAutoProcWorkerRef proc(m_processWorker, processId);
		//could even happen to proc.GetObj() == NULL ?!
		if (proc.IsReferenced() && proc.GetObj())
 			proc.GetObj()->ImageNotifyRoutine(fullImageName, processId, imageInfo);
	}

	static
	void ThreadNotifyRoutine(
		__in HANDLE processId,
		__in HANDLE threadId,
		__in BOOLEAN create
		)
	{
		CAutoProcWorkerRef proc(m_processWorker, processId);
		if (proc.IsReferenced() && proc.GetObj())
		{
			if (processId == PsGetCurrentProcessId())
				proc.GetObj()->ThreadNotifyRoutine(processId, threadId, create);
			else
				proc.GetObj()->RemoteThreadNotifyRoutine(PsGetCurrentProcessId(), threadId, create);
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

		CAutoProcWorkerRef proc(m_processWorker, PsGetCurrentProcessId());
		if (proc.IsReferenced() && proc.GetObj())
			status = proc.GetObj()->RegisterCallback(CallbackContext, Argument1, Argument2);

		return status;
	}
	
private:
	LARGE_INTEGER m_cookie;

	static CRefObjWorker<HANDLE, TYPE>* m_processWorker;
};

template<class TYPE>
CRefObjWorker<HANDLE, TYPE>* CProcessMonitor<TYPE>::m_processWorker;

#endif //__PROCESSMONITOR_H__
