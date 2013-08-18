/**
 * @file ProcessCtxWorker.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __PROCESSCTXWORKER_H__
#define __PROCESSCTXWORKER_H__

#include "../base/Common.h"
#include "LockedContainers.hpp"
#include "HashString.hpp"
#include "ProcessCtx.h"
#include "../base/ComparableId.hpp"

template<class TYPE>
class CProcessCtxWorker : 
	protected CLockedAVL< COMPARABLE_ID_PTR<HANDLE, TYPE> >
{
	typedef COMPARABLE_ID_PTR<HANDLE, TYPE> PROCESS_CTX;
public:
	__checkReturn
	bool RegisterProcess(
		__inout PEPROCESS process,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
	)
	{
		TYPE* proc_ctx = new TYPE(process, processId, createInfo);
		if (proc_ctx)
		{
			PROCESS_CTX proc_ctx_id(processId, proc_ctx);
			if (Push(proc_ctx_id))
			{
				proc_ctx->ProcessNotifyRoutineEx(process, processId, createInfo);
				//avoid free context...
				proc_ctx_id.Value = NULL;
				return true;
			}
		}
		//not sucessfully ctor & insert
		delete proc_ctx;
		return false;
	}

	void UnregisterProcess(
		__inout PEPROCESS process,
		__in HANDLE processId
		)
	{	
		TYPE* proc_ctx = NULL;
		{
			SPIN_LOCK
			PROCESS_CTX* proc_ctx_id;
			//due unique of procId not necessary to handle equal procid in avl
			if (m_avl.Find(&PROCESS_CTX(processId), &proc_ctx_id))
			{
				proc_ctx = proc_ctx_id->Value;

				//avoid dtor in spinlock
				proc_ctx_id->Value = NULL;
				m_avl.Remove(proc_ctx_id);
			}
		}

		//delete outside of spinlock
		if (proc_ctx)
		{
			proc_ctx->ProcessNotifyRoutineEx(process, processId, NULL);
			delete proc_ctx;
		}
	}

	//TODO : implement shared_ptr !
	__checkReturn
	bool GetProcess(
		__in HANDLE processId,
		__inout TYPE** out
		)
	{
		SPIN_LOCK
		PROCESS_CTX* proc_ctx_id;
		if (m_avl.Find(&PROCESS_CTX(processId), &proc_ctx_id))
		{
			if (proc_ctx_id && proc_ctx_id->Value)
			{
				*out = proc_ctx_id->Value;
				return true;
			}
		}
		return false;
	}


	//TODO : implement shared_ptr !
	__checkReturn
	bool GetProcessUnsafe(
		__in HANDLE processId,
		__inout TYPE** out
		)
	{
		PROCESS_CTX* proc_ctx_id = NULL;
		bool ret = (m_avl.Find(&PROCESS_CTX(processId), &proc_ctx_id));
		{
			if (proc_ctx_id && proc_ctx_id->Value)
			{
				*out = proc_ctx_id->Value;
				return ret;
			}
		}
		return false;
	}
};

#endif //__PROCESSCTXWORKER_H__
