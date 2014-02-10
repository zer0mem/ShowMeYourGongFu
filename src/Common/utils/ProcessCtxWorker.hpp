/**
 * @file ProcessCtxWorker.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __PROCESSCTXWORKER_H__
#define __PROCESSCTXWORKER_H__

#include "../base/Common.h"
#include "HashString.hpp"
#include "ProcessCtx.h"
#include "../base/ComparableId.hpp"

#include "../base/RefCounter.hpp"

template<class TYPE>
class CProcessCtxWorker : 
	protected CRefObjWorker<HANDLE, TYPE>
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
		if (Initialize(processId, proc_ctx))
			proc_ctx->ProcessNotifyRoutineEx(process, processId, createInfo);
	}

	void UnregisterProcess(
		__inout PEPROCESS process,
		__in HANDLE processId
		)
	{
		//auto ref, to get references to call unloading process
		CAutoRef<CProcessCtxWorker, HANDLE, PROCESS_CTX> auto_proc_ctx;		
		Drop(processId);//dont allow additional ref to this obj!

		//notify about unloading process
		if (auto_proc_ctx.IsReferenced())
		{
			TYPE* proc_ctx = auto_proc_ctx.GetObj();
			if (proc_ctx)
				proc_ctx->ProcessNotifyRoutineEx(process, processId, NULL);
		}
		//~CautoRef == delete proc_ctx (if no one else hold ref ...)
	}
};

#endif //__PROCESSCTXWORKER_H__
