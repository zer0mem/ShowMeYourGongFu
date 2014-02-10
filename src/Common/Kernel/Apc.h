/**
 * @file Apc.h
 * @author created by: Peter Hlavaty
 */

#ifndef __APC_H__
#define __APC_H__

#include "../base/Common.h"

#include "ntifs.h"
#include "wdm.h"

#include "AutoId.hpp"
#include "../utils/Undoc.hpp"

class CApc
{
public:
	explicit CApc(
		__in HANDLE threadId,
		__in_opt KAPC_ENVIRONMENT apcEnviroment = OriginalApcEnvironment,
		__in_opt MODE ringMode = KernelMode,
		__in_opt void* r3func = NULL,
		__in_opt void* normalCtx = NULL,
		__in_opt PKRUNDOWN_ROUTINE r0runDown = NULL
		) : m_thread(threadId),
			m_keRemoveQueueApc(CUndoc::KeRemoveQueueApcPtr())
	{
		if (m_thread.IsReferenced() && m_keRemoveQueueApc)
		{
			KeInitializeApc(
				&m_apc, 
				m_thread.GetRef(), 
				apcEnviroment, 
				StaticKApc, 
				r0runDown, 
				static_cast<PKNORMAL_ROUTINE>(r3func),//normal_routine, 
				ringMode,
				normalCtx);
		}
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	~CApc()
	{
		//if not removed yet, then do it now!
		m_keRemoveQueueApc(&m_apc);
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	__checkReturn 
	bool Run(
		__in_opt void* arg = NULL,
		__in_opt KPRIORITY priority = LOW_PRIORITY
		)
	{
		return !!KeInsertQueueApc(&m_apc, this, arg, priority);
	}

protected:
	//prohibited to free Apc, in kernel routine!!!
	virtual 
	void CustomKapc(
		__in struct _KAPC* Apc,
		__deref_inout_opt PKNORMAL_ROUTINE* NormalRoutine,
		__deref_inout_opt void** NormalContext,
		__deref_inout_opt void** SystemArgument
		) = 0;

private:
	static 
	void StaticKApc(
		__in KAPC* Apc,
		__deref_inout_opt PKNORMAL_ROUTINE* NormalRoutine,
		__deref_inout_opt void** NormalContext,
		__deref_inout_opt void** ThisPointer,
		__deref_inout_opt void** SystemArgument2
		)
	{
		if (ThisPointer)
		{
			CApc* apc = static_cast<CApc*>(*ThisPointer);
			if (apc)
				apc->CustomKapc(Apc, NormalRoutine, NormalContext, SystemArgument2);
		}
	}

protected:
	KAPC m_apc;
	CThreadById m_thread;
	KeRemoveQueueApc m_keRemoveQueueApc;
};

//necessary to inherit and do implement CustomKapc; whithout RunDown
class CSpecialApc :
	public CApc
{
public:
	CSpecialApc(
		__in HANDLE threadId,
		__in_opt KAPC_ENVIRONMENT apcEnviroment = OriginalApcEnvironment
		) : CApc(threadId, apcEnviroment)
	{
	}
};

//necessary to inherit and do implement CustomKapc; whithout RunDown
class CKernelUserApc :
	public CApc
{
public:
	CKernelUserApc(
		__in HANDLE threadId,
		__in void* r3func,
		__in_opt void* normalCtx = NULL,
		__in_opt MODE ringMode = UserMode,
		__in_opt KAPC_ENVIRONMENT apcEnviroment = OriginalApcEnvironment
		) : CApc(threadId, apcEnviroment, ringMode, r3func, normalCtx)
	{
	}
};

//ready to use, dummpy CustomKapc
class CUserApc :
	public CApc
{
public:
	CUserApc(
		__in HANDLE threadId,
		__in void* r3func,
		__in_opt void* normalCtx = NULL,
		__in_opt MODE ringMode = UserMode,
		__in_opt KAPC_ENVIRONMENT apcEnviroment = OriginalApcEnvironment
		) : CApc(threadId, apcEnviroment, ringMode, r3func, normalCtx)
	{
	}

protected:
	virtual 
	void CustomKapc(
		__in struct _KAPC* Apc,
		__deref_inout_opt PKNORMAL_ROUTINE* NormalRoutine,
		__deref_inout_opt void** NormalContext,
		__deref_inout_opt void** SystemArgument
		) override 
	{
		//dummy
	}
};

class CDisableApc
{
public:
	_IRQL_requires_max_(APC_LEVEL)
	CDisableApc()
	{
		KeEnterGuardedRegion();
	}
	_IRQL_requires_max_(APC_LEVEL)
	~CDisableApc()
	{
		KeLeaveGuardedRegion();
	}
};

class CDisableSpecialApc
{
public:
	_IRQL_requires_max_(APC_LEVEL)
	CDisableSpecialApc()
	{
		KeEnterCriticalRegion();
	}
	_IRQL_requires_max_(APC_LEVEL)
	~CDisableSpecialApc()
	{
		KeLeaveCriticalRegion();
	}
};

#endif //__APC_H__
