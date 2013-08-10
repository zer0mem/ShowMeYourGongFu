/**
 * @file Process.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __PROCESS_H__
#define __PROCESS_H__

#include "../base/Common.h"
#include "../base/ComparableId.hpp"

class CEProcess :
	public COMPARABLE_ID<PEPROCESS>
{
public:
	explicit CEProcess(
		__in HANDLE processId
		) : COMPARABLE_ID(NULL)
	{
		if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &Id)))
			Id = NULL;
	}

	~CEProcess()
	{
		if (Id)
			ObDereferenceObject(Id);
	}

	PEPROCESS GetEProcess()
	{
		return Id;
	}
};

class CAutoProcessAttach
{
public:
	_IRQL_requires_max_(APC_LEVEL)
	CAutoProcessAttach(
		__in PEPROCESS process
	)
	{
		if (PsGetCurrentProcess() != process)
		{
			m_attached = true;
			KeStackAttachProcess((PRKPROCESS)process, &m_apcState);
		}
		else
		{
			m_attached = false;
		}
	}

	_IRQL_requires_max_(APC_LEVEL)
	~CAutoProcessAttach()
	{
		if (m_attached)
			KeUnstackDetachProcess(&m_apcState);
	}

	__checkReturn
	bool IsAttached()
	{
		return m_attached;
	}

protected:
	bool m_attached;
	KAPC_STATE m_apcState;
};

#endif //__PROCESS_H__
