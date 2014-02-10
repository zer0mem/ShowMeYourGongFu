/**
 * @file Process.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __PROCESS_H__
#define __PROCESS_H__

#include "../base/Common.h"
#include "../base/ComparableId.hpp"
#include "AutoId.hpp"

class CProcessAttach :
	public COMPARABLE_ID<PEPROCESS>
{
public:
	CProcessAttach(
		__in_opt PEPROCESS process = NULL
		) : COMPARABLE_ID(process)
	{
		m_attached = false;
	}

	_IRQL_requires_max_(APC_LEVEL)
	~CProcessAttach()
	{
		Detach();
	}

	__checkReturn
	bool IsAttached()
	{
		return m_attached;
	}

	_IRQL_requires_max_(APC_LEVEL)
	bool Attach()
	{
		if (Id && !m_attached)
		{
			KeStackAttachProcess(reinterpret_cast<PRKPROCESS>(Id), &m_apcState);				
			m_attached = true;
			return true;
		}
		return false;
	}

	_IRQL_requires_max_(APC_LEVEL)
	void Detach()
	{
		if (m_attached)
			KeUnstackDetachProcess(&m_apcState);

		m_attached = false;
	}

protected:
	bool m_attached;
	KAPC_STATE m_apcState;
};

class CAutoProcessAttach :
	public CProcessAttach
{
public:
	_IRQL_requires_max_(APC_LEVEL)
	CAutoProcessAttach(
		__in PEPROCESS process
		) : CProcessAttach(process)
	{
		Attach();
	}

	_IRQL_requires_max_(APC_LEVEL)
	~CAutoProcessAttach()
	{
		Detach();
	}
};

class CAutoProcessIdAttach :
	public CProcessAttach
{
public:
	_IRQL_requires_max_(APC_LEVEL)
		CAutoProcessIdAttach(
		__in HANDLE processId
		) : m_eprocess(processId),
		CProcessAttach(m_eprocess.GetRef())
	{
		if (m_eprocess.ProcessId())
			Attach();
	}

private:
	CProcessById m_eprocess;
};

#endif //__PROCESS_H__
