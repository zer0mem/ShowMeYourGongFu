/**
 * @file Process.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __PROCESS_H__
#define __PROCESS_H__

#include "../base/Common.h"
#include "../base/ComparableId.hpp"

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

class CEProcess :
	public CProcessAttach
{
public:
	explicit CEProcess(
		__in HANDLE processId
		) : CProcessAttach(NULL),
			m_processId(processId)
	{
		if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &Id)))
			Id = NULL;
	}

	~CEProcess()
	{
		if (Id)
			ObDereferenceObject(Id);
	}

	HANDLE ProcessId()
	{
		return m_processId;
	}

protected:
	HANDLE m_processId;
	CProcessAttach m_attach;
};

class CAutoEProcessAttach
{
public:
	_IRQL_requires_max_(APC_LEVEL)
	CAutoEProcessAttach(
		__in CEProcess& eprocess
		) : m_eprocess(eprocess)
	{
		m_eprocess.Attach();
	}

	_IRQL_requires_max_(APC_LEVEL)
	~CAutoEProcessAttach()
	{
		m_eprocess.Detach();
	}

private:
	CEProcess& m_eprocess;
};

#endif //__PROCESS_H__
