/**
 * @file Process.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __PROCESS_H__
#define __PROCESS_H__

#include "../base/Common.h"

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
protected:
	bool m_attached;
	KAPC_STATE m_apcState;
};

#endif //__PROCESS_H__
