/**
 * @file CDelayLoadEntryPointHook.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __CDELAYLOADENTRYPOINTHOOK_H__
#define __CDELAYLOADENTRYPOINTHOOK_H__

#include "../base/Common.h"
#include "PE.hpp"
#include "ColdPatcher.hpp"

class CDelayLoadMzEntryPointHook :
	public COMPARABLE_ID<void*>
{
public:
	CDelayLoadMzEntryPointHook() : 
		COMPARABLE_ID(NULL),
		m_addrToHook(NULL),
		m_addrOfHook(NULL),
		m_relHook(NULL)
	{
	}

	CDelayLoadMzEntryPointHook(
		__in void* addrToHook 
		) : COMPARABLE_ID(addrToHook),
			m_addrToHook(addrToHook),
			m_addrOfHook(NULL),
			m_relHook(NULL)
	{
	}

	~CDelayLoadMzEntryPointHook()
	{
		UninstallHook();
	}

	void InitBase( 
		__in void* base 
		)
	{
		if (!IsInitialized())
		{
			CMdl mapped_img(base, 0x1000);
			void* img = mapped_img.Map();
			if (img)
			{
				CPE mz(img);
				if (mz.IsValid())
					m_addrToHook = reinterpret_cast<void*>(reinterpret_cast<BYTE*>(base) + mz.Entrypoint());
			}
		}
	}

	void SetUpHook( 
		__in const void* addrOfHook 
		)
	{
		m_addrOfHook = addrOfHook;
	}

	void InstallHook()
	{
		if (!m_relHook && m_addrOfHook && CMMU::IsValid(m_addrToHook))
		{
			m_relHook = new CRelCallHook(m_addrToHook, m_addrOfHook);
			if (!m_relHook->IsHooked())
			{
				delete m_relHook;
				m_relHook = NULL;
			}
		}
	}

	void UninstallHook()
	{
		m_addrToHook = NULL;
		m_addrOfHook = NULL;
		delete m_relHook;
		m_relHook = NULL;
	}

	__checkReturn
	bool IsHooked()
	{
		return (!!m_relHook && m_addrToHook && m_addrOfHook && m_relHook->IsHooked());
	}

	__checkReturn
	bool IsInitialized()
	{
		return !!m_addrToHook;
	}

	void* GetAddrToHook()
	{
		return m_addrToHook;
	}

protected:
	void* m_addrToHook;
	const void* m_addrOfHook;
	CRelCallHook* m_relHook;
};

#endif //__CDELAYLOADENTRYPOINTHOOK_H__
