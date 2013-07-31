/**
 * @file Constants.h
 * @author created by: Peter Hlavaty
 */

#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

#include "../Common/base/Common.h"
#include "../Common/base/Singleton.hpp"
#include "../Common/utils/AVL.hpp"
#include "../Common/utils/HashString.hpp"

class CConstants : 
	public CSingleton<CConstants>
{
	static CConstants m_instance;

	CConstants() : 
		CSingleton(m_instance)
	{
		for (size_t i = 0; i < _countof(ApplicationsToFuzz); i++)
			(void)m_applicationsToFuzzAVL.Insert(&CHashString(ApplicationsToFuzz[i]));
	}

public:
	CAVL<CHashString>& ApplicationsToFuzzAVL()
	{
		return m_applicationsToFuzzAVL;
	}
	
protected:
	CAVL<CHashString> m_applicationsToFuzzAVL;
	static const UNICODE_STRING ApplicationsToFuzz[1];
};

#endif //__CONSTANTS_H__
