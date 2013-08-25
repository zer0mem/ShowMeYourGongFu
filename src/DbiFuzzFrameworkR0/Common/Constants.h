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

enum
{
	ExtTrapTrace,
	ExtInfo,
	ExtHook,
	ExtCount
};

class CConstants : 
	public CSingleton<CConstants>
{
	static CConstants m_instance;

	CConstants() : 
		CSingleton(m_instance)
	{
		for (size_t i = 0; i < _countof(m_applicationsToFuzz); i++)
			(void)m_applicationsToFuzzAVL.Insert(&CHashString(m_applicationsToFuzz[i]));

		for (size_t i = 0; i < _countof(m_inAppModules); i++)
			(void)m_inAppModulesAVL.Insert(&CHashString(m_inAppModules[i]));

		for (size_t i = 0; i < _countof(m_systemModules); i++)
			(void)m_systemModulesAVL.Insert(&CHashString(m_systemModules[i]));
	}

public:
	CAVL<CHashString>& ApplicationsToFuzzAVL()
	{
		return m_applicationsToFuzzAVL;
	}

	CAVL<CHashString>& InAppModulesAVL()
	{
		return m_inAppModulesAVL;
	}

	CAVL<CHashString>& SystemModulesAVL()
	{
		return m_systemModulesAVL;
	}

	static 
	const CHAR* InAppExtRoutines(
		__in size_t ind
		)
	{
		if (ind < _countof(m_inAppExtRoutines))
			return m_inAppExtRoutines[ind].Buffer;

		return NULL;
	}
	
protected:
	CAVL<CHashString> m_applicationsToFuzzAVL;
	CAVL<CHashString> m_inAppModulesAVL;
	CAVL<CHashString> m_systemModulesAVL;

	static const UNICODE_STRING m_applicationsToFuzz[2];
	static const UNICODE_STRING m_inAppModules[1];
	static const UNICODE_STRING m_systemModules[6];

	static const STRING m_inAppExtRoutines[ExtCount];
};

#endif //__CONSTANTS_H__
