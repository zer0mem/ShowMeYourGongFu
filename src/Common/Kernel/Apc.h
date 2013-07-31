/**
 * @file Apc.h
 * @author created by: Peter Hlavaty
 */

#ifndef __APC_H__
#define __APC_H__

#include "../base/Common.h"

class CDisableKernelApc
{
public:
	CDisableKernelApc()
	{
		KeEnterGuardedRegion();
	}
	~CDisableKernelApc()
	{
		KeLeaveGuardedRegion();
	}
};

class CDisableSpecialApc
{
public:
	CDisableSpecialApc()
	{
		KeEnterCriticalRegion();
	}
	~CDisableSpecialApc()
	{
		KeLeaveCriticalRegion();
	}
};

#endif //__APC_H__
