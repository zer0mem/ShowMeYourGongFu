/**
 * @file MemoryMapping.h
 * @author created by: Peter Hlavaty
 */

#ifndef __MEMORYMAPPING_H__
#define __MEMORYMAPPING_H__

#include "../base/Common.h"
#include "IRQL.hpp"

//this objects work on DISPATCH_LEVEL. Dont change its IRQL during working with this object!
//suposed to use just for quick map & copy/write data ...

class CMdl
{
public:
	CMdl(
		__in const void* virtualAddress, 
		__in size_t size
		);
	~CMdl();

	__checkReturn bool Lock(
		__in_opt LOCK_OPERATION operation = IoReadAccess
		);

	void* Map(
		__in_opt MEMORY_CACHING_TYPE cacheType = MmCached
		);
	void Unmap();
	
	//getter
	void* GetMappedVirtualAddress();

protected:
	MDL* m_mdl;
	void* m_mem;
	bool m_locked;
	CDispatchLvl m_DispatchIRQL;
};

class CMmMap
{
public:
	CMmMap(
		__in ULONG_PTR address,
		__in size_t size
		);

	CMmMap(
		__in const void* address,
		__in size_t size
		);

	CMmMap(
		__in const PHYSICAL_ADDRESS& address, 
		__in size_t size
		);

	~CMmMap();

	void* GetVirtualAddress();

protected:
	void Init(
		__in ULONG_PTR address,
		__in size_t size
		);

	void* MapPhysicalToVirtual(
		__in const PHYSICAL_ADDRESS& address, 
		__in size_t size
		);

protected:
	PHYSICAL_ADDRESS m_addrPhysical;
	size_t m_size;
	void* m_addrVirtual;
};

#endif //__MEMORYMAPPING_H__
