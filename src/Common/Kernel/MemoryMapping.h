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
		__in void* virtualAddress, 
		__in size_t size
		);

	CMdl(
		__in const void* virtualAddress, 
		__in size_t size
		);

	~CMdl();

	_IRQL_requires_max_(APC_LEVEL)
	__checkReturn
	bool Lock();

	_IRQL_requires_max_(APC_LEVEL)
	__checkReturn
	const void* ReadPtr(
		__in_opt MEMORY_CACHING_TYPE cacheType = MmCached
		);

	_IRQL_requires_max_(APC_LEVEL)
	__checkReturn
	void* WritePtr(
		__in_opt MEMORY_CACHING_TYPE cacheType = MmCached
		);

	_IRQL_requires_max_(APC_LEVEL)
	__checkReturn
	const void* ReadPtrUser(
		__in_opt MEMORY_CACHING_TYPE cacheType = MmCached
		);

	_IRQL_requires_max_(APC_LEVEL)
	__checkReturn
	void* WritePtrUser(
		__in_opt MEMORY_CACHING_TYPE cacheType = MmCached
		);

	void Unmap();

protected:
	void* Map(
		__in_opt MEMORY_CACHING_TYPE cacheType,
		__in bool user
		);

protected:
	MDL* m_mdl;
	void* m_mem;
	bool m_locked;
	LOCK_OPERATION  m_lockOperation;
	CApcLvl m_apcIRQL;
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
