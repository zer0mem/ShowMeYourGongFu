/**
 * @file Mdl.cpp
 * @author created by: Peter Hlavaty
 */

#include "StdAfx.h"
#include "MemoryMapping.h"
#include "MMU.hpp"

//************* virtual to virtual *************

_IRQL_requires_max_(DISPATCH_LEVEL)
CMdl::CMdl(
	__in void* virtualAddress, 
	__in size_t size
	) : m_locked(false),
		m_mem(NULL)
{
	m_lockOperation = IoModifyAccess;
	m_mdl = IoAllocateMdl(virtualAddress, (ULONG)size, FALSE, FALSE, NULL);
}

CMdl::CMdl( 
	__in const void* virtualAddress, 
	__in size_t size 
	) : m_locked(false),
		m_mem(NULL)
{
	m_lockOperation = IoReadAccess;
	m_mdl = IoAllocateMdl(const_cast<void*>(virtualAddress), (ULONG)size, FALSE, FALSE, NULL);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CMdl::~CMdl()
{
	if (m_mdl)
	{
		if (m_locked)
		{
			MmUnlockPages(m_mdl);
			m_locked = false;
		}

		IoFreeMdl(m_mdl);
	}
}

//Callers of MmProbeAndLockPages must be running at IRQL <= APC_LEVEL for pageable addresses, or at IRQL <= DISPATCH_LEVEL for nonpageable addresses.
_IRQL_requires_max_(APC_LEVEL)
__checkReturn
bool CMdl::Lock(
	__in bool user
	)
{
	if (!m_locked)
	{
		__try 
		{
			MmProbeAndLockPages(m_mdl, user ? UserMode : KernelMode, m_lockOperation);
			m_locked = true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			//DbgPrint("\n LOCK ERROR\n");
		}
	}
	return m_locked;
}

//If AccessMode is UserMode, the caller must be running at IRQL <= APC_LEVEL. If AccessMode is KernelMode, the caller must be running at IRQL <= DISPATCH_LEVEL.
_IRQL_requires_max_(APC_LEVEL)
__checkReturn
const void* CMdl::ReadPtr(
	__in_opt MEMORY_CACHING_TYPE cacheType /*= MmCached*/ 
	)
{
	return Map(cacheType, false);
}

_IRQL_requires_max_(APC_LEVEL)
__checkReturn
void* CMdl::WritePtr( 
	__in_opt MEMORY_CACHING_TYPE cacheType /*= MmCached */
	)
{
//hook problems ... but this is wrong concept, find another solution ...
	if (m_lockOperation != IoReadAccess)
		return Map(cacheType, false);
	return NULL;
}

_IRQL_requires_max_(APC_LEVEL)
__checkReturn
void* CMdl::WritePtrUnsafe( 
	__in_opt MEMORY_CACHING_TYPE cacheType /*= MmCached */
	)
{
	//wrong concept ... used in colpatcher ...
	void* mapped = Map(cacheType, false);
	if (!mapped)
	{
		LOCK_OPERATION lock_op = m_lockOperation;
		m_lockOperation = IoReadAccess;
		mapped = Map(cacheType, false);
		m_lockOperation = lock_op;
	}

	return mapped;
}

_IRQL_requires_max_(APC_LEVEL)
const void* CMdl::ReadPtrUser( 
	__in_opt MEMORY_CACHING_TYPE cacheType /*= MmCached */ 
	)
{
	return Map(cacheType, true);
}

_IRQL_requires_max_(APC_LEVEL)
__checkReturn
void* CMdl::WritePtrUser( 
	__in_opt MEMORY_CACHING_TYPE cacheType /*= MmCached */ 
	)
{
	if (m_lockOperation == IoModifyAccess)
		return Map(cacheType, true);
	return NULL;
}


//Callers of MmUnmapLockedPages must be running at IRQL <= DISPATCH_LEVEL if the pages were mapped to system space. Otherwise, the caller must be running at IRQL <= APC_LEVEL.
_IRQL_requires_max_(APC_LEVEL)
void CMdl::Unmap()
{
	if (m_mem && m_mdl && !m_locked)
	{
		MmUnmapLockedPages(m_mem, m_mdl);
		m_mem = NULL;
	}
}

void* CMdl::Map( 
	__in MEMORY_CACHING_TYPE cacheType,
	__in bool user
	)
{
	if (m_mdl && !m_mem)
	{
		if (Lock(user))
		{
			__try 
			{
				m_mem = MmMapLockedPagesSpecifyCache(m_mdl, user ? UserMode : KernelMode, cacheType, NULL, FALSE, NormalPagePriority);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				//DbgPrint("\nMAP ERROR\n");
			}
		}
	}
	return m_mem;
}

_IRQL_requires_max_(APC_LEVEL)
__checkReturn 
const void* CMdl::ForceReadPtrUser( 
	__in_opt MEMORY_CACHING_TYPE cacheType /*= MmCached */
	)
{
	const void* mem = ReadPtrUser();
	if (!mem)
		mem = ReadPtr();
	return mem;
}

_IRQL_requires_max_(APC_LEVEL)
__checkReturn
void* CMdl::ForceWritePtrUser( 
	__in_opt MEMORY_CACHING_TYPE cacheType /*= MmCached */
	)
{
	void* mem = WritePtrUser();
	if (!mem)
	{
		mem = WritePtr();
		if (!mem)
			mem = WritePtrUnsafe();
	}
	return mem;		
}

//************* physical to virtual *************

_IRQL_requires_max_(DISPATCH_LEVEL)
CMmMap::CMmMap( 
	__in ULONG_PTR address,
	__in size_t size
	)
{
	Init(address, size);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CMmMap::CMmMap( 
	__in const void* address, 
	__in size_t size 
	)
{
	Init((ULONG_PTR)address, size);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CMmMap::CMmMap( 
	__in const PHYSICAL_ADDRESS& address,
	__in size_t size
	)
{
	Init(address.QuadPart, size);
}

void CMmMap::Init(
	__in ULONG_PTR address,
	__in size_t size
	)
{
	m_size = size;
	RtlZeroMemory(&m_addrPhysical, sizeof(m_addrPhysical));
	m_addrPhysical.QuadPart = address;

	m_addrVirtual = MapPhysicalToVirtual(m_addrPhysical, m_size);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CMmMap::~CMmMap()
{
	if (m_addrVirtual)//int nt!kipagefault getnexttable IRQL_NOT_LESS_OR_EQUAL
		MmUnmapIoSpace(m_addrVirtual, m_size);
}

void* CMmMap::GetVirtualAddress()
{
	return m_addrVirtual;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void* CMmMap::MapPhysicalToVirtual(
	__in const PHYSICAL_ADDRESS& address, 
	__in size_t size 
	)
{
	return MmMapIoSpace(address, size, MmNonCached);
}
