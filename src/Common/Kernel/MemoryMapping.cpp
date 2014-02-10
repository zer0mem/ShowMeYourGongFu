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
	) : m_mem(NULL)
{
	m_lockOperation = IoModifyAccess;
	m_mdl = IoAllocateMdl(virtualAddress, (ULONG)size, FALSE, FALSE, NULL);
}

CMdl::CMdl( 
	__in const void* virtualAddress, 
	__in size_t size 
	) : m_mem(NULL)
{
	m_lockOperation = IoReadAccess;
	m_mdl = IoAllocateMdl(const_cast<void*>(virtualAddress), (ULONG)size, FALSE, FALSE, NULL);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
CMdl::~CMdl()
{
	if (m_mdl)
	{
		if (m_mdl->MdlFlags & MDL_PAGES_LOCKED)
			MmUnlockPages(m_mdl);

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
	if (!m_mdl)
		return false;
	//should to be spinlocked ?!
	if (0 == (m_mdl->MdlFlags & MDL_PAGES_LOCKED))
	{
		__try 
		{
			MmProbeAndLockPages(m_mdl, static_cast<KPROCESSOR_MODE>(user ? UserMode : KernelMode), m_lockOperation);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			m_mdl->MdlFlags &= ~MDL_PAGES_LOCKED;
		}
	}
	return (0 != (m_mdl->MdlFlags & MDL_PAGES_LOCKED));
}

//Callers of MmUnmapLockedPages must be running at IRQL <= DISPATCH_LEVEL if the pages were mapped to system space. Otherwise, the caller must be running at IRQL <= APC_LEVEL.
_IRQL_requires_max_(APC_LEVEL)
	void CMdl::Unmap()
{
	if (m_mem && m_mdl && !(m_mdl->MdlFlags & MDL_PAGES_LOCKED))
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
				m_mem = MmMapLockedPagesSpecifyCache(m_mdl, static_cast<KPROCESSOR_MODE>(user ? UserMode : KernelMode), cacheType, NULL, FALSE, NormalPagePriority);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("\nMAP ERROR\n");
			}
		}
	}
	return m_mem;
}

//If AccessMode is UserMode, the caller must be running at IRQL <= APC_LEVEL. If AccessMode is KernelMode, the caller must be running at IRQL <= DISPATCH_LEVEL.
_IRQL_requires_max_(DISPATCH_LEVEL)
__checkReturn
const void* CMdl::ReadPtr(
	__in_opt MEMORY_CACHING_TYPE cacheType /*= MmCached*/ 
	)
{
	return Map(cacheType, false);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
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

_IRQL_requires_max_(APC_LEVEL)
__checkReturn 
const void* CMdl::ForceReadPtrUser( 
	__in_opt MEMORY_CACHING_TYPE cacheType /*= MmCached */
	)
{
	UNREFERENCED_PARAMETER(cacheType);
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
	UNREFERENCED_PARAMETER(cacheType);
	void* mem = WritePtrUser();
	if (!mem)
	{
		mem = WritePtr();
		if (!mem)
			mem = WritePtrUnsafe();
	}
	return mem;		
}

_IRQL_requires_max_(APC_LEVEL)
__checkReturn
const void* CMdl::ReadPtrToUser( 
	__in_opt MEMORY_CACHING_TYPE cacheType /*= MmCached */
	)
{
	UNREFERENCED_PARAMETER(cacheType);
	if (Lock(false))
		return ReadPtrUser();
	return NULL;
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
	Init(static_cast<ULONG_PTR>(address.QuadPart), size);
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
