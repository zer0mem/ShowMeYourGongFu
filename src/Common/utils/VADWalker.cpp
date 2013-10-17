/**
 * @file VADWalker.cpp
 * @author created by: Peter Hlavaty
 */

#include "stdafx.h"
#include "VADWalker.h"

#include "../Common/utils/Undoc.hpp"
#include "../Common/Kernel/MMU.hpp"

//------------------------------------------------------
// ****************** VAD AVL SCANNER ******************
//------------------------------------------------------


//////////////////////////////////////////////////////////////////////////
//auto class - helper obj
//////////////////////////////////////////////////////////////////////////

class CAutoVadShort
{
#define MIN_VAD_ALLOC_SIZE (max((size_t)CUndoc::EndingVpn(NULL), (size_t)CUndoc::StartingVpn(NULL)) + sizeof(*CUndoc::StartingVpn(NULL)))
public:
	CAutoVadShort(
		__in const void* startAddr,
		__in const void* endAddr = NULL
		) : m_autoFind(reinterpret_cast<VAD_SHORT*>( malloc(MIN_VAD_ALLOC_SIZE) ))
	{
		if (m_autoFind)
		{
			if (!endAddr)
				endAddr = startAddr;

			*CUndoc::StartingVpn(m_autoFind) = (ULONG)((ULONG_PTR)startAddr >> PAGE_SHIFT);
			*CUndoc::EndingVpn(m_autoFind) = (ULONG)((ULONG_PTR)endAddr >> PAGE_SHIFT);
		}
	}

	__checkReturn 
	bool GetFakeVadShort(
		__out VAD_SHORT** vadShort
		)
	{
		if (m_autoFind)
		{
			*vadShort = m_autoFind;
			return true;
		}
		return false;
	}

	~CAutoVadShort()
	{
		if (m_autoFind)
			free(m_autoFind);
	}
	
protected:
	VAD_SHORT* m_autoFind;
};

CVadScanner::CVadScanner( 
	__in PEPROCESS process
	) : m_process(process)
{
}

__checkReturn 
bool CVadScanner::ScanAddressSpace()
{
	CApcLvl irql;
	CVADScanLock vad_lock(m_process);
	if (vad_lock.IsLocked())
	{
		CVadWalker vad(m_process);
		
		const VAD_SHORT* mem_descryptor = vad.GetLowerBound();
		if (mem_descryptor)
		{
			do
			{
				CVadNodeMemRange mem(mem_descryptor);

				DbgPrint("\n>>> !Memory by VAD : %p %p [%p] %s", 
					mem.Begin(), 
					mem.End(), 
					mem.GetFlags(), 
					(mem.IsWriteable() ? "is writeable!" : "non writeable!")
					);

			} while(vad.GetNext(&mem_descryptor));

			return true;
		}
	}
	DbgPrint("\nerror not locked!!!");
	return false;
}

__checkReturn
bool CVadScanner::FindVadMemoryRange( 
	__in const void* addr, 
	__inout CVadNodeMemRange* vadMemRange
	)
{
	CApcLvl irql;
	CVADScanLock vad_lock(m_process);
	if (vad_lock.IsLocked())
	{
		CVadWalker vad(m_process);

		VAD_SHORT* mem_find;
		CAutoVadShort auto_vad(addr);
		if (auto_vad.GetFakeVadShort(&mem_find))
		{
			VAD_SHORT* mem_descryptor = NULL;
			if (vad.Find(mem_find, &mem_descryptor))
			{
				CVadNodeMemRange mem(mem_descryptor);
				*vadMemRange = mem;
				return true;
			}

		}
	}
	return false;
}

__checkReturn
bool CVadScanner::GetNextVadMemoryRange( 
	__in const void* addr, 
	__inout CVadNodeMemRange* vadMemRange
	)
{
	CApcLvl irql;
	CVADScanLock vad_lock(m_process);
	if (vad_lock.IsLocked())
	{
		CVadWalker vad(m_process);

		VAD_SHORT* mem_find;
		CAutoVadShort auto_vad(addr);
		if (auto_vad.GetFakeVadShort(&mem_find))
		{
			VAD_SHORT* mem_descryptor = NULL;
			if (vad.Find(mem_find, &mem_descryptor))//== get lowerbound if addr = 0...
				if (!vad.GetNext(const_cast<const VAD_SHORT**>(&mem_descryptor)))
					return false;

			if (mem_descryptor)
			{
				CVadNodeMemRange mem(mem_descryptor);
				*vadMemRange = mem;
				return true;
			}
		}
	}
	return false;
}

bool CVadScanner::SetVadMemoryRangeFlags( 
	__in const void* addr, 
	__in MMVAD_FLAGS flags
	)
{
	CApcLvl irql;
	CVADScanLock vad_lock(m_process);
	if (vad_lock.IsLocked())
	{
		CVadWalker vad(m_process);

		VAD_SHORT* mem_find;
		CAutoVadShort auto_vad(addr);
		if (auto_vad.GetFakeVadShort(&mem_find))
		{
			VAD_SHORT* mem_descryptor;
			if (vad.Find(mem_find, &mem_descryptor))
			{
				*CUndoc::Flags(mem_descryptor) = flags;
				return true;
			}
		}
	}
	return false;
}

__checkReturn
void CVadScanner::SetUnwriteable( 
	__in const void* addr, 
	__in size_t size 
	)
{
	void* end_addr = reinterpret_cast<BYTE*>((ULONG_PTR)addr + size);
	for (CVadNodeMemRange vad_mem; 
		end_addr > addr && FindVadMemoryRange(addr, &vad_mem); 
		addr = vad_mem.End() + 1)
	{
		if (vad_mem.IsWriteable())
		{
			//temporary skip this pages, further investigation ...
			if (vad_mem.IsWriteCopy())
				continue;

			MMVAD_FLAGS flags = vad_mem.GetFlags();
			
			BYTE low_prot = vad_mem.IsExecuteable() ? 3 /*PAGE_EXECUTE_READ*/ : 1 /*PAGE_READONLY*/;
			flags.Protection = (flags.Protection & (~7)) | low_prot;
			
			SetVadMemoryRangeFlags(addr, flags);
		}
	}
}

//------------------------------------------------------------------
// ****************** VAD_ROOT ADDRESS SPACE LOCK ******************
//------------------------------------------------------------------ 

CVADScanLock::CVADScanLock(
	__in PEPROCESS process
	) :	m_attach(process), 
	m_addressSpaceLock(CUndoc::AddressCreationLock(process)),
	m_workingSetLock(CUndoc::WorkingSetMutex(process))
{
	ASSERT(process && MmIsAddressValid(process));

	if (CUndoc::Flags(process)->VmDeleted)
	{
		m_locked = false;
	}
	else
	{
		m_workingSetLock.Lock();

		m_locked = true;
		PETHREAD ethread = PsGetCurrentThread();
		CUndoc::SameThreadApcFlags(ethread)->OwnsProcessAddressSpaceExclusive = TRUE;
		CUndoc::SameThreadApcFlags(ethread)->OwnsProcessWorkingSetExclusive = TRUE;
	}
}

CVADScanLock::~CVADScanLock()
{
	if (m_locked)
	{
		m_workingSetLock.Unlock();

		PETHREAD ethread = PsGetCurrentThread();
		CUndoc::SameThreadApcFlags(ethread)->OwnsProcessAddressSpaceExclusive = FALSE;
		CUndoc::SameThreadApcFlags(ethread)->OwnsProcessWorkingSetExclusive = FALSE;
	}
}

__checkReturn bool CVADScanLock::IsLocked()
{
	return m_locked;
}

//------------------------------------------------------------
// ****************** VAD_NODE MEMORY RANGE ****************** 
//------------------------------------------------------------

CVadNodeMemRange::CVadNodeMemRange( 
	__in const VAD_SHORT* vadNode 
	) : CMemoryRange(
			reinterpret_cast<BYTE*>(EXPAND(*CUndoc::StartingVpn(vadNode))), 
			EXPAND(*CUndoc::EndingVpn(vadNode) - *CUndoc::StartingVpn(vadNode) + 1),
			*reinterpret_cast<const ULONG*>(CUndoc::Flags(vadNode))
			)
{

}

//-----------------------------------------------------
// ****************** VAD AVL WALKER ******************
//-----------------------------------------------------

struct VAD_SHORT
{
	friend 
	__forceinline 
	bool operator>(
		__in const VAD_SHORT& left, 
		__in const VAD_SHORT& right
		)
	{
		return (CVadNodeMemRange(&left) > CVadNodeMemRange(&right));
	}

	friend
	__forceinline
	bool operator==(
		__in const VAD_SHORT& left, 
		__in const VAD_SHORT& right
		)
	{

		return (CVadNodeMemRange(&left) == CVadNodeMemRange(&right));
	}
};

#define VAD_PARENT_OFFSET ((size_t)CUndoc::Parent(NULL))
#define VAD_LEFTCH_OFFSET ((size_t)CUndoc::LeftChild(NULL))
#define VAD_RGHTCH_OFFSET ((size_t)CUndoc::RightChild(NULL))

CVadWalker::CVadWalker( 
	__in PEPROCESS process 
	) : CBinTreeWalker(
			reinterpret_cast<const VAD_SHORT**>(CUndoc::RightChild(reinterpret_cast<const MMVAD_SHORT*>(CUndoc::VadRoot(process)))),
			VAD_PARENT_OFFSET, 
			VAD_LEFTCH_OFFSET, 
			VAD_RGHTCH_OFFSET, 
			CUndoc::AvlSanity()		
			),
			m_avlInfo(CUndoc::AVLInfo(reinterpret_cast<MM_AVL_TABLE*>(CUndoc::VadRoot(process))))
{

}
