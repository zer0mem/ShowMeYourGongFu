/**
 * @file VADWalker.h
 * @author created by: Peter Hlavaty
 */

#ifndef __VADWALKER_H__
#define __VADWALKER_H__

#include "../base/Common.h"

#include "../Kernel/IRQL.hpp"
#include "../Kernel/Lock.hpp"
#include "../Kernel/Apc.h"

#include "../utils/Vad.h"
#include "../utils/Undoc.h"

#include "../utils/BinTreeWalker.hpp"

#include "../Kernel/MMU.h"
#include "../utils/MemoryRange.h"

#include "../Kernel/Process.hpp"

//------------------------------------------------------------
// ****************** VAD_NODE MEMORY RANGE ****************** 
//------------------------------------------------------------

class CVadNodeMemRange : 
	public CMemoryRange
{
#define EXPAND(addr) (ULONG_PTR)((ULONG)(addr) << PAGE_SHIFT)
public:
	CVadNodeMemRange(
		__in const CVadNodeMemRange& origin
		)//copy constructor
	{
		*this = origin;
	}

	CVadNodeMemRange() : CMemoryRange() {}

	CVadNodeMemRange(
		__in const VAD_SHORT* vadNode
		);

	//nt!MmProtectToValue
	__forceinline
	MMVAD_FLAGS GetFlags()
	{
		return *reinterpret_cast<MMVAD_FLAGS*>(&m_flags);
	}

	__forceinline
	__checkReturn
	bool IsExecuteable()
	{
		return !!(MmProtectToValue[GetFlags().Protection] & PAGE_EXE_MASK);
	}

	__forceinline
	__checkReturn 
	bool IsWriteable()
	{
		return !!(MmProtectToValue[GetFlags().Protection] & PAGE_WR_MASK);
	}

	__forceinline
	__checkReturn 
	bool IsWriteCopy()
	{
		return !!(MmProtectToValue[GetFlags().Protection] & PAGE_WR_COPY);
	}
};

//------------------------------------------------------
// ****************** VAD AVL SCANNER ******************
//------------------------------------------------------

class CVadScanner
{
public:
	CVadScanner(
		__in PETHREAD ethread
		);

	CVadScanner();

	void Init(
		__in PETHREAD ethread
		);

	__checkReturn 
	bool ScanAddressSpace();

	__checkReturn
	bool FindVadMemoryRange( 
		__in const void* addr, 
		__inout CVadNodeMemRange* vadMemRange
		);
	
	__checkReturn
	bool GetNextVadMemoryRange( 
		__in const void* addr, 
		__inout CVadNodeMemRange* vadMemRange
		);

	bool CVadScanner::SetVadMemoryRangeFlags( 
		__in const void* addr, 
		__in MMVAD_FLAGS flags
		);

	__checkReturn
	void SetUnwriteable(
		__in const void* addr,
		__in size_t size
		);

protected:
	PETHREAD m_thread;
	PEPROCESS m_process;
};

//------------------------------------------------------------------
// ****************** VAD_ROOT ADDRESS SPACE LOCK ******************
//------------------------------------------------------------------ 

class CVADScanLock
{
public:
	CVADScanLock(
		__in PEPROCESS process
		);
	~CVADScanLock();
	__checkReturn bool IsLocked();

protected:
	bool m_locked;

	CAutoProcessAttach m_attach;
	//CDisableKernelApc m_kernelapcDisabled;
	CAutoLock<CExclusiveLock> m_addressSpaceLock;
	CExclusiveLock m_workingSetLock;
};

//-----------------------------------------------------
// ****************** VAD AVL WALKER ******************
//-----------------------------------------------------

class CVadWalker : public CBinTreeWalker<VAD_SHORT>
{
public:
	CVadWalker(
		__in PEPROCESS process
		);

	__forceinline
	size_t GetSize()
	{
		return m_avlInfo->NumberGenericTableElements;
	}

private:
	const AVL_INFO* m_avlInfo;
};

#endif //__VADWALKER_H__
