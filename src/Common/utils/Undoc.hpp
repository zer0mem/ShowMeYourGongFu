/**
 * @file Undoc.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __UNDOC_H__
#define __UNDOC_H__

#include "../base/Common.h"

#include "Undoc.h"
#include "Vad.h"

//or use namespace ? http://winterdom.com/dev/cpp/nspaces

DECLARE_GLOBAL_CONST_UNICODE_STRING(KE_REMOVE_QUEUE_APC, L"KeRemoveQueueApc");

class CUndoc
{
//private, prohibity ctor, static singleton! .. smth like namespace ..
	CUndoc();
public:	
	~CUndoc();

	__checkReturn 
	static bool IsInitialized()
	{
		return m_initialized;
	}

	static void Init(
		__in size_t eprocessVadRoot,
		__in size_t eprocessAddressCreationLock,
		__in size_t eprocessWorkingSetMutex,
		__in size_t eprocessVMFlags,
		__in size_t ethreadSameThreadApcFlags,
		__in size_t ethreadTrapFrame,
		__in size_t avlTableLinks,
		__in size_t avlTableInfo,
		__in ULONG_PTR avlSanity,
		__in size_t vadParent,
		__in size_t vadLeftChild,
		__in size_t vadRightChild,
		__in size_t vadStartingVpn,
		__in size_t vadEndingVpn,
		__in size_t vadFlags,
		__in size_t deallocationStack32,
		__in size_t deallocationStack64,
		__in size_t pKTIMER,
		__in size_t patchGuardContextStackTopDelta,
		__in ULONG_PTR patchGuardMagic
		)
	{
		m_eprocessVadRoot = eprocessVadRoot;
		m_eprocessAddressCreationLock = eprocessAddressCreationLock;
		m_eprocessWorkingSetMutex = eprocessWorkingSetMutex;
		m_eprocessVMFlags = eprocessVMFlags;

		m_ethreadSameThreadApcFlags = ethreadSameThreadApcFlags;
		m_ethreadTrapFrame = ethreadTrapFrame;

		m_avlTableLinks = avlTableLinks;
		m_avlTableInfo = avlTableInfo;

		m_avlSanity = avlSanity;

		m_vadParent = vadParent;
		m_vadLeftChild = vadLeftChild;
		m_vadRightChild = vadRightChild;
		m_vadStartingVpn = vadStartingVpn;
		m_vadEndingVpn = vadEndingVpn;
		m_vadFlags = vadFlags;
		
		m_deallocationStack32 = deallocationStack32;
		m_deallocationStack64 = deallocationStack64;

		m_pKTIMER = pKTIMER;
		m_patchGuardContextStackTopDelta = patchGuardContextStackTopDelta;
		m_patchGuardMagic = patchGuardMagic;

		m_keRemoveQueueApc = static_cast<KeRemoveQueueApc>(MmGetSystemRoutineAddress(const_cast<UNICODE_STRING*>(&KE_REMOVE_QUEUE_APC)));
		DbgPrint("m_keRemoveQueueApc %ws %p", KE_REMOVE_QUEUE_APC.Buffer, m_keRemoveQueueApc);
		KeBreak();

		m_initialized = true;
	}

	__forceinline
	static 
	MM_AVL_TABLE* VadRoot(
		__in const PEPROCESS eprocess
		)
	{
		return MEMBER(MM_AVL_TABLE, eprocess, m_eprocessVadRoot);
	}

	__forceinline
	static
	EX_PUSH_LOCK* AddressCreationLock(
		__in const PEPROCESS eprocess
		)
	{
		return MEMBER(EX_PUSH_LOCK, eprocess, m_eprocessAddressCreationLock);
	}

	__forceinline
	static
	EX_PUSH_LOCK* WorkingSetMutex(
		__in const PEPROCESS eprocess
		)
	{ 
		return MEMBER(EX_PUSH_LOCK, eprocess, m_eprocessWorkingSetMutex);
	}

	__forceinline
	static
	VM_FLAGS* Flags(
		__in const PEPROCESS eprocess
		)
	{
		return MEMBER(VM_FLAGS, eprocess, m_eprocessVMFlags);
	}

	__forceinline
	static
	SAME_THREAD_APC_FLAGS* SameThreadApcFlags(
		__in const PETHREAD ethread
		)
	{
		return MEMBER(SAME_THREAD_APC_FLAGS, ethread, m_ethreadSameThreadApcFlags);
	}
	

	__forceinline
	__checkReturn
	static KTRAP_FRAME* EthreadTrapFrame(
		__in const PETHREAD ethread
		)
	{
		KTRAP_FRAME** p_ktrap_frame = MEMBER(KTRAP_FRAME*, ethread, m_ethreadTrapFrame);
		if (p_ktrap_frame)
			return *p_ktrap_frame;
		return NULL;
	}

	__forceinline
	static
	AVL_INFO* AVLInfo(
		__in const MM_AVL_TABLE* avl
		)
	{
		return MEMBER(AVL_INFO, avl, m_avlTableInfo);
	}

	__forceinline
	static
	ULONG_PTR AvlSanity()
	{
		return m_avlSanity;
	}

	__forceinline
	static
	MMVAD_SHORT* BalancedRoot(
		__in const MM_AVL_TABLE* vadRoot
		)
	{
		return MEMBER(MMVAD_SHORT, vadRoot, m_avlTableLinks);
	}

	__forceinline
	static
	MMVAD_SHORT* Parent(
		__in const MMVAD_SHORT* vadNode
		)
	{
		return MEMBER(MMVAD_SHORT, vadNode, m_vadParent);
	}

	__forceinline
	static
	MMVAD_SHORT* LeftChild(
		__in const MMVAD_SHORT* vadNode
		)
	{
		return MEMBER(MMVAD_SHORT, vadNode, m_vadLeftChild);
	}

	__forceinline
	static
	MMVAD_SHORT* RightChild(
		__in const MMVAD_SHORT* vadNode
		)
	{
		return MEMBER(MMVAD_SHORT, vadNode, m_vadRightChild);
	}

	__forceinline
	static
	ULONG* StartingVpn(
		__in const MMVAD_SHORT* vadNode
		)
	{
		return MEMBER(ULONG, vadNode, m_vadStartingVpn);
	}

	__forceinline
	static
	ULONG* EndingVpn(
		__in const MMVAD_SHORT* vadNode
		)
	{
		return MEMBER(ULONG, vadNode, m_vadEndingVpn);
	}

	__forceinline
	static
	MMVAD_FLAGS* Flags(
		__in const MMVAD_SHORT* vadNode
		)
	{
		return MEMBER(MMVAD_FLAGS, vadNode, m_vadFlags);
	}

	//template and sizeof ==> compiler optimalize it!
	template<class TYPE>
	__forceinline
	static
	ULONG_PTR* DeallocationStack(
		__in const TYPE* teb
		)
	{
		if (sizeof(TYPE) == sizeof(NT_TIB32))
			return reinterpret_cast<ULONG_PTR*>(reinterpret_cast<ULONG_PTR>(teb) + m_deallocationStack32);
		else
			return reinterpret_cast<ULONG_PTR*>(reinterpret_cast<ULONG_PTR>(teb) + m_deallocationStack64);
	}

	__forceinline
	static 
	KTIMER* PatchGuardGetPKTIMER( 
		__in ULONG_PTR contextAddr 
		) 
	{
		return *reinterpret_cast<KTIMER**>(contextAddr + m_pKTIMER);//0x330
	}

	__forceinline
	static 
	size_t PatchGuardContextStackTopDelta() 
	{
		return m_patchGuardContextStackTopDelta;//0x7D0
	}

	__forceinline
	static 
	bool IsPatchGuardContextOnRTDSC(
		__in const ULONG_PTR reg[REG_COUNT]
		) 
	{
		return (reg[RSI] == m_patchGuardMagic);//0x7010008004002001
	}

	__forceinline
	static KTRAP_FRAME* GetCurrentThreadTrapFrame()
	{
		return reinterpret_cast<KTRAP_FRAME*>(
			reinterpret_cast<ULONG_PTR>(IoGetInitialStack()) - 
			CUndoc::GetFxSaveAreaLength() - 
			CUndoc::GetKTrapFrameLength());
	}

	__checkReturn
	__forceinline
	static KeRemoveQueueApc KeRemoveQueueApcPtr()
	{
		return m_keRemoveQueueApc;
	}

private:
	__forceinline
	static size_t GetFxSaveAreaLength()
	{
#ifdef _WIN64
#define FX_SAVE_AREA_LENGTH 0
#else
#define FX_SAVE_AREA_LENGTH 0x210
#endif
		return FX_SAVE_AREA_LENGTH;
	}

	__forceinline
	static size_t GetKTrapFrameLength()
	{
//http://doxygen.reactos.org/d9/dbe/amd64_2asm_8h_abeb741506594b3a77367cbfea5f4799e.html
#define KTRAP_FRAME_ALIGN sizeof(void*)
		return ALIGN_UP_BY(sizeof(KTRAP_FRAME), KTRAP_FRAME_ALIGN);
	}

protected:
	static bool m_initialized;
	
private:
	static size_t m_eprocessVadRoot;
	static size_t m_eprocessAddressCreationLock;
	static size_t m_eprocessWorkingSetMutex;
	static size_t m_eprocessVMFlags;

	static size_t m_ethreadSameThreadApcFlags;
	static size_t m_ethreadTrapFrame;
	
	static size_t m_avlTableLinks;
	static size_t m_avlTableInfo;

	static ULONG_PTR m_avlSanity;

	static size_t m_vadParent;
	static size_t m_vadLeftChild;
	static size_t m_vadRightChild;
	static size_t m_vadStartingVpn;
	static size_t m_vadEndingVpn;
	static size_t m_vadFlags;

	static size_t m_deallocationStack32;
	static size_t m_deallocationStack64;

	static size_t m_pKTIMER;
	static size_t m_patchGuardContextStackTopDelta;
	static ULONG_PTR m_patchGuardMagic;

	static KeRemoveQueueApc m_keRemoveQueueApc;
};

__declspec(selectany) KeRemoveQueueApc CUndoc::m_keRemoveQueueApc;

__declspec(selectany) ULONG_PTR CUndoc::m_patchGuardMagic;

__declspec(selectany) size_t CUndoc::m_patchGuardContextStackTopDelta;

__declspec(selectany) size_t CUndoc::m_pKTIMER;

__declspec(selectany) size_t CUndoc::m_deallocationStack64;

__declspec(selectany) size_t CUndoc::m_deallocationStack32;

__declspec(selectany) size_t CUndoc::m_vadFlags;

__declspec(selectany) size_t CUndoc::m_avlTableInfo;

__declspec(selectany) size_t CUndoc::m_eprocessVMFlags;

__declspec(selectany) size_t CUndoc::m_ethreadSameThreadApcFlags;

__declspec(selectany) size_t CUndoc::m_ethreadTrapFrame;

__declspec(selectany) size_t CUndoc::m_vadEndingVpn;

__declspec(selectany) size_t CUndoc::m_vadStartingVpn;

__declspec(selectany) size_t CUndoc::m_eprocessWorkingSetMutex;

__declspec(selectany) size_t CUndoc::m_eprocessAddressCreationLock;

__declspec(selectany) size_t CUndoc::m_vadRightChild;

__declspec(selectany) size_t CUndoc::m_vadLeftChild;

__declspec(selectany) size_t CUndoc::m_vadParent;

__declspec(selectany) ULONG_PTR CUndoc::m_avlSanity;

__declspec(selectany) size_t CUndoc::m_avlTableLinks;

__declspec(selectany) size_t CUndoc::m_eprocessVadRoot;

__declspec(selectany) bool CUndoc::m_initialized = false;

#endif //__UNDOC_H__
