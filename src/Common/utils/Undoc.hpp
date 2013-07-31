/**
 * @file Undoc.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __UNDOC_H__
#define __UNDOC_H__

#include "../base/Common.h"

#include "Undoc.h"
#include "Vad.h"

#define MEMBER(process, member) ((ULONG_PTR)(process) + (ULONG_PTR)(member))

//or use namespace ? http://winterdom.com/dev/cpp/nspaces

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
		__in size_t avlTableLinks,
		__in size_t avlTableInfo,
		__in ULONG_PTR avlSanity,
		__in size_t vadParent,
		__in size_t vadLeftChild,
		__in size_t vadRightChild,
		__in size_t vadStartingVpn,
		__in size_t vadEndingVpn,
		__in size_t vadFlags
		)
	{
		m_eprocessVadRoot = eprocessVadRoot;
		m_eprocessAddressCreationLock = eprocessAddressCreationLock;
		m_eprocessWorkingSetMutex = eprocessWorkingSetMutex;
		m_eprocessVMFlags = eprocessVMFlags;

		m_ethreadSameThreadApcFlags = ethreadSameThreadApcFlags;

		m_avlTableLinks = avlTableLinks;
		m_avlTableInfo = avlTableInfo;

		m_avlSanity = avlSanity;

		m_vadParent = vadParent;
		m_vadLeftChild = vadLeftChild;
		m_vadRightChild = vadRightChild;
		m_vadStartingVpn = vadStartingVpn;
		m_vadEndingVpn = vadEndingVpn;
		m_vadFlags = vadFlags;

		m_initialized = true;
	}

	__forceinline
	static 
	MM_AVL_TABLE* VadRoot(__in const PEPROCESS eprocess)
	{
		return reinterpret_cast<MM_AVL_TABLE*>(MEMBER(eprocess, m_eprocessVadRoot));
	}

	__forceinline
	static
	EX_PUSH_LOCK* AddressCreationLock(__in const PEPROCESS eprocess)
	{
		return reinterpret_cast<EX_PUSH_LOCK*>(MEMBER(eprocess, m_eprocessAddressCreationLock));
	}

	__forceinline
	static
	EX_PUSH_LOCK* WorkingSetMutex(__in const PEPROCESS eprocess)
	{ 
		return reinterpret_cast<EX_PUSH_LOCK*>(MEMBER(eprocess, m_eprocessWorkingSetMutex));
	}

	__forceinline
	static
	VM_FLAGS* Flags(__in const PEPROCESS eprocess)
	{
		return reinterpret_cast<VM_FLAGS*>(MEMBER(eprocess, m_eprocessVMFlags));
	}

	__forceinline
	static
	SAME_THREAD_APC_FLAGS* SameThreadApcFlags(__in const PETHREAD ethread)
	{
		return reinterpret_cast<SAME_THREAD_APC_FLAGS*>(MEMBER(ethread, m_ethreadSameThreadApcFlags));
	}

	__forceinline
	static
	AVL_INFO* AVLInfo(__in const MM_AVL_TABLE* avl)
	{
		return reinterpret_cast<AVL_INFO*>(MEMBER(avl, m_avlTableInfo));
	}

	__forceinline
	static
	ULONG_PTR AvlSanity()
	{
		return m_avlSanity;
	}

	__forceinline
	static
	MMVAD_SHORT* BalancedRoot(__in const MM_AVL_TABLE* vadRoot)
	{
		return reinterpret_cast<MMVAD_SHORT*>(MEMBER(vadRoot, m_avlTableLinks));
	}

	__forceinline
	static
	MMVAD_SHORT* Parent(__in const MMVAD_SHORT* vadNode)
	{
		return reinterpret_cast<MMVAD_SHORT*>(MEMBER(vadNode, m_vadParent));
	}

	__forceinline
	static
	MMVAD_SHORT* LeftChild(__in const MMVAD_SHORT* vadNode)
	{
		return reinterpret_cast<MMVAD_SHORT*>(MEMBER(vadNode, m_vadLeftChild));
	}

	__forceinline
	static
	MMVAD_SHORT* RightChild(__in const MMVAD_SHORT* vadNode)
	{
		return reinterpret_cast<MMVAD_SHORT*>(MEMBER(vadNode, m_vadRightChild));
	}

	__forceinline
	static
	ULONG StartingVpn(__in const MMVAD_SHORT* vadNode)
	{
		return *reinterpret_cast<ULONG*>(MEMBER(vadNode, m_vadStartingVpn));
	}

	__forceinline
	static
	ULONG EndingVpn(__in const MMVAD_SHORT* vadNode)
	{
		return *reinterpret_cast<ULONG*>(MEMBER(vadNode, m_vadEndingVpn));
	}

	__forceinline
	static
	ULONG* StartingVpnPtr(__in const MMVAD_SHORT* vadNode)
	{
		return reinterpret_cast<ULONG*>(MEMBER(vadNode, m_vadStartingVpn));
	}

	__forceinline
	static
	ULONG* EndingVpnPtr(__in const MMVAD_SHORT* vadNode)
	{
		return reinterpret_cast<ULONG*>(MEMBER(vadNode, m_vadEndingVpn));
	}

	__forceinline
	static
	MMVAD_FLAGS* Flags(__in const MMVAD_SHORT* vadNode)
	{
		return reinterpret_cast<MMVAD_FLAGS*>(MEMBER(vadNode, m_vadFlags));
	}

protected:
	static bool m_initialized;
	
private:
	static size_t m_eprocessVadRoot;
	static size_t m_eprocessAddressCreationLock;
	static size_t m_eprocessWorkingSetMutex;
	static size_t m_eprocessVMFlags;

	static size_t m_ethreadSameThreadApcFlags;
	
	static size_t m_avlTableLinks;
	static size_t m_avlTableInfo;

	static ULONG_PTR m_avlSanity;

	static size_t m_vadParent;
	static size_t m_vadLeftChild;
	static size_t m_vadRightChild;
	static size_t m_vadStartingVpn;
	static size_t m_vadEndingVpn;
	static size_t m_vadFlags;
};

__declspec(selectany) size_t CUndoc::m_vadFlags;

__declspec(selectany) size_t CUndoc::m_avlTableInfo;

__declspec(selectany) size_t CUndoc::m_eprocessVMFlags;

__declspec(selectany) size_t CUndoc::m_ethreadSameThreadApcFlags;

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
