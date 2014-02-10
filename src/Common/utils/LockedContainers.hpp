/**
 * @file LockedTree.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __LOCKEDTREE_H__
#define __LOCKEDTREE_H__

#include "../base/Common.h"
#include "../Kernel/Lock.hpp"
#include "AVL.hpp"

template<class TYPE, class TCLOCK, class TROLOCK, class TRWLOCK>
class CLockedAVLLockSpec
{
protected:
	typedef CAutoLock<TCLOCK, TROLOCK> read_only_lock;
	typedef CAutoLock<TCLOCK, TRWLOCK> read_write_lock;
#define RSRC_LOCK_RO read_only_lock lock(m_lock);
#define RSRC_LOCK_RW read_write_lock lock(m_lock);

public:
	__checkReturn
	bool Find(
		__in const TYPE& key, 
		__inout TYPE** out
		)
	{
		RSRC_LOCK_RO
		return m_avl.Find(&key, out);
	}

	bool Find(
	__in const TYPE& key
		)
	{
		RSRC_LOCK_RO
		return m_avl.Find(&key);
	}

	__checkReturn
	bool Push(
		__in const TYPE& element
		)
	{
		RSRC_LOCK_RW
		return m_avl.Insert(&element);
	}

	bool Pop(
		__in const TYPE& element
		)
	{
		RSRC_LOCK_RW
		while (m_avl.Remove(&element));
		return !m_avl.Find(&element);
	}

	__checkReturn
	bool GetNext(
		__in const TYPE& element,
		__inout TYPE** out
		)
	{
		RSRC_LOCK_RO
		return m_avl.GetNext(&element, out);
	}

	__checkReturn
	size_t GetSize()
	{
		RSRC_LOCK_RO
		return m_avl.GetSize();
	}

protected:
	CAVL<TYPE> m_avl;
	TCLOCK m_lock;
};

template<class TYPE>
class CLockedAVL :
	public CLockedAVLLockSpec<TYPE, CRsrcFastLock, CSharedLockWorker, CExclusiveLockWorker>
{
};

template<class TYPE>
class CLockedAVLAtDPC :
	public CLockedAVLLockSpec<TYPE, CSpinLock, CSpinLockWorker, CSpinLockWorker>
{
};

#endif //__LOCKEDTREE_H__
