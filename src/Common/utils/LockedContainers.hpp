/**
 * @file LockedTree.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __LOCKEDTREE_H__
#define __LOCKEDTREE_H__

#include "../base/Common.h"
#include "../Kernel/Lock.hpp"
#include "AVL.hpp"

template<class TYPE>
class CLockedAVL
{
#define SPIN_LOCK CAutoLock<CInitSpinLock> lock(&m_lock);
public:
	__checkReturn
	bool Find(
		__in const TYPE& key, 
		__inout TYPE** out
		)
	{
		SPIN_LOCK
		return m_avl.Find(&key, out);
	}

	bool Find(
	__in const TYPE& key
		)
	{
		SPIN_LOCK
		return m_avl.Find(&key);
	}

	__checkReturn
	bool Push(
		__in const TYPE& element
		)
	{
		SPIN_LOCK
		return m_avl.Insert(&element);
	}

	bool Pop(
		__in const TYPE& element
		)
	{
		SPIN_LOCK
		while (true)
		{
			if (!m_avl.Remove(&element))
				return false;
		}
		return true;
	}

	__checkReturn
	bool GetNext(
		__in const TYPE& element,
		__inout TYPE** out
		)
	{
		SPIN_LOCK
		return m_avl.GetNext(&element, out);
	}

	__checkReturn
	size_t GetSize()
	{
		SPIN_LOCK
		return m_avl.GetSize();
	}

protected:
	CAVL<TYPE> m_avl;
	CInitSpinLock m_lock;
};

#endif //__LOCKEDTREE_H__
