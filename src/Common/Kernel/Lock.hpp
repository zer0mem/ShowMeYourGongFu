/**
 * @file Lock.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __LOCK_H__
#define __LOCK_H__

#include "../base/Common.h"

#include "Fltkernel.h"

//-----------------------------------------------------------
// ****************** GENERIC LOCK CLASSES ******************
//-----------------------------------------------------------

template<class LOCK>
class CAutoLock
{
public:
	explicit CAutoLock(
		__inout void* lock
		) : m_lock(lock)
	{
		m_lock.Lock();
	}

	~CAutoLock()
	{
		m_lock.Unlock();
	}

private:
	CAutoLock(const CAutoLock&);
	void operator=(const CAutoLock&);

protected:
	LOCK m_lock;
};

template<class TLOCK>
class CLock
{
protected:
	explicit CLock(
		__inout void* lock
		) : m_tLock(reinterpret_cast<TLOCK*>(lock)) {}

private:
	CLock(const CLock&);
	void operator=(const CLock&);

protected:
	TLOCK* m_tLock;
};

template<class TLOCK>
class CInitLock
{
protected:
	explicit CInitLock() {}

public:
	TLOCK* operator&()
	{
		return &m_tInitLock;
	}

private:
	CInitLock(const CInitLock&);
	void operator=(const CInitLock&);

protected:
	TLOCK m_tInitLock;
};


//----------------------------------------------------
// ****************** GUARDED MUTEX ******************
//----------------------------------------------------

class CGuardedMutex : protected CLock<KGUARDED_MUTEX>
{
public:
	CGuardedMutex(
		__inout void* lock
		) : CLock(reinterpret_cast<KGUARDED_MUTEX*>(lock)) {}
	
	_IRQL_requires_max_(APC_LEVEL)
	void Lock()
	{
		KeAcquireGuardedMutex(m_tLock);
	}

	_IRQL_requires_max_(APC_LEVEL)
	void Unlock()
	{
		KeReleaseGuardedMutex(m_tLock);
	}

};

//after compiler optimalization looks much more prettier ;)
class CInitGuardedMutex : public CInitLock<KSPIN_LOCK>, public CGuardedMutex
{
public:
	CInitGuardedMutex() : CGuardedMutex(NULL)
	{
		KeInitializeSpinLock(&m_tInitLock);
	}

	CInitGuardedMutex(__inout void* lock) : CGuardedMutex(lock) {}
};


//-----------------------------------------------------
// ****************** EXCLUSIVE LOCK ******************
//-----------------------------------------------------

class CExclusiveLock : public CLock<EX_PUSH_LOCK>
{
public:
	CExclusiveLock(
		__inout void* lock
		) : CLock(reinterpret_cast<EX_PUSH_LOCK*>(lock)) {}

	_IRQL_requires_max_(APC_LEVEL)
	void Lock()
	{
		FltAcquirePushLockExclusive(m_tLock);
	}

	_IRQL_requires_max_(APC_LEVEL)
	void Unlock()
	{
		FltReleasePushLock(m_tLock);
	}
};

//after compiler optimalization looks much more prettier ;)
class CInitExclusiveLock : public CInitLock<KSPIN_LOCK>, public CExclusiveLock
{
public:
	CInitExclusiveLock() : CExclusiveLock(NULL)
	{
		KeInitializeSpinLock(&m_tInitLock);
	}

	CInitExclusiveLock(__inout void* lock) : CExclusiveLock(lock) {}
};


//------------------------------------------------
// ****************** SPIN LOCK ******************
//------------------------------------------------

class CSpinLock : public CLock<KSPIN_LOCK>
{
public:
	CSpinLock(
		__inout void* lock
		) : CLock(reinterpret_cast<KSPIN_LOCK*>(lock)) {}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	void Lock()
	{
		m_irql = KeAcquireSpinLockRaiseToDpc(m_tLock);
	}

	_IRQL_requires_max_(DISPATCH_LEVEL)
	void Unlock()
	{
		KeReleaseSpinLock(m_tLock, m_irql);
	}

protected:
	KIRQL m_irql;
};

//after compiler optimalization looks much more prettier ;)
class CInitSpinLock : public CInitLock<KSPIN_LOCK>, public CSpinLock
{
public:
	CInitSpinLock() : CSpinLock(NULL)
	{
		KeInitializeSpinLock(&m_tInitLock);
	}

	CInitSpinLock(__inout void* lock) : CSpinLock(lock) {}
};

#endif //__LOCK_H__
