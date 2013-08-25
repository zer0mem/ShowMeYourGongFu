/**
 * @file Thread.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __THREAD_H__
#define __THREAD_H__

#include "../base/Common.h"
#include "../base/ComparableId.hpp"
#include "IRQL.hpp"
#include "../utils/VADWalker.h"
#include "../utils/Undoc.hpp"

EXTERN_C NTKERNELAPI PVOID NTAPI PsGetThreadTeb( PETHREAD Thread );
EXTERN_C NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process( PEPROCESS Process );

class CEthread :
	public COMPARABLE_ID<PETHREAD>
{
public:
	explicit CEthread(
		__in HANDLE threadId
		) : COMPARABLE_ID(NULL),
			m_threadId(threadId)
	{
		m_stack.Set(NULL, NULL);
	}

	~CEthread()
	{
		if (Id)
			ObDereferenceObject(Id);
	}

	__checkReturn
	bool Initialize()
	{
		if (!m_stack.Begin())
		{
			if (!Id && NT_SUCCESS(PsLookupThreadByThreadId(m_threadId, &Id)))
			{
				m_vadScanner.Init(Id);

				CPassiveLvl irql;
				void* teb;
				if (teb = GetWow64Teb(Id))
					ResolveThreadLimits<NT_TIB32>(reinterpret_cast<NT_TIB32*>(teb));
				else if (teb = PsGetThreadTeb(Id))
					ResolveThreadLimits<NT_TIB>(reinterpret_cast<NT_TIB*>(teb));

				DbgPrint("\nstack boundaries : %p %p\n", m_stack.Begin(), m_stack.End());
				return true;
			}
		}
		return false;
	}

	HANDLE ThreadId()
	{
		return m_threadId;
	}

	CVadScanner& VadScanner()
	{
		return m_vadScanner;
	}

	PEPROCESS GetEProcess()
	{
		return PsGetThreadProcess(Id);
	}

	CRange<ULONG_PTR>& Stack()
	{
		return m_stack;
	}

private:
	template<class TYPE>
	__forceinline
	void ResolveThreadLimits(
		__in const TYPE* teb
		)
	{
		if (teb)
			m_stack.Set(reinterpret_cast<ULONG_PTR*>(*CUndoc::DeallocationStack<TYPE>(teb)), reinterpret_cast<ULONG_PTR*>(teb->StackBase));
		else
			m_stack.Set(NULL, NULL);
	}

	__checkReturn
	NT_TIB32* GetWow64Teb( 
		__in PETHREAD thread
		)
	{
		if(PsGetProcessWow64Process(IoThreadToProcess(thread)))
		{
			NT_TIB* teb = reinterpret_cast<NT_TIB*>(PsGetThreadTeb(thread));
			DbgPrint("\nTEB : %p\n", teb);
			if (teb)
			{
				NT_TIB32* teb32 = reinterpret_cast<NT_TIB32*>(teb->ExceptionList);
				if (teb32 && ((ULONG_PTR)teb32->Self == (ULONG_PTR)teb32))
					return teb32;
			}
		}
		return NULL;
	}

protected:
	HANDLE m_threadId;
	CRange<ULONG_PTR> m_stack;
	CVadScanner m_vadScanner;
};

#endif //__THREAD_H__
