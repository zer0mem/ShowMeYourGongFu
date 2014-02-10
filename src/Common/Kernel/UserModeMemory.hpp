/**
 * @file UserModeMemory.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __USERMODEMEMORY_H__
#define __USERMODEMEMORY_H__

#include "../base/Common.h"

template<class TYPE>
class CUserModeMem
{
public:
	_IRQL_requires_max_(PASSIVE_LEVEL)
	CUserModeMem(
		__in_ecount(base) size_t count,
		__in ULONG protection,
		__in HANDLE process,
		__in ULONG allocationType = MEM_COMMIT,
		__in ULONG_PTR zeroBits = 0,
		__in void* base = NULL
		)
	{
		m_size = count * sizeof(TYPE);
		if (NT_SUCCESS(ZwAllocateVirtualMemory(
			process, 
			&base, 
			zeroBits, 
			&static_cast<SIZE_T>(m_size), 
			allocationType, 
			protection)))
		{
			m_proc = process;
			m_mem = reinterpret_cast<TYPE*>(base);
		}
		else
		{
			m_mem = NULL;
			m_size = NULL;
		}
	}

	_IRQL_requires_max_(PASSIVE_LEVEL)
	~CUserModeMem()
	{
		if (m_mem)
			ZwFreeVirtualMemory(m_proc, reinterpret_cast<void**>(&m_mem), &static_cast<SIZE_T>(m_size), MEM_RELEASE);
	}

	size_t GetCount()
	{
		return m_size / sizeof(TYPE);
	}

	__checkReturn
	TYPE* GetMemory()
	{
		return m_mem;
	}

	TYPE& operator[](
		__in size_t i
		) const
	{
		return m_mem[i];
	}

protected:
	HANDLE m_proc;
	size_t m_size;
	TYPE* m_mem;
};

#endif //__USERMODEMEMORY_H__
