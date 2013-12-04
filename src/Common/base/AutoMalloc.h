/**
 * @file AutoMalloc.h
 * @author created by: Peter Hlavaty
*/

#ifndef __AUTOMALLOC_H__
#define __AUTOMALLOC_H__

#include "../utils/Range.h"

template<class TYPE>
class CAutoTypeMalloc : public CRange<TYPE>
{
public:
	CAutoTypeMalloc(
		__in size_t count = 1
		) : 
		m_mem((TYPE*)malloc(sizeof(TYPE) * count)),
		m_count(m_mem ? count : 0),
		CRange(m_mem, m_count * sizeof(TYPE))			
	{
	}

	~CAutoTypeMalloc()
	{
		free(m_mem);
	}

	__checkReturn 
	bool Resize(
		__in size_t size
		)
	{
		TYPE* mem = (TYPE*)realloc(m_mem, sizeof(TYPE) * size);
		if (!mem)
			return false;

		m_mem = mem;
		m_count = size;
		return true;
	}

	__checkReturn 
	TYPE* GetMemory() const
	{
		return m_mem;
	}

	__checkReturn 
	size_t GetSize() const
	{
		return m_count * sizeof(TYPE);
	}

	__checkReturn 
	size_t GetCount() const
	{
		return m_count;
	}

	TYPE& operator[](size_t i) const
	{
		return m_mem[i];
	}

private:
	TYPE* m_mem;
	size_t m_count;
};

#endif //__AUTOMALLOC_H__
