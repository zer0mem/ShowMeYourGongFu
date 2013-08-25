/**
 * @file MemoryRange.h
 * @author created by: Peter Hlavaty
 */

#ifndef __CODERANGE_H__
#define __CODERANGE_H__

#include "Range.h"

class CMemoryRange : 
	public CRange<BYTE>
{
public :
	CMemoryRange() : m_flags(0) { };

	CMemoryRange(
		__in const BYTE* begin, 
		__in const BYTE* end
		) : CRange(begin, end),
			m_flags(0)
	{
	}

	CMemoryRange(
		__in const BYTE* begin, 
		__in size_t size, 
		__in ULONG_PTR flags = 0
		) : m_flags(flags)
	{
		m_begin = (ULONG_PTR)begin;
		SetSize(size);
	}

	~CMemoryRange() {};

	__checkReturn
	bool MatchFlags(
		__in ULONG_PTR flags
		) const 
	{
		return !!(m_flags & flags);
	}

	void SetFlags(
		__in ULONG_PTR flags
		)
	{
		m_flags = flags;
	}

	ULONG_PTR GetFlags()
	{
		return m_flags;
	}

protected :
	ULONG_PTR m_flags;
};

#endif //__CODERANGE_H__
