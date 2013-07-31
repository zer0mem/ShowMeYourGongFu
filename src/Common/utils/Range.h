/**
 * @file Range.h
 * @author created by: Peter Hlavaty
 */

#ifndef __RANGE_H__
#define __RANGE_H__

#include "../base/Common.h"

template<class TYPE>
struct CRange
{
	CRange() : m_begin(0), m_end(0) { };
	~CRange() { };

	//implicit
	CRange(
		__in const TYPE* begin
		) : m_begin((ULONG_PTR)begin), m_end((ULONG_PTR)begin) { };

	//implicit
	CRange(
		__in const TYPE* begin, 
		__in const TYPE* end
		) : m_begin((ULONG_PTR)begin), m_end((ULONG_PTR)end) { };

public:
	bool IsInRange(
		__in const TYPE* address
		) const
	{
		return ((ULONG_PTR)address >= m_begin && (ULONG_PTR)address <= m_end);
	};

	void Set(
		__in const TYPE* begin, 
		__in const TYPE* end
		)
	{
		m_begin = (ULONG_PTR)begin; 
		m_end = max((ULONG_PTR)begin, (ULONG_PTR)end);
	};

	void SetSize(
		__in size_t size
		)
	{ 
		m_end = max(m_begin + size - 1, m_end); 
	};

	void Reset(
		__in const TYPE* begin
		)
	{
		Set(begin, begin);
	};

	TYPE* Begin() const
	{
		return reinterpret_cast<TYPE*>(m_begin);
	};

	TYPE* End() const
	{
		return reinterpret_cast<TYPE*>(m_end);
	};

protected:
	ULONG_PTR m_begin;
	ULONG_PTR m_end;

	static 
	inline 
	bool IsOverlaping(
		__in const CRange &left, 
		__in const CRange &right
		)
	{
		return !(left.Begin() > right.End() || right.Begin() > left.End());
	}

	friend
	bool operator>(
		__in const CRange &left, 
		__in const CRange &right
		)
	{
		if (IsOverlaping(left, right))
			return false;
		
		return (left.m_end > right.m_end);
	}

	friend
	bool operator==(
		__in const CRange &left, 
		__in const CRange &right
		)
	{
		return IsOverlaping(left, right);
	}
};

#endif //__RANGE_H__
