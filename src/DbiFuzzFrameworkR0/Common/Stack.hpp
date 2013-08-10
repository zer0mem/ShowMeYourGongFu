/**
 * @file Stack.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __STACK_H__
#define __STACK_H__

//missing locks ;) - crappy container, just for quick dbgprints, should to be removed ...
//but not important to much :P just helper ... 
template<class TYPE>
class CStack
{
public:
	CStack() : 
		m_top(0), 
		m_bottom(0)
	{
	}

	__checkReturn
	bool IsEmpty()
	{
		return (m_bottom == m_top);
	}

	bool Push(
		__in const TYPE& val
		)
	{
		ASSERT(m_bottom <= m_top);

		if (m_bottom <= m_top)
		{
			size_t ind = InterlockedExchangeAdd64((LONG64*)&m_top, 1);
			m_entries[ind] = val;
			return true;
		}
		return false;
	}

	TYPE Pop()
	{
		size_t ind = InterlockedExchangeAdd64((LONG64*)&m_bottom, 1);
		return m_entries[ind];
	}

protected:
	size_t m_top;
	size_t m_bottom;
	TYPE m_entries[0x100];
};

#endif //__STACK_H__
