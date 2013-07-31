/**
 * @file Singleton.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __SINGLETON_H__
#define __SINGLETON_H__

template<class TYPE>
class CSingleton
{
	CSingleton(const CSingleton&);// = delete;
	void operator=(CSingleton const&);// = delete;
	static TYPE* m_instancePtr;
public:
	static
	TYPE& GetInstance()
	{
		return *m_instancePtr;
	}

protected:
	CSingleton(
		__in TYPE& staticInstance
		)
	{
		m_instancePtr = &staticInstance;
	}
};

template<class TYPE>
TYPE* CSingleton<TYPE>::m_instancePtr = NULL;

#endif //__SINGLETON_H__
