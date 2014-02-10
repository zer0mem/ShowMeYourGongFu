/**
 * @file AutoRef.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __AUTOREF_H__
#define __AUTOREF_H__

#include "Common.h"
#include "ComparableId.hpp"

template<class TYPE>
class CDeref :
	public COMPARABLE_ID<TYPE>
{
public:
	explicit CDeref(
		__in TYPE ref = NULL
		) : COMPARABLE_ID(ref)
	{
	}

	~CDeref()
	{
		if (Id)
			ObDereferenceObject(Id);
	}

	__checkReturn
	bool IsReferenced()
	{
		return !!Id;
	}

	TYPE GetRef()
	{
		return Id;
	}
};

template<class TYPE>
class CAutoObRef :
	public CDeref<TYPE>
{
public:
	CAutoObRef(
		__in TYPE ref2obj
		) : COMPARABLE_ID(ref2obj)
	{
		if (Id)
			ObReferenceObject(Id);
	}
};

#endif //__AUTOREF_H__
