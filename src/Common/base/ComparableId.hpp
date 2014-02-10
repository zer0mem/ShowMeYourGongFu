/**
 * @file ComparableId.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __COMPARABLEID_H__
#define __COMPARABLEID_H__

template<class TYPE>
struct COMPARABLE_ID
{	
	explicit COMPARABLE_ID(
		__in const TYPE& id
		)
	{
		Id = id;
	}

	~COMPARABLE_ID()
	{
		Id = 0;
	}

	friend
	__forceinline
	bool operator>(
		__in const COMPARABLE_ID &left, 
		__in const COMPARABLE_ID &right
		)
	{		
		return (left.Id > right.Id);
	}

	friend
	__forceinline
	bool operator==(
		__in const COMPARABLE_ID &left, 
		__in const COMPARABLE_ID &right
		)
	{
		return (left.Id == right.Id);
	}

protected:
	TYPE Id;
};

template<class ID, class TYPE>
struct COMPARABLE_ID_PTR :
	public COMPARABLE_ID<ID>
{
	TYPE* Obj;

	//implicit
	COMPARABLE_ID_PTR(
		__in const ID& id = NULL, 
		__in_opt TYPE* obj = NULL
		) : COMPARABLE_ID(id)
	{
		Obj = obj;
	}

	~COMPARABLE_ID_PTR()
	{
		delete Obj;
		Obj = NULL;
	}
};

#endif //__COMPARABLEID_H__
