/**
 * @file ComparableId.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __COMPARABLEID_H__
#define __COMPARABLEID_H__

template<class TYPE>
struct COMPARABLE_ID
{	
	COMPARABLE_ID(
		__in const TYPE& id
		)
	{
		Id = id;
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
	TYPE* Value;

	COMPARABLE_ID_PTR() : COMPARABLE_ID(NULL)
	{
		Value = NULL;
	}

	//implicit
	COMPARABLE_ID_PTR(
		__in const ID& id, 
		__in_opt TYPE* val = NULL
		) : COMPARABLE_ID(id)
	{
		Id = id;
		Value = val;
	}

	~COMPARABLE_ID_PTR()
	{
		delete Value;
		Value = NULL;
	}
};

#endif //__COMPARABLEID_H__
