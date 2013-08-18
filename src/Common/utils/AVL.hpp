/**
 * @file AVLTreeWalker.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __AVLTREEWALKER_H__
#define __AVLTREEWALKER_H__

#include "../base/Common.h"
#include "BinTreeWalker.hpp"

template <class TYPE>
struct AVL_NODE
{
	RTL_BALANCED_LINKS Links;
	TYPE Value;

	AVL_NODE(
		__in const TYPE* val
		)
	{
		Value = *val;
	}

	friend
	__forceinline
	bool operator>(
		__in const AVL_NODE& left, 
		__in const AVL_NODE& right
		)
	{
		return (left.Value > right.Value);
	}

	friend
	__forceinline
	bool operator==(
		__in const AVL_NODE& left, 
		__in const AVL_NODE& right
		)
	{
		return (left.Value == right.Value);
	}
};

template<class TYPE>
class CAVL : public CBinTreeWalker< AVL_NODE<TYPE> >
{
	void operator=(const CAVL&);
public:
	CAVL() :
		CBinTreeWalker(
			(const AVL_NODE<TYPE>**)reinterpret_cast<AVL_NODE<TYPE>**>(&m_avl.BalancedRoot.RightChild),
			offsetof(RTL_BALANCED_LINKS, Parent),
			offsetof(RTL_BALANCED_LINKS, LeftChild),
			offsetof(RTL_BALANCED_LINKS, RightChild)
			)
	{
		RtlInitializeGenericTableAvl(&m_avl, CompareRoutine, AllocationRoutine, FreeRoutine, NULL);
	}

	~CAVL()
	{
		const AVL_NODE<TYPE>* element;
		while (GetLowerBound(GetRoot(), &element))
			Remove(&element->Value);
	}

	__forceinline
	size_t GetSize()
	{
		return RtlNumberGenericTableElementsAvl(&m_avl);
	}

	__forceinline
	bool Insert(
		__in const TYPE* val
		)
	{
		BOOLEAN sucess;
		(void)RtlInsertElementGenericTableAvl(&m_avl, (TYPE*)val, sizeof(*val), &sucess);
		return !!sucess;
	}
	
	__forceinline
	bool Remove(
		__in const TYPE* val
		)
	{
		TYPE* obj;
		if (Find(val, &obj))
		{
			obj->~TYPE();
		
			return !!RtlDeleteElementGenericTableAvl(&m_avl, (TYPE*)val);
		}
		return false;
	}
	
	__checkReturn
	bool GetNext(
		__in const TYPE* key,
		__inout TYPE** val
		)
	{
		if (!GetSize())
			return false;

		AVL_NODE<TYPE>* found_or_parent;
		if (CBinTreeWalker::Find(CONTAINING_RECORD(key, AVL_NODE<TYPE>, Value), &found_or_parent))
		{
			if (CBinTreeWalker::GetNext((const AVL_NODE<TYPE>**)&found_or_parent))
			{
				//shared ptr ...
				*val = &found_or_parent->Value;
				return true;
			}
		}
		return false;
	}

	__forceinline
	__checkReturn
	bool Find(
		__in const TYPE* key,
		__inout TYPE** val
		)
	{
		if (!GetSize())
			return false;
		
		AVL_NODE<TYPE>* found;
		bool contains = CBinTreeWalker::Find(CONTAINING_RECORD(key, AVL_NODE<TYPE>, Value), &found);

		//shared ptr ...
		*val = &(found->Value);

		return contains;
	}

	__forceinline
	__checkReturn
	bool Find(
		__in const TYPE* key
		)
	{
		if (!GetSize())
			return false;

		AVL_NODE<TYPE>* found;
		return CBinTreeWalker::Find(CONTAINING_RECORD(key, AVL_NODE<TYPE>, Value), &found);
	}

protected:
	static
	RTL_GENERIC_COMPARE_RESULTS
	CompareRoutine(
		__in struct _RTL_AVL_TABLE* table,
		__in void* firstStruct,
		__in void* secondStruct
		)
	{
		if (*reinterpret_cast<TYPE*>(firstStruct) > *reinterpret_cast<TYPE*>(secondStruct))
			return GenericGreaterThan;

		if (*reinterpret_cast<TYPE*>(firstStruct) == *reinterpret_cast<TYPE*>(secondStruct))
			return GenericEqual;

		return GenericLessThan;
	}

//implement own virtual memory mngr
	static
	void*
	AllocationRoutine(
		__in struct _RTL_AVL_TABLE* table,
		__in CLONG byteSize
		)
	{
		return malloc(byteSize);
	}

	static
	void
	FreeRoutine(
		__in struct _RTL_AVL_TABLE* table,
		__in void* buffer
		)
	{
		free(buffer);
	}

protected:
	RTL_AVL_TABLE m_avl;
};

#endif //__AVLTREEWALKER_H__

#if 0

/*
//ntddk.h
//http://doxygen.reactos.org/d5/d86/avltable_8c_source.html
RtlGetElementGenericTableAvl //get by index
RtlLookupElementGenericTableFullAvl //get by key
RtlEnumerateGenericTableLikeADirectory //enum
RtlIsGenericTableEmpty //is empty
RtlNumberGenericTableElements  //size
RtlLookupFirstMatchingElementGenericTableAvl  //get lower (key)
RtlLookupElementGenericTableFullAvl  // contains
*/

	__forceinline
		__checkReturn
		TYPE* GetLowerBound(
		__in_opt TYPE* root = NULL
		)
	{
		return (TYPE*)RtlGetElementGenericTableAvl(m_avl, 0);
	}

	__forceinline
		__checkReturn
		TYPE* GetUpperBound(
		__in_opt TYPE* root = NULL
		)
	{
		//if tree is empty : It returns NULL if the given I is too large or if the generic AVL table currently has no elements.
		return (TYPE*)RtlGetElementGenericTableAvl(m_avl, RtlNumberGenericTableElementsAvl(m_avl) - 1);
	}

	__forceinline
		__checkReturn
		bool Find(
		__in TYPE* key,
		__out TYPE** val
		)
	{
		TYPE* _val;
		RTL_BALANCED_LINKS* node_or_parent;
		if (Find(key, &_val, &node_or_parent))
		{
			*val = _val;
			return true;
		}		 
		return false;
	}

	__forceinline
		__checkReturn
		bool GetFirst(
		__out TYPE** val
		)
	{		
		TYPE* _val = GetLowerBound();
		if (_val)
		{
			RTL_BALANCED_LINKS* node_or_parent = NULL;
			(void)Find(_val, val, &node_or_parent);

			m_iterator = node_or_parent;

			return true;
		}
		return false;
	}

	__forceinline
		__checkReturn
		bool Seek(
		__in TYPE* key,
		__out_opt TYPE** val = NULL
		)
	{
		TYPE* _val;
		RTL_BALANCED_LINKS* node_or_parent;
		if (Find(key, &_val, &node_or_parent))
		{
			if (val)
				*val = _val;

			m_iterator = node_or_parent;
			return true;
		}		 
		return false;
	}

	__forceinline
		__checkReturn
		bool GetNext(
		__out TYPE** val
		)
	{
		if (m_iterator)
		{
			TYPE* _val = (TYPE*)RtlEnumerateGenericTableLikeADirectory(m_avl, NULL, NULL, TRUE, NULL, &m_deleteCount, m_iterator);
			if (_val)
			{
				*val = _val;
				return true;
			}
		}
		return false;
	}

protected:
	__forceinline
		__checkReturn
		bool Find(
		__in TYPE* key,
		__out TYPE** val,
		__out RTL_BALANCED_LINKS** nodeOrParent
		)
	{
		TABLE_SEARCH_RESULT lookup;
		*val = (TYPE*)RtlLookupElementGenericTableFullAvl(&m_avl, key, (void**)nodeOrParent, &lookup);
		return (TableFoundNode == lookup);
	}

protected:
	ULONG m_deleteCount;
	RTL_BALANCED_LINKS* m_iterator;

#endif
