/**
 * @file BinTreeWalker.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __BINTREEWALKER_H__
#define __BINTREEWALKER_H__

#include "../base/Common.h"

template<class TYPE>
class CBinTreeWalker
{
	void operator=(const CBinTreeWalker&);
public:
	CBinTreeWalker(
		__in const TYPE** root, 
		__in size_t parentOffset,
		__in size_t leftChildOffset,
		__in size_t rightChildOffset,
		__in size_t sanityMask = ~0x0
		) : m_root(root), 
			m_parentOffset(parentOffset),
			m_leftChildOffset(leftChildOffset),
			m_rightChildOffset(rightChildOffset),
			m_sanityMask(sanityMask)
	{
		ASSERT(m_root && MmIsAddressValid((void*)m_root) && sanityMask);
	}

	~CBinTreeWalker()
	{
	}

	__forceinline
	__checkReturn 
	const TYPE* GetRoot()
	{
		return *m_root;
	}

	__checkReturn
	const TYPE* GetLowerBound(
		__in_opt const TYPE* root = NULL
		)
	{
		if (!root)
			root = GetRoot();

		for (const TYPE* node = root; node; node = LeftChild(node))
			root = node;

		return root;
	}

	__checkReturn
	const TYPE* GetUpperBound(
		__in_opt const TYPE* root = NULL
		)
	{
		if (!root)
			root = GetRoot();

		for (const TYPE* node = root; node; node = RightChild(node))
			root = node;

		return root;
	}

	//m$ implementation ==> MiGetNextNode
	__checkReturn
	bool GetNext(
		__inout const TYPE** node
		)
	{
		if (node && *node)
		{
			const TYPE* next;
			if (next = RightChild(*node))
				return GetLowerBound(next, node);

			next = Parent(*node);
			for (const void* child = *node; next && next != child; next = Parent(child))
			{
				if (RightChild(next) != child)
				{
					*node = next;
					return true;
				}
				child = next;
			}
		}
		return false;
	}

	//m$ implementation ==> MiGetPreviousNode
	__checkReturn
	bool GetPrev(
		__inout const TYPE** node
	)
	{
		if (node && *node)
		{
			const TYPE* next;
			if (next = LeftChild(*node))
				return GetUpperBound(next, node);

			next = Parent(*node);
			for (const void* child = *node; next && next != child; next = Parent(child))
			{
				if (LeftChild(next) != child)
				{
					*node = next;
					return true;
				}
				child = next;
			}
		}
		return false;
	}

	//m$ implementation ==> FindNodeOrParent, this is whithout parent :P
	__checkReturn
	bool Find(
		__in const TYPE* key,
		__inout TYPE** val
		)
	{
		const TYPE* root = GetRoot();
		if (root)
		{
			for (const TYPE* parent = key; root != parent; )
			{
				if (!root)
				{
					root = parent;
					break;
				}

				parent = root;

				if (*key > *root)
					root = RightChild(root);
				else if (*key == *root)
					break;
				else
					root = LeftChild(root);
			}
			
			*val = const_cast<TYPE*>(root);

			return (*key == *root);
		}		
		return false;
	}

protected:
	__forceinline
	__checkReturn	
	bool GetLowerBound(__in_opt const TYPE* root, __inout const TYPE** node)
	{
		const TYPE* _node = GetLowerBound(root);
		if (_node)
		{
			*node = _node;
			return true;
		}
		return false;
	}

	__forceinline
	__checkReturn	
	bool GetUpperBound(__in_opt const TYPE* root, __inout const TYPE** node)
	{
		const TYPE* _node = GetUpperBound(root);
		if (_node)
		{
			*node = _node;
			return true;
		}
		return false;
	}

private:
	__forceinline
	const TYPE* Parent(__in const void* node)
	{
		return reinterpret_cast<const TYPE*>(
			(ULONG_PTR)(*reinterpret_cast<const TYPE**>(((ULONG_PTR)node + m_parentOffset))) & m_sanityMask
			);
	}

	__forceinline
	const TYPE* RightChild(__in const void* node)
	{
		return *reinterpret_cast<const TYPE**>((ULONG_PTR)node + m_rightChildOffset);
	}

	__forceinline
	const TYPE* LeftChild(__in const void* node)
	{
		return *reinterpret_cast<const TYPE**>((ULONG_PTR)node + m_leftChildOffset);
	}

protected:
	const TYPE** m_root;

	size_t m_sanityMask;
	size_t m_parentOffset;
	size_t m_leftChildOffset;
	size_t m_rightChildOffset;
};

#endif //__BINTREEWALKER_H__
