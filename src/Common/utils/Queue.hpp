/**
 * @file Queue.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __QUEUE_H__
#define __QUEUE_H__

#include "../base/Common.h"

template<class TYPE>
struct QUEUE_ENTRY
{
	SLIST_ENTRY Next;
	TYPE Value;
};

template<class TYPE>
class CQueue
{
public:
	~CQueue()
	{
		TYPE* entry;
		while (entry = Pop())
			Remove(entry);
	}

	__checkReturn
	TYPE* Create()
	{
		//malloc is aligned - NonPagedPoolCacheAlignedMustS
		QUEUE_ENTRY<TYPE>* entry = reinterpret_cast<QUEUE_ENTRY<TYPE>*>(malloc(sizeof(QUEUE_ENTRY<TYPE>)));
		return entry ? &entry->Value : NULL;
	}

	void Remove(
		__in TYPE* entry
		)
	{
		delete CONTAINING_RECORD(entry, QUEUE_ENTRY<TYPE>, Value);
	}

	void Push(
		__in TYPE* entry
		)
	{
		InterlockedPushEntrySList(&m_head, &(CONTAINING_RECORD(entry, QUEUE_ENTRY<TYPE>, Value)->Next));
	}

	__checkReturn
	TYPE* Pop()
	{
		QUEUE_ENTRY<TYPE>* entry = reinterpret_cast<QUEUE_ENTRY<TYPE>*>(InterlockedPopEntrySList(&m_head));
		return (entry ? &entry->Value : NULL);
	}

	//top is not implemented, due that this structure is not locked ..

protected:
	SLIST_HEADER m_head;	
};

#endif //__QUEUE_H__
