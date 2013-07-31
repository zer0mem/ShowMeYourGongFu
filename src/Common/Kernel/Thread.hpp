/**
 * @file Thread.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __THREAD_H__
#define __THREAD_H__

#include "../base/Common.h"
#include "../base/ComparableId.hpp"

/*
 * dont leak referenced PETHREAD! 
 * unless implemented refcounting, but in most cases
 * it is necessary to work directly with lookuped ethread ?
 */
class CEthread :
	public COMPARABLE_ID<PETHREAD>
{
	explicit CEthread(
		__in HANDLE threadId
		) : COMPARABLE_ID(NULL)
	{
		if (!NT_SUCCESS(PsLookupThreadByThreadId(threadId, &Id)))
			Id = NULL;
	}

	~CEthread()
	{
		if (Id)
			ObDereferenceObject(Id);
	}
};

#endif //__THREAD_H__
