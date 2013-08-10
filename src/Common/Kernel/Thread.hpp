/**
 * @file Thread.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __THREAD_H__
#define __THREAD_H__

#include "../base/Common.h"
#include "../base/ComparableId.hpp"

class CEthread :
	public COMPARABLE_ID<PETHREAD>
{
public:
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

	PETHREAD GetEthread()
	{
		return Id;
	}

	PEPROCESS GetEProcess()
	{
		return PsGetThreadProcess(Id);
	}
};

#endif //__THREAD_H__
