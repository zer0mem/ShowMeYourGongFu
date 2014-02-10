/**
 * @file AutoId.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __AUTOID_H__
#define __AUTOID_H__

#include "ntifs.h"
#include "../base/AutoObRef.hpp"

class CProcessById : 
	public CDeref<PEPROCESS>
{
public:
	CProcessById(
		__in HANDLE processId = NULL
		)
	{
		if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &Id)))
			Id = NULL;
	}

	HANDLE ProcessId()
	{
		if (GetRef())
			return PsGetProcessId(GetRef());
		return NULL;
	}
};

class CThreadById : 
	public CDeref<PETHREAD>
{
public:
	CThreadById(
		__in HANDLE threadId = NULL
		)
	{
		if (!NT_SUCCESS(PsLookupThreadByThreadId(threadId, &Id)))
			Id = NULL;
	}

	HANDLE ThreadId()
	{
		if (GetRef())
			return PsGetThreadId(GetRef());
		return NULL;
	}
};

#endif //__AUTOID_H__
