/**
 * @file AutoHandle.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __AUTOHANDLE_H__
#define __AUTOHANDLE_H__

#include "../base/Common.h"

class CDerefHandle
{
public:
	~CDerefHandle()
	{
		CloseHandle(hndl);
	}

	__checkReturn
	bool IsReferenced()
	{
		return !!hndl;
	}

	__checkReturn
	HANDLE GetHandle()
	{
		return hndl;
	}

protected:
	HANDLE hndl;
};

class COpenProcess :
	public CDerefHandle
{
public:
	COpenProcess(
		__in DWORD dwProcessId,
		__in DWORD dwDesiredAccess = PROCESS_ALL_ACCESS,
		__in BOOL bInheritHandle = FALSE
		)
	{
		hndl = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	}
};

class COpenThread :
	public CDerefHandle
{
public:
	COpenThread(
		__in DWORD dwThreadId,
		__in DWORD dwDesiredAccess = PROCESS_ALL_ACCESS,
		__in BOOL bInheritHandle = FALSE
		)
	{
		hndl = OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
	}
};

#endif //__AUTOHANDLE_H__
