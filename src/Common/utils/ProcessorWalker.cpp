/**
 * @file Process.h
 * @author created by: Peter Hlavaty
 */

#ifndef __PROCESSCTX_H__
#define __PROCESSCTX_H__

#include "../base/Common.h"

//define ext-interface
class CProcessContext
{
public:
	explicit CProcessContext(
		__inout PEPROCESS process,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		) : m_eprocess(process), m_processId(processId) { }

	static
	__checkReturn
	bool WatchProcess(
		__inout PEPROCESS process,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		)
	{
		return true;
	}

	void ProcessNotifyRoutineEx(
		__inout PEPROCESS process,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		)
	{
	}

	void ChildProcessNotifyRoutineEx(
		__inout PEPROCESS process,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		)
	{
	}

	void ImageNotifyRoutine(
		__in_opt UNICODE_STRING* fullImageName,
		__in HANDLE processId,
		__in IMAGE_INFO* imageInfo
		)
	{
	}

	void ThreadNotifyRoutine(
		__in HANDLE processId,
		__in HANDLE threadId,
		__in BOOLEAN create
		)
	{
	}

	void RemoteThreadNotifyRoutine(
		__in HANDLE processId,
		__in HANDLE threadId,
		__in BOOLEAN create
		)
	{
	}

	__checkReturn
	NTSTATUS RegisterCallback(
		__in void* CallbackContext,
		__in_opt void* Argument1,
		__in_opt void* Argument2
		)
	{
		return STATUS_SUCCESS;
	}

protected:
	static
	__checkReturn
	bool ResolveImageName( 
	__in_ecount(len) const WCHAR* fullImagePath, 
	__in size_t len, 
	__out UNICODE_STRING* imageName 
	)
	{
		const WCHAR* name = fullImagePath;

		if (0 != len)
		{
			const WCHAR* resolved_name = wcschrn(fullImagePath, L'\\', len, (int)(len - 1), true);
			if (NULL != resolved_name)
			{
				name = resolved_name + 1;
				len -= (name - fullImagePath);
				InitUnicodeSubstring(name, len, imageName);

				return true;
			}
		}

		return false;
	}


protected:
	HANDLE m_processId;
	PEPROCESS m_eprocess;
};

#endif //__PROCESSCTX_H__
