/**
 * @file Process.h
 * @author created by: Peter Hlavaty
 */

#include "StdAfx.h"

#include "ProcessCtx.h"

__checkReturn
bool CProcessContext::ResolveImageName( 
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
			//DbgPrint("\nProcess launched : %ws", resolved_name);
			len -= (name - fullImagePath);
			InitUnicodeSubstring(name, len, imageName);

			return true;
		}
	}

	return false;
}
