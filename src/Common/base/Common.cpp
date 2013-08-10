/**
 * @file Common.cpp
 * @author created by: Peter Hlavaty
 */

#include "stdafx.h"

#include "Common.h"

__checkReturn
const WCHAR* wcschrn( 
	__in_ecount(len) const WCHAR* buff, 
	__in WCHAR c, 
	__in size_t len, 
	__in_opt int from /*= 0*/, 
	__in_opt bool reverse /*= false*/
	)
{
	for (int i = from; i >= 0 && i < (int)len; reverse ? i-- : i++)
	{
		if (c == buff[i])
			return buff + i;
	}

	return NULL;
}

void InitUnicodeSubstring( 
	__in_ecount(count) const WCHAR* wsubstr, 
	__in size_t count, 
	__out UNICODE_STRING* ustr 
	)
{
	ustr->Length = ustr->MaximumLength = (USHORT)(count * sizeof(WCHAR));
	ustr->Buffer = (PWCH)(wsubstr);
}
