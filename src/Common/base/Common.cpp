/**
 * @file Common.cpp
 * @author created by: Peter Hlavaty
 */

#include "stdafx.h"

#include "Common.h"

#include <ntimage.h>

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

__checkReturn
bool Is64Module( 
	__in const VOID* base
	)
{
#ifdef _WIN64

	const PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	const IMAGE_NT_HEADERS32 *nt32 = (IMAGE_NT_HEADERS32*)((PBYTE)base + dos->e_lfanew);

	// is64!
	return (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

#else

	return false;

#endif
}

__checkReturn
ULONG GetSizeOfImage( 
	__in const VOID* base 
	)
{
	const PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;

#ifdef _WIN64

	if (Is64Module(base))
	{
		const IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)((PBYTE)base + dos->e_lfanew);
		return nt64->OptionalHeader.SizeOfImage;
	}
	else

#endif
	{
		const IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)((PBYTE)base + dos->e_lfanew);
		return nt32->OptionalHeader.SizeOfImage;
	}
}
