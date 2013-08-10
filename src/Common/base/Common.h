#ifndef _COMMON_H
#define _COMMON_H

//#include "wdm.h"
#include "ntifs.h"
#include <stdlib.h>
#include <stddef.h>

#include "new.h"

#include "Shared.h"

#define MEMBER(cast, ptr, member) reinterpret_cast<cast*>((ULONG_PTR)(ptr) + (size_t)(member))

//----------------------------------------------------
// ****************** DRIVER OBJECT ******************
//----------------------------------------------------

extern PDRIVER_OBJECT gDriverObject;


//------------------------------------------------------
// ****************** COMMON ROUTINES ******************
//------------------------------------------------------

void InitUnicodeSubstring(
	__in_ecount(count) const WCHAR* wsubstr,
	__in size_t count, 
	__out UNICODE_STRING* ustr
	);

__checkReturn
const WCHAR* wcschrn(
	__in_ecount(len) const WCHAR* buff, 
	__in WCHAR c, 
	__in size_t len, 
	__in_opt int from = 0, 
	__in_opt bool reverse = false
	);

__checkReturn
void* GetProcAddress(
	__in const void* base, 
	__in const void* funcId
	);

#ifdef _WIN64

EXTERN_C void __kebreak();
#define KeBreak __kebreak

#else
__inline void KeBreak()
{
	__asm int 3;
	return;
}
#endif // _WIN64


//----------------------------------------------------
// ****************** COMMON MACROS ******************
//----------------------------------------------------

#define MAX_PROCID (sizeof(ULONG) << 3) //*8 .. byte => 8bite
#define	PROCID(cpu)		(KAFFINITY)((ULONG_PTR)KeQueryActiveProcessors() & (ULONG_PTR)(1 << (USHORT)cpu))

#endif // _COMMON_H
