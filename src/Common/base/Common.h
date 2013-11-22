#ifndef _COMMON_H
#define _COMMON_H

//#include "wdm.h"
#include "ntifs.h"
#include <stdlib.h>
#include <stddef.h>

#include "new.h"

#include "Shared.h"

//#define _DEBUG_MODE

#define MEMBER(cast, ptr, member) reinterpret_cast<cast*>(reinterpret_cast<ULONG_PTR>(ptr) + static_cast<size_t>(member))

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
bool IsUserModeAddress(
	__in const void* addr
	);

__checkReturn
bool IsUserModeAddress(
	__in ULONG_PTR addr
	);

#ifdef _WIN64

EXTERN_C void __kebreak();
EXTERN_C void __nop();

#ifdef _DEBUG_MODE
#define KeBreak __kebreak
#else
#define KeBreak __nop
#endif

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

#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
	(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
	(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
	(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
	(((signed __int64)(seconds)) * MILLISECONDS(1000L))


#endif // _COMMON_H
