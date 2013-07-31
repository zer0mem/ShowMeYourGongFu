#ifndef _COMMON_H
#define _COMMON_H

//#include "wdm.h"
#include "ntifs.h"
#include <stdlib.h>
#include <stddef.h>

#include "new.h"

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

#ifdef _WIN64

#ifdef HYPERVISOR
#define KeBreak void
#else
EXTERN_C void __kebreak();
#define KeBreak __kebreak
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

//------------------------------------------------------------------
// ****************** DEFINE PUSHAQ order of regs ******************
//------------------------------------------------------------------

enum
{
	RAX = 0,
	RCX,
	RDX,
	RBX,
	RSP,
	RBP,
	RSI,
	RDI,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
	REG_COUNT
};

enum
{
	VOLATILE_REG_RCX = 0,
	VOLATILE_REG_RDX,
	VOLATILE_REG_R8,
	VOLATILE_REG_R9,
	VOLATILE_REG_COUNT
};

#define LOAD_RSP(reg) ((ULONG_PTR*)(reg[RSP]) + 2)
//compiler will handle this by optimalization
#define PPARAM(reg, num) (ULONG_PTR*)((num && num <= VOLATILE_REG_COUNT) ? (num < VOLATILE_REG_R8 ? &reg[RCX + num - 1 - VOLATILE_REG_RCX] :	&reg[R8 + num - 1 - VOLATILE_REG_R8]) : (LOAD_RSP(reg) + num))
#define PRETURN(reg) PPARAM(reg, 0)

#define ALIGN(addr, granularity)	(ULONG_PTR)((ULONG_PTR)addr & (~(granularity - 1)))

//--------------------------------------------------------------
// ****************** DEFINE TYPES -> based.h ******************
//--------------------------------------------------------------

// windows types
typedef unsigned long long  QWORD, *PQWORD, *LPQWORD;
typedef unsigned long	DWORD,	*PDWORD,	*LPDWORD;
typedef unsigned short	WORD,	*PWORD,		*LPWORD;
typedef unsigned char	BYTE,	*PBYTE,		*LPBYTE;
typedef unsigned int	UINT,	*PUINT,		*LPUINT;
typedef int				BOOL,	*PBOOL,		*LPBOOL;
typedef void					*PVOID,		*LPVOID;

typedef signed char SBYTE;
typedef signed short SWORD;
typedef signed long int SDWORD;

typedef char CHAR;
typedef wchar_t WCHAR;
typedef short SHORT;
typedef long LONG;
typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef unsigned long ULONG;

typedef BYTE BOOLEAN;

typedef __int64 LONGLONG;
typedef unsigned __int64 ULONGLONG;

typedef const void *LPCVOID;

#endif // _COMMON_H
