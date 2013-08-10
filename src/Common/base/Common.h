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


//-----------------------------------------------------
// ****************** WORK WITH REGS ******************
//-----------------------------------------------------

class CRegXType
{
public:
	CRegXType(
		__in bool is64,
		__in void* regs
		) : m_is64(is64),
			m_regs(regs)
	{
	}

	ULONG_PTR GetRAX() { return GetReg(RAX); }
	ULONG_PTR GetRBX() { return GetReg(RBX); }
	ULONG_PTR GetRCX() { return GetReg(RCX); }
	ULONG_PTR GetRDX() { return GetReg(RDX); }
	ULONG_PTR GetRSI() { return GetReg(RSI); }
	ULONG_PTR GetRDI() { return GetReg(RDI); }
	ULONG_PTR GetRBP() { return GetReg(RBP); }
	ULONG_PTR GetRSP() { return GetReg(RSP); }
	ULONG_PTR GetFLAGS() { return GetReg(m_is64 ? REG_X64_COUNT : REG_X86_COUNT); }

	void SetRAX(__in ULONG_PTR regVal) { SetReg(RAX, regVal); }
	void SetRBX(__in ULONG_PTR regVal) { SetReg(RBX, regVal); }
	void SetRCX(__in ULONG_PTR regVal) { SetReg(RCX, regVal); }
	void SetRDX(__in ULONG_PTR regVal) { SetReg(RDX, regVal); }
	void SetRSI(__in ULONG_PTR regVal) { SetReg(RSI, regVal); }
	void SetRDI(__in ULONG_PTR regVal) { SetReg(RDI, regVal); }
	void SetRBP(__in ULONG_PTR regVal) { SetReg(RBP, regVal); }
	void SetRSP(__in ULONG_PTR regVal) { SetReg(RSP, regVal); }
	void SetFLAGS(__in ULONG_PTR flags) { SetReg(m_is64 ? REG_X64_COUNT : REG_X86_COUNT, flags); }

protected:
	void SetReg(
		__in size_t regId,
		__in ULONG_PTR regVal
		)
	{
		if (m_is64)
		{
			((reinterpret_cast<ULONG64*>(m_regs))[regId]) = (ULONG64)regVal;
		}
		else
		{
			((reinterpret_cast<ULONG*>(m_regs))[regId]) = (ULONG)regVal;
		}
	}

	ULONG_PTR GetReg(
		__in size_t regId
		)
	{
		if (m_is64)
		{
			return (ULONG_PTR)((reinterpret_cast<ULONG64*>(m_regs))[regId]);
		}
		else
		{
			return (ULONG_PTR)((reinterpret_cast<ULONG*>(m_regs))[regId]);
		}
	}

protected:
	bool m_is64;
	void* m_regs;
};


#endif // _COMMON_H
