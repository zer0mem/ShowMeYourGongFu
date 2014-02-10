/**
 * @file ColdPatcher.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __COLDPATCHER_H__
#define __COLDPATCHER_H__

#include "../base/Common.h"
#include "../Kernel/MemoryMapping.h"
#include "../Kernel/MMU.hpp"

template<size_t size>
class CColdPatch
{
public:
	CColdPatch() : m_addrToHook(NULL)
	{
	}

	CColdPatch(
		__in void* addrToHook,
		__in_bcount(size) const void* hook
		)
	{
		if (CMMU::IsValid(addrToHook))
		{
//const_cast + WritePtrUnsafe ==>> IoReadAccess isntead of IoModifyAccess ==> hook problems ... but this is wrong concept, find another solution ...
//probably it is already locked against modify ... 
			CApcLvl irql;
			if (irql.SufficienIrql())
			{
				CMdl patcher(addrToHook, size);
				void* cold_patch = patcher.WritePtrUnsafe();

				if (cold_patch)
				{
					DbgPrint("\n CColdPatch : %p %p %x\n", addrToHook, hook, size);

					memcpy(m_hookOrigB, cold_patch, size);
					memcpy(cold_patch, hook, size);

					m_addrToHook = addrToHook;
					return;
				}
			}
		}
		m_addrToHook = NULL;
	}

	~CColdPatch()
	{
		if (m_addrToHook)
		{
//const_cast + WritePtrUnsafe ==>> IoReadAccess isntead of IoModifyAccess ==> hook problems ... but this is wrong concept, find another solution ...
//probably it is already locked against modify ... 
			CApcLvl irql;
			if (!!NT_VERIFY(irql.SufficienIrql()))
			{
				CMdl patcher(m_addrToHook, size);
				void* cold_patch = patcher.WritePtrUnsafe();

				ASSERT(cold_patch);

				if (cold_patch)
				{
					//DbgPrint("\n ~CColdPatch uninstall : %p\n", m_addrToHook);
					memcpy(cold_patch, m_hookOrigB, size);
				}
			}
		}
	}

	__checkReturn
	bool IsHooked()
	{
		return !!m_addrToHook;
	}

	void* AddrToHook()
	{
		return m_addrToHook;
	}

private:
	BYTE m_hookOrigB[size];
	void* m_addrToHook;
};


#define SIZE_REL_CALL ((sizeof(ULONG) + sizeof(BYTE)))

struct RELCALLHOOK
{
	BYTE Buffer[SIZE_REL_CALL];

	RELCALLHOOK(
		__in void* addrToHook,
		__in const void* addrOfHook
		)
	{
		ULONG delta = (ULONG)(ULONG_PTR)((ULONG_PTR)addrOfHook - (ULONG_PTR)addrToHook - SIZE_REL_CALL);
		Buffer[0] = 0xE8;
		*reinterpret_cast<ULONG*>(Buffer + 1) = delta;		
	}
private:
	RELCALLHOOK();
};

/*
	call qword ptr[@next_instr]
@next_instr:
	dq 01234567812345678h
*/
#define FARCALL_INST_SIZE (sizeof(WORD) + sizeof(DWORD))
#define FARCALLHOOK_SIZE (FARCALL_INST_SIZE + sizeof(ULONG_PTR))

struct FARCALLHOOK
{
	BYTE Buffer[FARCALLHOOK_SIZE];

	FARCALLHOOK(
		__in const void* addrOfHook
		)
	{
		//call rsp
		memcpy(Buffer, "\xff\x15\x00\x00\x00\x00", FARCALL_INST_SIZE);
		*reinterpret_cast<ULONG_PTR*>(&Buffer[FARCALL_INST_SIZE]) = reinterpret_cast<ULONG_PTR>(addrOfHook);
	}
};

/*
	jmp rsp ; 0xe4ff [0xff 0xe4]
*/
#define INT3HOOK_SIZE sizeof(BYTE)

struct INT3HOOK
{
	BYTE Buffer[INT3HOOK_SIZE];

	INT3HOOK()
	{
		Buffer[0] = 0xCC;
	}
};

class CINT3Hook
{
public:
	CINT3Hook(
		__in void* addrToHook
		) : m_coldPatch(addrToHook, &m_hook.Buffer)
	{
	}
	__checkReturn
	bool IsHooked()
	{
		return m_coldPatch.IsHooked();
	}

	void* AddrToHook()
	{
		return m_coldPatch.AddrToHook();
	}
protected:
	INT3HOOK m_hook;
	CColdPatch<INT3HOOK_SIZE> m_coldPatch;
};

class CFarCallHook
{
	CFarCallHook(
		__in void* addrToHook,
		__in const void* addrOfHook
		) : m_hook(addrOfHook),
			m_coldPatch(addrToHook, &m_hook.Buffer)
	{
	}
protected:
	FARCALLHOOK m_hook;
	CColdPatch<FARCALLHOOK_SIZE> m_coldPatch;
};

class CRelCallHook
{
	CRelCallHook(
		__in void* addrToHook,
		__in const void* addrOfHook
		) : m_hook(addrToHook, addrOfHook),
			m_coldPatch(addrToHook, &m_hook.Buffer)
	{
	}
protected:
	RELCALLHOOK m_hook;
	CColdPatch<SIZE_REL_CALL> m_coldPatch;
};

#endif //__COLDPATCHER_H__
