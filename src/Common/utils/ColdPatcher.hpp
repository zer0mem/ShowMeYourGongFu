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
		__in_bcount(size) const BYTE* hook
		)
	{
		if (CMMU::IsValid(addrToHook))
		{
			CMdl patcher(addrToHook, size);
			void* cold_patch = patcher.WritePtr();
			if (cold_patch)
			{
				DbgPrint("\n CColdPatch : %p %p %x\n", addrToHook, hook, size);

				memcpy(m_hookOrigB, cold_patch, size);
				memcpy(cold_patch, hook, size);

				m_addrToHook = addrToHook;
				return;
			}
		}
		m_addrToHook = NULL;
	}

	~CColdPatch()
	{
		if (m_addrToHook)
		{
			CMdl patcher(m_addrToHook, size);
			void* cold_patch = patcher.WritePtr();

			ASSERT(cold_patch);

			if (cold_patch)
			{
				DbgPrint("\n ~CColdPatch uninstall : %p\n", m_addrToHook);
				memcpy(cold_patch, m_hookOrigB, size);
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
		__in ULONG delta
		)
	{
		Buffer[0] = 0xE8;
		*reinterpret_cast<ULONG*>(Buffer + 1) = delta;		
	}
private:
	RELCALLHOOK();
};

class CRelCallHook
{
public:
	CRelCallHook(
		__in void* addrToHook,
		__in const void* addrOfHook
		) : m_relCallHook((ULONG)(ULONG_PTR)((ULONG_PTR)addrOfHook - (ULONG_PTR)addrToHook - SIZE_REL_CALL)),
			m_coldPatch(addrToHook, m_relCallHook.Buffer)
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

private:
	RELCALLHOOK m_relCallHook;
	CColdPatch<SIZE_REL_CALL> m_coldPatch;
};

#endif //__COLDPATCHER_H__
