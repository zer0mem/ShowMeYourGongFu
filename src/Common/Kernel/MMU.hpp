/**
 * @file MMU.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __MMU_H__
#define __MMU_H__

#include "../base/Common.h"
#include "MMU.h"
#include "MemoryMapping.h"

class CMMU
{
public:
	CMMU(
		__in const void* address
		) : m_va(*reinterpret_cast<const VIRTUAL_ADDRESS*>(&address)),
			m_pml4(readcr3() + m_va.Selector.PML4Selector * sizeof(void*), sizeof(PAGE_TABLE_ENTRY)),
			m_pdp(GetNextTable(PML4(), m_va.Selector.PDPSelector), sizeof(PAGE_TABLE_ENTRY)),
			m_pt(GetNextTable(PDP(), m_va.Selector.PTSelector), sizeof(PAGE_TABLE_ENTRY)),
			m_pte(GetNextTable(PT(), m_va.Selector.PTESelector), sizeof(PAGE_TABLE_ENTRY))
	{
	}

	~CMMU()
	{
	}

	__checkReturn
	bool GetPML4(__out PAGE_TABLE_ENTRY& pte)
	{
		PAGE_TABLE_ENTRY* _pte = PML4();
		if (_pte)
		{
			pte = *_pte;
			return true;
		}
		return false;
	}

	__forceinline
	void SetPML4(__in PAGE_TABLE_ENTRY& pte)
	{
		PAGE_TABLE_ENTRY* _pte = PML4();
		if (_pte)
			*_pte = pte;
	}

	__checkReturn
	bool GetPDP(__out PAGE_TABLE_ENTRY& pte)
	{
		PAGE_TABLE_ENTRY* _pte = PDP();
		if (_pte)
		{
			pte = *_pte;
			return true;
		}
		return false;
	}

	__forceinline
	void SetPDP(__in PAGE_TABLE_ENTRY& pte)
	{
		PAGE_TABLE_ENTRY* _pte = PDP();
		if (_pte)
			*_pte = pte;
	}

	__checkReturn
	bool GetPT(__out PAGE_TABLE_ENTRY& pte)
	{
		PAGE_TABLE_ENTRY* _pte = PT();
		if (_pte)
		{
			pte = *_pte;
			return true;
		}
		return false;
	}

	__forceinline
	void SetPT(__in PAGE_TABLE_ENTRY& pte)
	{
		PAGE_TABLE_ENTRY* _pte = PT();
		if (_pte)
			*_pte = pte;
	}

	__checkReturn
	bool GetPTE(__out PAGE_TABLE_ENTRY& pte)
	{
		PAGE_TABLE_ENTRY* _pte = PTE();
		if (_pte)
		{
			pte = *_pte;
			return true;
		}
		return false;
	}

	__forceinline
	void SetPTE(__in PAGE_TABLE_ENTRY& pte)
	{
		PAGE_TABLE_ENTRY* _pte = PTE();
		if (_pte)
			*_pte = pte;
	}

	static
	bool IsValid(
		__in const void* addr
		)
	{
		CMMU mmu(addr);
		PAGE_TABLE_ENTRY pte;
		return (mmu.GetPTE(pte) && pte.Valid);
	}

	static
	bool IsWriteable(
		__in const void* addr
		)
	{
		CMMU mmu(addr);
		PAGE_TABLE_ENTRY pte;
		if (mmu.GetPTE(pte))
			return !!pte.Write;

		return false;
	}

	static
	void SetWriteable(
		__in const void* addr,
		__in size_t size
		)
	{
		const BYTE* end_addr = reinterpret_cast<const BYTE*>(PAGE_ALIGN((ULONG_PTR)addr + size + PAGE_SIZE));
		for (addr = reinterpret_cast<const BYTE*>(addr); 
			addr < end_addr; 
			addr = reinterpret_cast<const void*>((ULONG_PTR)addr + PAGE_SIZE))
		{
			CMMU mmu(addr);
			PAGE_TABLE_ENTRY pte;
			if (mmu.GetPTE(pte))
			{
				pte.Write = 1;
				mmu.SetPTE(pte);
			}
		}
	}

	static
	void SetUnWriteable(
		__in const void* addr,
		__in size_t size
		)
	{
		const BYTE* end_addr = reinterpret_cast<const BYTE*>(PAGE_ALIGN((ULONG_PTR)addr + size + PAGE_SIZE));
		for (addr = reinterpret_cast<const BYTE*>(addr); 
			addr < end_addr; 
			addr = reinterpret_cast<const void*>((ULONG_PTR)addr + PAGE_SIZE))
		{
			CMMU mmu(addr);
			PAGE_TABLE_ENTRY pte;
			if (mmu.GetPTE(pte))
			{
				pte.Write = 0;
				mmu.SetPTE(pte);
			}
		}
	}

protected:
	__forceinline
	__checkReturn 
	const void* GetNextTable(
		__in const PAGE_TABLE_ENTRY* table, 
		__in size_t selector
		)
	{
		if (!table)
			return NULL;

		return reinterpret_cast<const void*>((table->PageFrameNumber << PAGE_SHIFT) + selector * sizeof(void*));
	}

private:
	__forceinline
	__checkReturn 
	PAGE_TABLE_ENTRY* PML4()
	{
		PAGE_TABLE_ENTRY* pte = reinterpret_cast<PAGE_TABLE_ENTRY*>(m_pml4.GetVirtualAddress());
		return ( (pte && pte->Valid) ? pte : NULL );
	}

	__forceinline
	__checkReturn 
	PAGE_TABLE_ENTRY* PDP()
	{
		PAGE_TABLE_ENTRY* pte = reinterpret_cast<PAGE_TABLE_ENTRY*>(m_pdp.GetVirtualAddress());
		return ( (pte && pte->Valid) ? pte : NULL );
	}

	__forceinline
	__checkReturn
	PAGE_TABLE_ENTRY* PT()
	{
		PAGE_TABLE_ENTRY* pte = reinterpret_cast<PAGE_TABLE_ENTRY*>(m_pt.GetVirtualAddress());
		return ( (pte && pte->Valid) ? pte : NULL );
	}

	__forceinline
	__checkReturn 
	PAGE_TABLE_ENTRY* PTE()
	{
		PAGE_TABLE_ENTRY* pte = reinterpret_cast<PAGE_TABLE_ENTRY*>(m_pte.GetVirtualAddress());
		return ( (pte && pte->Valid) ? pte : NULL );
	}
	
protected:
	CDispatchLvl m_irql;

	VIRTUAL_ADDRESS m_va;

	CMmMap m_pml4;
	CMmMap m_pdp;
	CMmMap m_pt;
	CMmMap m_pte;
};

#endif //__MMU_H__
