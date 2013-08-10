/**
 * @file PE.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __PE_H__
#define __PE_H__

#include <ntimage.h>
#include "../base/Common.h"

//dangerous! necessary to have all data mapped!
//also imeplement safe read method!

class CPE
{
public:
	explicit CPE(
		__in const void* base
		) : m_base(base)
	{
		if (OptionalHeaderToData(m_base, &m_optHeader, &m_is64))
		{
#ifdef _WIN64
			if (m_is64)
			{
				const IMAGE_OPTIONAL_HEADER64* opt_header64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(m_optHeader);
				m_imgDir = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(&opt_header64->DataDirectory);
				m_ep = *reinterpret_cast<const ULONG*>(&opt_header64->AddressOfEntryPoint);
			}
			else
#endif
			{
				const IMAGE_OPTIONAL_HEADER32* opt_header32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(m_optHeader);
				m_imgDir = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(&opt_header32->DataDirectory);
				m_ep = *reinterpret_cast<const ULONG*>(&opt_header32->AddressOfEntryPoint);
			}
		}
		else
		{
			m_optHeader = NULL;
		}
	}
	
	__checkReturn
	bool IsValid()
	{
		return !!m_optHeader;
	}

	__checkReturn
	bool Is64Img()
	{
		return m_is64;
	}

	__checkReturn
	ULONG Entrypoint()
	{
		return m_ep;
	}

	__checkReturn
	const void* OptionalHeaderToData()
	{
		return m_optHeader;
	}
	
	__checkReturn
	void* GetProcAddress(
		__in const void* funcId
		)
	{
		if (IsValid())
		{
			IMAGE_EXPORT_DIRECTORY* export_dir = MEMBER(IMAGE_EXPORT_DIRECTORY, m_base, m_imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			WORD* ordinal_table = MEMBER(WORD, m_base, export_dir->AddressOfNameOrdinals );
			ULONG* offset_table = MEMBER(ULONG, m_base, export_dir->AddressOfFunctions );

			//find by ordinal
			if (*reinterpret_cast<const ULONG_PTR*>(funcId) < 0xFFFF)
			{
				ULONG ordinal = *reinterpret_cast<const ULONG*>(funcId);
				if (ordinal <= export_dir->NumberOfFunctions)
				{
					ULONG_PTR addr = offset_table[ordinal - export_dir->Base];
					if (addr > m_imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && 
						addr < m_imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + m_imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
					{
						//forwarded export						
						return NULL;
					}

					if (addr)
						return MEMBER(void, m_base, addr);
				}
			}
			//find by name
			else if (export_dir->NumberOfNames < 0xFFFF)
			{
				ULONG* names_table = MEMBER(ULONG, m_base, export_dir->AddressOfNames);

				for (ULONG min = 0, max = export_dir->NumberOfNames, i = max >> 1, prev = max + 1; 
					prev != i; 
					prev = i, i = min + ((max - min) >> 1))
				{
					const char* func_name = MEMBER(const char, m_base, names_table[i]);
					int cmp = strcmp(reinterpret_cast<const char*>(funcId), func_name);

					DbgPrint("\nbin search at %i (%s)\n", i, func_name);

					if (cmp < 0)
						max = i;
					else if (cmp > 0)
						min = i;
					else
						return MEMBER(void, m_base, offset_table[ordinal_table[i]]);
				}
			}
		}
		return NULL;
	}
	
private:
	__checkReturn
	bool OptionalHeaderToData(
		__in const void* base,
		__inout const void** optHeader,
		__inout_opt bool* is64
		)
	{
		const IMAGE_DOS_HEADER* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
		if (dos_header->e_magic == IMAGE_DOS_SIGNATURE)
		{
			const IMAGE_NT_HEADERS* nt_header = MEMBER(IMAGE_NT_HEADERS, dos_header, dos_header->e_lfanew);
			if (nt_header->Signature == IMAGE_NT_SIGNATURE)
			{
				if (nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC)
				{
					*optHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(&nt_header->OptionalHeader);
					if (is64)
						*is64 = true;
#ifdef _WIN64
				}
				else if (nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				{
					const IMAGE_NT_HEADERS32* nt_header32 = MEMBER(const IMAGE_NT_HEADERS32, dos_header, dos_header->e_lfanew);
					*optHeader = reinterpret_cast<const IMAGE_NT_HEADERS32*>(&nt_header32->OptionalHeader);
					if (is64)
						*is64 = false;
#endif
				}

				return true;
			}
		}
		return false;
	}

protected:
	const void* m_base;

	bool m_is64;
	ULONG m_ep;
	const void* m_optHeader;
	const IMAGE_DATA_DIRECTORY* m_imgDir;
};

#endif //__PE_H__
