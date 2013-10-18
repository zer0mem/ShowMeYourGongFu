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
		const void* opt_hdr = OptionalHeaderToData(m_base, &m_is64);
		if (opt_hdr)
		{
			m_isValid = true;
#ifdef _WIN64
			if (m_is64)
			{
				const IMAGE_OPTIONAL_HEADER64* opt_header64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(opt_hdr);
				m_ep = *reinterpret_cast<const ULONG*>(&opt_header64->AddressOfEntryPoint);
				
				m_imgDir = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(&opt_header64->DataDirectory);
			}
			else
#endif
			{
				const IMAGE_OPTIONAL_HEADER32* opt_header32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(opt_hdr);
				m_ep = *reinterpret_cast<const ULONG*>(&opt_header32->AddressOfEntryPoint);

				m_imgDir = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(&opt_header32->DataDirectory);
			}
		}
		else
		{
			m_isValid = false;
		}
	}
	
	__checkReturn
	__forceinline
	bool IsValid()
	{
		return m_isValid;
	}

	__checkReturn
	__forceinline
	bool Is64Img()
	{
		return m_is64;
	}

	__checkReturn
	__forceinline
	ULONG Entrypoint()
	{
		return m_ep;
	}

	__checkReturn
	__forceinline
	const IMAGE_DATA_DIRECTORY* ImageDataDirectory()
	{
		return m_imgDir;
	}

	__checkReturn 
	__forceinline
	const void* GetProcAddress(
		__in const void* funcId
		)
	{
		return GetProcAddress(funcId, m_base, m_imgDir, MEMBER(IMAGE_EXPORT_DIRECTORY, m_base, m_imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	}

	__checkReturn
	static 
	const void* GetProcAddressSafe(
		__in const void* funcId,
		__in const void* base
		)
	{
		const void* func_addr = NULL;

		CMdl image_map(base, PAGE_SIZE);
		const void* img_base = image_map.ReadPtrUser();
		if (img_base)
		{
			CPE mz(img_base);
			if (mz.IsValid())
			{
				//mdl can be mapped (& overlaped) more times ...
				CMdl img_dir_map(MEMBER(const IMAGE_DATA_DIRECTORY, base, ((ULONG_PTR)mz.ImageDataDirectory() - (ULONG_PTR)img_base)), 
					sizeof(IMAGE_DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR + 1]));

				const IMAGE_DATA_DIRECTORY* img_dir = static_cast<const IMAGE_DATA_DIRECTORY*>(img_dir_map.ReadPtrUser());
				if (img_dir)
				{
					CMdl export_dir_map(MEMBER(const IMAGE_EXPORT_DIRECTORY, base, img_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), 
						img_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);

					const IMAGE_EXPORT_DIRECTORY* export_dir = static_cast<const IMAGE_EXPORT_DIRECTORY*>(export_dir_map.ReadPtrUser());
					if (export_dir)
						func_addr = GetProcAddress(funcId, img_base, img_dir, export_dir);
				}							
			}
		}
		return func_addr;
	}
	
private:
	__checkReturn
	const void* OptionalHeaderToData(
		__in const void* base,
		__inout_opt bool* is64
		)
	{
		const void* opt_hdr = NULL;
		if (base)
		{
			const IMAGE_DOS_HEADER* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
			if (dos_header->e_magic == IMAGE_DOS_SIGNATURE)
			{
				const IMAGE_NT_HEADERS* nt_header = MEMBER(IMAGE_NT_HEADERS, dos_header, dos_header->e_lfanew);
				if (nt_header->Signature == IMAGE_NT_SIGNATURE)
				{
					if (nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC)
					{
						opt_hdr = reinterpret_cast<const void*>(&nt_header->OptionalHeader);
						if (is64)
							*is64 = true;
#ifdef _WIN64
					}
					else if (nt_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
					{
						const IMAGE_NT_HEADERS32* nt_header32 = MEMBER(const IMAGE_NT_HEADERS32, dos_header, dos_header->e_lfanew);
						opt_hdr = reinterpret_cast<const void*>(&nt_header32->OptionalHeader);
						if (is64)
							*is64 = false;
#endif
					}
				}
			}
		}		
		return opt_hdr;
	}

	__checkReturn
	static 
	const void* GetProcAddress(
		__in const void* funcId,
		__in const void* base,
		__in const IMAGE_DATA_DIRECTORY* imgDir,
		__in const IMAGE_EXPORT_DIRECTORY* export_dir
		)
	{
		WORD* ordinal_table = MEMBER(WORD, export_dir, export_dir->AddressOfNameOrdinals - imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		ULONG* offset_table = MEMBER(ULONG, export_dir, export_dir->AddressOfFunctions - imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		//find by ordinal
		if (*reinterpret_cast<const ULONG_PTR*>(funcId) < 0xFFFF)
		{
			ULONG ordinal = *reinterpret_cast<const ULONG*>(funcId);
			if (ordinal <= export_dir->NumberOfFunctions)
			{
				ULONG_PTR addr = offset_table[ordinal - export_dir->Base];

				if (addr > imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress && 
					addr < imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
				{
					//forwarded export						
					return NULL;
				}

				if (addr)
					return MEMBER(void, base, addr);
			}
		}
		//find by name
		else if (export_dir->NumberOfNames < 0xFFFF)
		{
			ULONG* names_table = MEMBER(ULONG, export_dir, export_dir->AddressOfNames - imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			for (ULONG min = 0, max = export_dir->NumberOfNames, i = max >> 1, prev = max + 1; 
				prev != i; 
				prev = i, i = min + ((max - min) >> 1))
			{
				const char* func_name = MEMBER(const char, export_dir, names_table[i] - imgDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				int cmp = strcmp(reinterpret_cast<const char*>(funcId), func_name);

				if (cmp < 0)
					max = i;
				else if (cmp > 0)
					min = i;
				else
					return MEMBER(void, base, offset_table[ordinal_table[i]]);
			}
		}
		return NULL;
	}

protected:
	const void* m_base;

	bool m_is64;
	ULONG m_ep;
	bool m_isValid;
	const IMAGE_DATA_DIRECTORY* m_imgDir;
};

#endif //__PE_H__
