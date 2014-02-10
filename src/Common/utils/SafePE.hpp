/**
 * @file SafePE.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __SAFEPE_H__
#define __SAFEPE_H__

#include "../UM/PE.hpp"
#include "../Kernel/IRQL.hpp"
#include "../Kernel/MemoryMapping.h"
#include "../base/Common.h"

class CSafePE :
	public CPE
{
public:
	__checkReturn
	static 
	const void* GetProcAddressSafe(
		__in const void* funcId,
		__in const void* base
		)
	{
		const void* func_addr = NULL;

		CApcLvl irql;
		if (irql.SufficienIrql())
		{
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
							func_addr = GetProcAddress(funcId, base, img_base, img_dir, export_dir);
					}							
				}
			}
		}		

		return func_addr;
	}
};

#endif //__SAFEPE_H__
