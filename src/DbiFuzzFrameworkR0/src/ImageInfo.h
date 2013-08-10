/**
 * @file ImageInfo.hpp
 * @author created by: Peter Hlavaty
 * @author created on: 2013/08/09
 * @author \n
 * @author Copyright (c) 2013 ESET, spol. s r. o.
 * @note current owner: Peter Hlavaty (peter.hlavaty@eset.sk)
 * @note IMPORTANT: Before doing any significant change to this file check your plan with the current owner to avoid unexpected behaviour.
 */

#ifndef __IMAGEINFO_H__
#define __IMAGEINFO_H__

#include "../../Common/utils/ProcessCtx.h"
#include "../../Common/utils/LockedContainers.hpp"
#include "../../Common/utils/ColdPatcher.hpp"
#include "../../Common/utils/Range.h"

typedef COMPARABLE_ID_PTR<void*, CRelCallHook> RELLCALLHOOK_ID;

class CImage :
	public LOADED_IMAGE
{
	CImage();
	void operator=(const CImage&);
public:
	CImage(
		__in_opt UNICODE_STRING* fullImageName,
		__in IMAGE_INFO* imgInfo
		);

	bool SetUpNewRelHook(
		__in void* addrToHook,
		__in const void* addrOfHook
		);

	__checkReturn
	bool IsHooked(
		__in void* addrToHookCheck
		);

	void UninstallHook(
		__in void* addrToHookDown
		);

	bool Is64() { return m_is64; };
	ULONG EntryPoint() { return m_entryPoint; };
	UNICODE_STRING& ImageName() { return m_imageName; };

protected:
	bool m_is64;
	ULONG m_entryPoint;
	UNICODE_STRING m_imageName;

private:
	WCHAR* m_imgNameBuffer;
	CLockedAVL<RELLCALLHOOK_ID> m_hooks;
};

typedef COMPARABLE_ID_PTR<CRange<void>, CImage> CIMAGEINFO_ID;

#endif //__IMAGEINFO_H__
