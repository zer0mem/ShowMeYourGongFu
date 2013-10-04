/**
 * @file ImageInfo.cpp
 * @author created by: Peter Hlavaty
 */

#include "StdAfx.h"

#include "ImageInfo.h"

#include "../../Common/base/Common.h"
#include "Common/Constants.h"
#include "../../Common/utils/HashString.hpp"
#include "../../Common/utils/PE.hpp"

CImage::CImage(
	__in_opt UNICODE_STRING* fullImageName, 
	__in HANDLE processId, 
	__in IMAGE_INFO* imageInfo 
	) : LOADED_IMAGE(fullImageName, processId, imageInfo)
{
	CPE pe(imageInfo->ImageBase);
	if (pe.IsValid())
	{
		m_is64 = pe.Is64Img();
		m_entryPoint = pe.Entrypoint();
	}
	else
	{
		m_is64 = false;
		m_entryPoint = 0;
	}

	//DbgPrint("\nImage saved at : %p ", imageInfo->ImageBase);

	if (fullImageName && 
		CProcessContext<THREAD_INFO, CHILD_PROCESS, LOADED_IMAGE>::ResolveImageName(fullImageName->Buffer, 
			fullImageName->Length / sizeof(fullImageName->Buffer[0]), 
			&m_imageName))
	{
		m_imgNameBuffer = new WCHAR[(m_imageName.Length + 2) >> 1];
		if (m_imgNameBuffer)
		{
			memcpy(m_imgNameBuffer, m_imageName.Buffer, m_imageName.Length);
			m_imgNameBuffer[m_imageName.Length >> 1] = 0;
			m_imageName.Buffer = m_imgNameBuffer;

			m_system = CConstants::GetInstance().SystemModulesAVL().Find(&CHashString(m_imageName));
		}
		return;
	}

	m_system = false;

	m_imageName.Buffer = NULL;
	m_imageName.Length = 0;
	m_imageName.MaximumLength = 0;
}

bool CImage::SetUpNewRelHook( 
	__in void* addrToHook, 
	__in const void* addrOfHook 
	)
{
	if (Image().IsInRange(addrToHook))
	{
		if (!m_hooks.Find(RELLCALLHOOK_ID(addrToHook)))
		{
			CFarCallHook* hook = new CFarCallHook(addrToHook, addrOfHook);
			if (hook && hook->IsHooked())
			{
				RELLCALLHOOK_ID hook_id(addrToHook, hook);
				if (m_hooks.Push(hook_id))
				{
					hook_id.Value = NULL;//avoid dtor
					return true;
				}
			}
		}
	}
	else
	{
		//DbgPrint("\n this is probably not image inside you want to hook ;) : %p %p %p", addrToHook, Image().Begin(), Image().End());
		//KeBreak();
	}
	return false;
}

__checkReturn
bool CImage::IsHooked( 
	__in void* addrToHookCheck 
	)
{
	RELLCALLHOOK_ID* hook_id;
	if (m_hooks.Find(RELLCALLHOOK_ID(addrToHookCheck), &hook_id) && hook_id->Value)
		return hook_id->Value->IsHooked();
	return false;
}

void CImage::UninstallHook( 
	__in void* addrToHookDown 
	)
{
	(void)m_hooks.Pop(RELLCALLHOOK_ID(addrToHookDown));
}
