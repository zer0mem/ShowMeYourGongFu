/**
 * @file ImageInfo.cpp
 * @author created by: Peter Hlavaty
 */

#include "StdAfx.h"

#include "ImageInfo.h"

#include "../../Common/base/Common.h"

CImage::CImage(
	__in_opt UNICODE_STRING* fullImageName,
	__in IMAGE_INFO* imgInfo 
	) : LOADED_IMAGE(imgInfo)
{
	CPE pe(imgInfo->ImageBase);
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

	if (CProcessContext::ResolveImageName(fullImageName->Buffer, 
		fullImageName->Length / sizeof(fullImageName->Buffer[0]), 
		&m_imageName))
	{
		m_imgNameBuffer = new WCHAR[(m_imageName.Length + 2) >> 1];
		if (m_imgNameBuffer)
		{
			memcpy(m_imgNameBuffer, m_imageName.Buffer, m_imageName.Length);
			m_imgNameBuffer[m_imageName.Length >> 1] = 0;
			m_imageName.Buffer = m_imgNameBuffer;
		}
		return;
	}

	m_imageName.Buffer = NULL;
	m_imageName.Length = 0;
	m_imageName.MaximumLength = 0;
}

bool CImage::SetUpNewRelHook( 
	__in void* addrToHook, 
	__in const void* addrOfHook 
	)
{
	if (!m_hooks.Find(RELLCALLHOOK_ID(addrToHook)))
	{
		CRelCallHook* hook = new CRelCallHook(addrToHook, addrOfHook);
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
	KeBreak();
	(void)m_hooks.Pop(RELLCALLHOOK_ID(addrToHookDown));
}
