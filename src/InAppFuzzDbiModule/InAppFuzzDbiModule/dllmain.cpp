// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "InAppFuzzDbiModule.h"

BOOL APIENTRY DllMain( 
	__in HMODULE hModule,
	__in DWORD  ul_reason_for_call,
	__in LPVOID lpReserved
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
