/**
 * @file Constants.h
 * @author created by: Peter Hlavaty
 */

#include "stdafx.h"

#include "Constants.h"

const UNICODE_STRING CConstants::m_applicationsToFuzz[] =
{
	RTL_CONSTANT_STRING(L"codecoverme.exe"),
	RTL_CONSTANT_STRING(L"winhlp32.exe"),
};

const UNICODE_STRING CConstants::m_inAppModules[] =
{
	RTL_CONSTANT_STRING(L"inappfuzzdbimodule.dll"),
};

const STRING CConstants::m_inAppExtRoutines[] =
{
	RTL_CONSTANT_STRING("ExtTrapTrace"),
	RTL_CONSTANT_STRING("ExtInfo"),
	RTL_CONSTANT_STRING("ExtMain"),
};

CConstants CConstants::m_instance;
