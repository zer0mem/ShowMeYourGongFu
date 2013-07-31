/**
 * @file Constants.h
 * @author created by: Peter Hlavaty
 */

#include "stdafx.h"

#include "Constants.h"

const UNICODE_STRING CConstants::ApplicationsToFuzz[] =
{
	RTL_CONSTANT_STRING(L"codecoverme.exe"),
};

CConstants CConstants::m_instance;
