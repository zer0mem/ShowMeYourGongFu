#include "StdAfx.h"

#include "./src/DbiMonitor.h"

#include "../Common/base/Common.h"
#include "drv_common.h"

#include "../Common/utils/Undoc.hpp"
#include "Common/Constants.h"

EXTERN_C
void __cdecl doexit(
	__in int /*code*/, 
	__in int quick, 
	__in int /*retcaller*/
	);

EXTERN_C
int __cdecl _cinit(int);

void OnUnload(
	__in DRIVER_OBJECT* DriverObject
	)
{
	doexit(0, 0, 0);
}

void EnviromentDependentVariablesInit()
{
	CUndoc::Init(
		VADVadRoot,
		VADAddressCreationLock,
		VADWorkingSetMutex,
		VADFlags,
		VADSameThreadApcFlags,
		0x090,// TrapFrame : Ptr64 _KTRAP_FRAME
		offsetof(_MM_AVL_TABLE, BalancedRoot),
		offsetof(_MM_AVL_TABLE, AvlInfo),
		(~0x3),
		(offsetof(_MMVAD_SHORT, VadNode) + offsetof(_MM_AVL_NODE, Parent)), 
		(offsetof(_MMVAD_SHORT, VadNode) + offsetof(_MM_AVL_NODE, LeftChild)), 
		(offsetof(_MMVAD_SHORT, VadNode) + offsetof(_MM_AVL_NODE, RightChild)),
		offsetof(_MMVAD_SHORT, StartingVpn), 
		offsetof(_MMVAD_SHORT, EndingVpn),
		offsetof(_MMVAD_SHORT, Flags),
		0xE0C,
		0x1478,		
		0x330,
		0x7D0,
		0x7010008004002001
		);

	/*
	//win7 SP1 ? - to check
	CUndoc::Init(
		0x448,
		0x218,
		0x390,
		0x440,
		0x450,
		offsetof(_MM_AVL_TABLE, BalancedRoot),
		offsetof(_MM_AVL_TABLE, AvlInfo),
		(~0x3),
		(offsetof(_MMVAD_SHORT, VadNode) + offsetof(_MM_AVL_NODE, Parent)), 
		(offsetof(_MMVAD_SHORT, VadNode) + offsetof(_MM_AVL_NODE, LeftChild)), 
		(offsetof(_MMVAD_SHORT, VadNode) + offsetof(_MM_AVL_NODE, RightChild)),
		offsetof(_MMVAD_SHORT, StartingVpn), 
		offsetof(_MMVAD_SHORT, EndingVpn),
		offsetof(_MMVAD_SHORT, Flags)
		);
		*/
}

NTSTATUS DriverEntry(
	__in DRIVER_OBJECT* driverObject, 
	__in UNICODE_STRING* RegistryPath
	)
{
	gDriverObject = driverObject;
	EnviromentDependentVariablesInit();

	_cinit(0);

	("DriverEntry\n");
	driverObject->DriverUnload = OnUnload;

	CDbiMonitor::GetInstance().Install();

    return STATUS_SUCCESS;
} // end DriverEntry()
