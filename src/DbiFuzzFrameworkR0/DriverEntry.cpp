#include "StdAfx.h"

#include "./src/DbiMonitor.h"

#include "../Common/base/Common.h"
#include "drv_common.h"

#include "../Common/utils/Undoc.hpp"
#include "Common/Constants.h"

PDRIVER_OBJECT gDriverObject;

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
}

NTSTATUS DriverEntry(
	__in DRIVER_OBJECT* driverObject, 
	__in UNICODE_STRING* RegistryPath
	)
{
	gDriverObject = driverObject;
	EnviromentDependentVariablesInit();

	_cinit(0);

	DbgPrint("DriverEntry\n");
	driverObject->DriverUnload = OnUnload;

	CDbiMonitor::GetInstance().Install();

    return STATUS_SUCCESS;
} // end DriverEntry()
