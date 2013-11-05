/**
 * @file HyperVisor.h
 * @author created by: Peter Hlavaty
 */

#ifndef __HYPERVISOR_H__
#define __HYPERVISOR_H__

#include "../Common/base/HVCommon.h"

class CHyperVisor
{
public:
	CHyperVisor(
		__in BYTE coredId,
		__in_opt const ULONG_PTR traps[MAX_CALLBACK], 
		__in_opt const VOID* callback = NULL
		);
	~CHyperVisor();

	ULONG_PTR HVEntryPoint(
		__inout ULONG_PTR reg[REG_COUNT], 
		__in VOID* param
		);
	BYTE GetCoredId();

protected:
	void HandleCrxAccess(
		__inout ULONG_PTR reg[REG_COUNT]
	);

protected:
	BYTE m_coreId;
	const VOID* m_callback;
	ULONG_PTR m_hvCallbacks[MAX_CALLBACK];
};

EXTERN_C VOID  hv_exit();

EXTERN_C void __hv_invd();
EXTERN_C void __hv_rdmsr();
EXTERN_C void __hv_wrmsr();
EXTERN_C void __hv_cpuid();
EXTERN_C void __hv_crx();
EXTERN_C void __hv_dummy();
EXTERN_C void __hv_dummy();
EXTERN_C void __hv_vmcall();
EXTERN_C void __hv_rdtsc();

#define INVD		reinterpret_cast<ULONG_PTR>(__hv_invd)
#define RDMSR		reinterpret_cast<ULONG_PTR>(__hv_rdmsr)
#define WRMSR		reinterpret_cast<ULONG_PTR>(__hv_wrmsr)
#define CPUID		reinterpret_cast<ULONG_PTR>(__hv_cpuid)
#define CRX			reinterpret_cast<ULONG_PTR>(__hv_crx)
#define VMX			reinterpret_cast<ULONG_PTR>(__hv_dummy)
#define DUMMY		reinterpret_cast<ULONG_PTR>(__hv_dummy)
#define VMCALL		reinterpret_cast<ULONG_PTR>(__hv_vmcall)
#define RDTSC		reinterpret_cast<ULONG_PTR>(__hv_rdtsc)

#endif //__HYPERVISOR_H__
