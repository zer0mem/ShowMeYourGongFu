/**
 * @file CSYSCALL.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __CSYSCALL_H__
#define __CSYSCALL_H__

#include "../Common/base/Common.h"
#include "CSYSCALL.h"

EXTERN_C ULONG_PTR* get_ring3_rsp();

class CSYSCALL
{
public:
	__checkReturn
	virtual bool Syscall(
		__inout ULONG_PTR reg[REG_COUNT]
		)
	{
		ULONG_PTR ring0rsp = reg[RSP];
		//-2 == simulating push ebp, pushfq to copy state as in reg[REG_COUNT]
		reg[RSP] = (ULONG_PTR)(get_ring3_rsp() - 2);

		bool status = false;
		switch ((ULONG)reg[RAX])
		{
		case ntdll_NtAllocateVirtualMemory:
			status = NtAllocateVirtualMemory(reg);
			break;
		case ntdll_ZwFreeVirtualMemory:
			status = ZwFreeVirtualMemory(reg);
			break;
		case ntdll_ZwQueryVirtualMemory:
			status = ZwQueryVirtualMemory(reg);
			break;
		case ntdll_NtWriteVirtualMemory:
			status = NtWriteVirtualMemory(reg);
			break;
		case ntdll_NtReadVirtualMemory:
			status = NtReadVirtualMemory(reg);
			break;
		case ntdll_NtProtectVirtualMemory:
			status = NtProtectVirtualMemory(reg);
			break;
		case ntdll_NtFlushVirtualMemory:
			status = NtFlushVirtualMemory(reg);
			break;
		case ntdll_NtLockVirtualMemory:
			status = NtLockVirtualMemory(reg);
			break;
		case ntdll_ZwSetInformationVirtualMemory:
			status = ZwSetInformationVirtualMemory(reg);
			break;
		case ntdll_ZwUnlockVirtualMemory:
			status = ZwUnlockVirtualMemory(reg);
			break;
		default:
			break;
		}

		reg[RSP] = ring0rsp;
		return status;
	}

protected:
	virtual bool NtAllocateVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	)
	{
		return false;
	}
	virtual bool ZwFreeVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	)
	{
		return false;
	}
	virtual bool ZwQueryVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	)
	{
		return false;
	}
	virtual bool NtWriteVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	)
	{
		return false;
	}
	virtual bool NtReadVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	)
	{
		return false;
	}
	virtual bool NtProtectVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	)
	{
		return false;
	}
	virtual bool NtFlushVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	)
	{
		return false;
	}
	virtual bool NtLockVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	)
	{
		return false;
	}
	virtual bool ZwSetInformationVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	)
	{
		return false;
	}
	virtual bool ZwUnlockVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	)
	{
		return false;
	}
};

#endif //__CSYSCALL_H__
