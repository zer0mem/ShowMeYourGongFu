/**
 * @file CSyscallCallbacks.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __CSYSCALLCALLBACKS_H__
#define __CSYSCALLCALLBACKS_H__

#include "../base/Common.h"
#include "CSYSCALL.hpp"

#include "../Kernel/MMU.h"

struct MEMORY_INFO
{
	const void* Memory;
	size_t Size;
	bool Write;
	void* Buffer;

	void SetInfo(
		__in const void* memory,
		__in size_t size,
		__in bool write,
		__in_opt void* buffer = NULL
		)
	{
		Memory = memory;
		Size = size;
		Write = write;
		Buffer = buffer;
	}
};

class CSyscallCallbacks :
	public CSYSCALL
{
protected:
	__checkReturn
	virtual bool VirtualMemoryCallback(
		__in void* memory,
		__in size_t size,
		__in bool write,
		__inout ULONG_PTR reg[REG_COUNT],
		__inout_opt BYTE* buffer = NULL
		)
	{
		return false;
	}

protected:
/*
 * TODO: 
 *   I. for sure all callbacks handle corectly params ? 
 *  II. handle some pagefault in nopageable area
 * III. tests
 */

//imeplemntation of Virtual Memory syscalls callbacks
	virtual bool NtAllocateVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	) override
	{
		return VirtualMemoryCallback(
			reinterpret_cast<void*>(*reinterpret_cast<ULONG_PTR*>(reg[RDX])),
			*reinterpret_cast<size_t*>(reg[R9]), 
			!!((ULONG)*PPARAM(reg, 6) & PAGE_WR_MASK), 
			reg
			);
	}
	virtual bool ZwFreeVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	) override
	{
		return VirtualMemoryCallback(
			reinterpret_cast<void*>(*reinterpret_cast<ULONG_PTR*>(reg[RDX])), 
			*reinterpret_cast<size_t*>(reg[R8]), 
			false,  
			reg
			);
	}
	virtual bool ZwQueryVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	) override
	{
		return VirtualMemoryCallback(reinterpret_cast<void*>(reg[RDX]), 
			0, 
			false,
			reg
			);
	}
	virtual bool NtWriteVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	) override
	{
		return VirtualMemoryCallback(
			reinterpret_cast<void*>(reg[RDX]), 
			(size_t)reg[R9], 
			true,
			reg, 
			reinterpret_cast<BYTE*>(reg[R8])
			);
	}
	virtual bool NtReadVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	) override
	{
		return VirtualMemoryCallback(
			reinterpret_cast<void*>(reg[RDX]),
			(size_t)reg[R9], 
			false,
			reg, 
			reinterpret_cast<BYTE*>(reg[R8])
			);
	}
	virtual bool NtProtectVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	) override
	{
		return VirtualMemoryCallback(
			reinterpret_cast<void*>(*reinterpret_cast<ULONG_PTR*>(reg[RDX])), 
			*reinterpret_cast<size_t*>(reg[R8]), 
			!!((ULONG)reg[R9] & PAGE_WR_MASK),
			reg
			);
	}
	virtual bool NtFlushVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	) override
	{
		return VirtualMemoryCallback(
			reinterpret_cast<void*>(*reinterpret_cast<ULONG_PTR*>(reg[RDX])), 
			*reinterpret_cast<size_t*>(reg[R8]), 
			false,
			reg
			);
	}
	virtual bool NtLockVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	) override
	{
		return VirtualMemoryCallback(
			reinterpret_cast<void*>(*reinterpret_cast<ULONG_PTR*>(reg[RDX])), 
			*reinterpret_cast<size_t*>(reg[R8]), 
			false,
			reg
			);
	}
	//f.e. used by KERNELBASE!PrefetchVirtualMemory; r9 == WIN32_MEMORY_RANGE_ENTRY*
	virtual bool ZwSetInformationVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	) override
	{
		return VirtualMemoryCallback(
			reinterpret_cast<void*>(*reinterpret_cast<ULONG_PTR*>(reg[R9])), 
			*reinterpret_cast<size_t*>(reinterpret_cast<ULONG_PTR*>(reg[R9]) + 1),
			false,
			reg
			);
	}
	virtual bool ZwUnlockVirtualMemory(
		__inout ULONG_PTR reg[REG_COUNT]
	) override
	{
		return VirtualMemoryCallback(
			reinterpret_cast<void*>(*reinterpret_cast<ULONG_PTR*>(reg[RDX])), 
			*reinterpret_cast<size_t*>(reg[R8]), 
			false,
			reg
			);
	}
};

#endif //__CSYSCALLCALLBACKS_H__
