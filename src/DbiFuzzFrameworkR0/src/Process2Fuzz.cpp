/**
 * @file Process.cpp
 * @author created by: Peter Hlavaty
 */

#include "stdafx.h"

#include "Process2Fuzz.h"
#include "Common/Constants.h"

#include "../../Common/utils/HashString.hpp"
#include "../../Common/Kernel/MMU.hpp"
#include "../../Common/utils/VADWalker.h"

EXTERN_C void syscall_instr_prologue();
EXTERN_C void syscall_instr_epilogue();

//need to call _dynamic_initializer_for__cSyscallSize_
//static const size_t cSyscallSize = (ULONG_PTR)syscall_instr_epilogue - (ULONG_PTR)syscall_instr_prologue;
#define cSyscallSize ((ULONG_PTR)syscall_instr_epilogue - (ULONG_PTR)syscall_instr_prologue)

EXTERN_C ULONG_PTR* get_ring3_rsp();

//-----------------------------------------------------------------
// ****************** DEFINE THREAD INFO STRUCTS ******************
//-----------------------------------------------------------------

struct FUZZ_THREAD_INFO : 
	public THREAD_INFO
{
	MEMORY_INFO MemoryInfo;
	ULONG_PTR GeneralPurposeContext[REG_COUNT];

	FUZZ_THREAD_INFO() : 
		THREAD_INFO(PsGetCurrentThreadId(), PsGetCurrentProcessId())
	{
		WaitForSyscallCallback = false;
	}

	FUZZ_THREAD_INFO(
		__in HANDLE threadId,
		__in HANDLE parentProcessId
		) : THREAD_INFO(threadId, parentProcessId)
	{
		WaitForSyscallCallback = false;
	}

	__forceinline
	__checkReturn
	bool WaitForSyscallEpilogue()
	{
		return WaitForSyscallCallback;
	}

	void SetCallbackEpilogue(
		__in ULONG_PTR reg[REG_COUNT],
		__in void* memory,
		__in size_t size,
		__in bool write,
		__in_opt void* pageFault = NULL
		)

	{
		WaitForSyscallCallback = true;

		*GeneralPurposeContext = *reg;
		MemoryInfo.SetInfo(memory, size, write);

//invoke SYSCALL again after syscall is finished!
		reg[RCX] -= cSyscallSize;
/*
		ULONG_PTR* r3stack = get_ring3_rsp();
		//set return againt to SYSCALL instr
		*r3stack -= cSyscallSize;
*/
	}

	__forceinline 
	void EpilogueProceeded()
	{
		WaitForSyscallCallback = false;
	}

protected:
	bool WaitForSyscallCallback;
};


//-------------------------------------------------------------------
// ****************** CProcess2Fuzz implementation ******************
//-------------------------------------------------------------------

CProcess2Fuzz::CProcess2Fuzz( 
	__inout PEPROCESS process, 
	__in HANDLE processId, 
	__inout_opt PS_CREATE_NOTIFY_INFO* createInfo 
	) : CProcessContext(process, processId, createInfo)
{
}

CProcess2Fuzz::~CProcess2Fuzz()
{
}

__checkReturn
bool CProcess2Fuzz::WatchProcess( 
	__inout PEPROCESS eprocess, 
	__in HANDLE processId, 
	__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
	)
{
	UNICODE_STRING image_name;
	if (createInfo->ImageFileName)
	{
		if (ResolveImageName(createInfo->ImageFileName->Buffer, 
				createInfo->ImageFileName->Length / sizeof(createInfo->ImageFileName->Buffer[0]), 
				&image_name))
		{
			//return true;//test if correct handled syscall, virtualmemory, pagefault callbacks ...
			return CConstants::GetInstance().ApplicationsToFuzzAVL().Find(&CHashString(image_name));
		}
	}
	return false;
}

void CProcess2Fuzz::ProcessNotifyRoutineEx( 
	__inout PEPROCESS eprocess, 
	__in HANDLE processId,
	__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
	)
{
	DbgPrint("\n @ProcessNotifyRoutineEx %x %p %s\n", processId, eprocess, !!createInfo ? "start" : "exit");
}

void CProcess2Fuzz::ChildProcessNotifyRoutineEx( 
	__inout PEPROCESS eprocess, 
	__in HANDLE processId, 
	__inout_opt PS_CREATE_NOTIFY_INFO* createInfo 
	)
{
	if (createInfo)
		(void)m_childs.Push(CHILD_PROCESS(eprocess, processId));
	else
		(void)m_childs.Pop(CHILD_PROCESS(eprocess));

	DbgPrint("\n CHILD!ProcessNotifyRoutineEx %x %p %s %x\n", processId, PsGetCurrentProcessId(), !!createInfo ? "start" : "exit", createInfo->ImageFileName->Buffer);
}

void CProcess2Fuzz::ImageNotifyRoutine( 
	__in_opt UNICODE_STRING* fullImageName, 
	__in HANDLE processId,
	__in IMAGE_INFO* imageInfo
	)
{
	(void)m_loadedImgs.Push(LOADED_IMAGE(imageInfo));

	if (!imageInfo->SystemModeImage)
	{
		DbgPrint("\n @ImageNotifyRoutine %x %p [%p %p]\n", processId, PsGetCurrentProcess(), imageInfo->ImageBase, imageInfo->ImageSize);
	}
	else
	{
		DbgPrint("\n SYSTEM ImageNotifyRoutine %x %p\n", processId, PsGetCurrentProcess());
	}
}

void CProcess2Fuzz::ThreadNotifyRoutine( 
	__in HANDLE processId, 
	__in HANDLE threadId, 
	__in BOOLEAN create
	)
{
	FUZZ_THREAD_INFO thread_info(threadId, processId);
	if (!!create)
	{
		(void)m_threads.Push(thread_info);
		(void)m_stacks.Push(thread_info.Stack);
	}
	else
	{
		(void)m_threads.Pop(thread_info);
		(void)m_stacks.Pop(thread_info.Stack);
	}

	DbgPrint("\n @ThreadNotifyRoutine %x %p %s\n", processId, PsGetCurrentProcess(), !!create ? "start" : "exit");
}

void CProcess2Fuzz::RemoteThreadNotifyRoutine(
	__in HANDLE parentProcessId, 
	__in HANDLE threadId, 
	__in BOOLEAN create 
	)
{
	FUZZ_THREAD_INFO thread_info(threadId, parentProcessId);
	if (!!create)
	{
		(void)m_threads.Push(thread_info);
		(void)m_stacks.Push(thread_info.Stack);
	}
	else
	{
		(void)m_threads.Pop(thread_info);
		(void)m_stacks.Pop(thread_info.Stack);
	}

	DbgPrint("\n REMOTE!ThreadNotifyRoutine %x %p %s\n", parentProcessId, PsGetCurrentProcess(), !!create ? "start" : "exit");
}

__checkReturn
bool CProcess2Fuzz::VirtualMemoryCallback(
	__in void* memory,
	__in size_t size,
	__in bool write,
	__inout ULONG_PTR reg[REG_COUNT],
	__inout_opt BYTE* buffer /*= NULL*/
	)
{
	DbgPrint("\n@VirtualMemoryCallback %p %p [thread : %p]\n", PsGetThreadProcessId(PsGetCurrentThread()), m_processId, PsGetCurrentThread());
	FUZZ_THREAD_INFO* fuzz_thread;
	if (m_threads.Find(FUZZ_THREAD_INFO(), &fuzz_thread))
	{
		ULONG_PTR* r3stack = get_ring3_rsp();
		DbgPrint("\n >  I. @Prologue %p %p [%p]\n", r3stack, *r3stack, reg[RCX]);
		fuzz_thread->SetCallbackEpilogue(reg, memory, size, write);
	}
	return false;
}

__checkReturn
bool CProcess2Fuzz::Syscall( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	//implement ref counting ? auto_ptr...
	//but assumption, if thread is in syscall then it can not exit for now good enough...
	FUZZ_THREAD_INFO* fuzz_thread;
	if (m_threads.Find(FUZZ_THREAD_INFO(), &fuzz_thread))
	{
		if (fuzz_thread->WaitForSyscallEpilogue())
		{				
			if (fuzz_thread->MemoryInfo.Write &&
				//CMemoryRange((BYTE*)fuzz_thread->MemoryInfo.Memory, fuzz_thread->MemoryInfo.Size, 0).IsInRange((BYTE*)0x2340000))
				!m_stacks.Find(CRange<ULONG_PTR>(reinterpret_cast<ULONG_PTR*>(fuzz_thread->MemoryInfo.Memory))))
			{
				SetUnwriteable(fuzz_thread->MemoryInfo.Memory, fuzz_thread->MemoryInfo.Size);
			}
				
			DbgPrint("\n > @Epilogue %p %x %s\n", fuzz_thread->MemoryInfo.Memory, fuzz_thread->MemoryInfo.Size, fuzz_thread->MemoryInfo.Write ? "attempt to write" : "easy RE+ attempt");
			fuzz_thread->EpilogueProceeded();
			return true;
		}
	}

	return CSYSCALL::Syscall(reg);
}

__checkReturn
bool CProcess2Fuzz::PageFault( __inout ULONG_PTR reg[REG_COUNT] )
{
	BYTE* fault_addr = reinterpret_cast<BYTE*>(readcr2());

	//temporary for demo
	if (0x2340000 == (ULONG_PTR)fault_addr)
		return false;

	if (0x2340002 == (ULONG_PTR)fault_addr)
		KeBreak();

	if (m_nonWritePages.Find(CMemoryRange(fault_addr, sizeof(BYTE))))
	{
		m_nonWritePages.Pop(CMemoryRange(fault_addr, sizeof(BYTE)));
		if (!CMMU::IsWriteable(fault_addr))
		{
			CMMU::SetWriteable(fault_addr, sizeof(ULONG_PTR));
			//+set trap after instruction, to set unwriteable!

			//sync problem, not locked and acces via ref, via ref counting ...
			return true;
		}
	}
	
	return false;
}

void CProcess2Fuzz::SetUnwriteable( 
	__in const void* addr, 
	__in size_t size 
	)
{
	CVadNodeMemRange vad_mem;
	CVadScanner vad_scanner(PsGetCurrentThread());
	if (vad_scanner.FindVadMemoryRange(addr, &vad_mem))
	{
		ULONG flags = *reinterpret_cast<ULONG*>(&vad_mem.GetFlags());
		const BYTE* end_addr = reinterpret_cast<const BYTE*>( PAGE_ALIGN((ULONG_PTR)addr + size + PAGE_SIZE) );
		for (const BYTE* b_addr = reinterpret_cast<const BYTE*>(addr);
			b_addr < end_addr;
			b_addr += PAGE_SIZE)
		{
			(void)m_nonWritePages.Push(CMemoryRange(b_addr, PAGE_SIZE, flags));
		}
					
		/*
		 * After initializing mem, it is stored just in VAD
		 * at first pagefault using this addrres is parsed VAD and created particular PTE!
		 */
	  if (!CMMU::IsValid(addr))
			vad_scanner.SetUnwriteable(addr, size);
		else
			CMMU::SetUnWriteable(addr, size);
	}
}
