/**
 * @file Process.cpp
 * @author created by: Peter Hlavaty
 */

#include "stdafx.h"

#include "Process2Fuzz.h"

#include "../../Common/utils/HashString.hpp"
#include "../../Common/Kernel/MMU.hpp"
#include "../../Common/utils/VADWalker.h"

#include "../../Common/utils/PE.hpp"
#include "../../Common/FastCall/FastCall.h"

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
	if (!imageInfo->SystemModeImage)
	{
		if (!m_epHook.IsInitialized())
			m_epHook.InitBase(imageInfo->ImageBase);


		UNICODE_STRING image_name;

		LOADED_IMAGE img(imageInfo);
		if (ResolveImageName(fullImageName->Buffer, 
			fullImageName->Length / sizeof(fullImageName->Buffer[0]), 
			&image_name))
		{
			img.ImgName = new WCHAR[(image_name.Length + 2) >> 1];
			memcpy(img.ImgName, image_name.Buffer, image_name.Length);
			img.ImgName[image_name.Length >> 1] = 0;

			(void)m_loadedImgs.Push(img);

			if (CConstants::GetInstance().InAppModulesAVL().Find(&CHashString(image_name)))
			{
				KeBreak();
				CPE pe(imageInfo->ImageBase);
				const void* func_name;
				for (size_t i = 0;
					(func_name = CConstants::InAppExtRoutines(i));
					i++)
				{
					m_extRoutines[i] = pe.GetProcAddress(func_name);
				}
				//setup last function as hook
				m_epHook.SetUpHook(m_extRoutines[ExtMain]);
			}
		}
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
	CThreadEvent thread_info(threadId, processId);
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
	CThreadEvent thread_info(threadId, parentProcessId);
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
	CThreadEvent* fuzz_thread;
	if (m_threads.Find(CThreadEvent(), &fuzz_thread))
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
	if (!m_epHook.IsHooked())
		m_epHook.InstallHook();


	if (FAST_CALL == reg[DBI_IOCALL])
	{
		switch (reg[DBI_ACTION])//reg[RAX]
		{
		case SYSCALL_INFO_FLAG:
			DbgPrint("\n > SYSCALL_INFO_FLAG < \n");
			KeBreak();
			return true;
		case SYSCALL_TRACE_FLAG:
			DbgPrint("\n > SYSCALL_TRACE_FLAG < \n");
			KeBreak();
			return true;
		default:
			DbgPrint("\n > SYSCALL_UNKNOWN_FLAG < \n");
			break;
		}		
	}
	//implement ref counting ? auto_ptr...
	//but assumption, if thread is in syscall then it can not exit for now good enough...
	CThreadEvent* fuzz_thread;
	if (m_threads.Find(CThreadEvent(), &fuzz_thread))
	{		
		if (fuzz_thread->WaitForSyscallEpilogue())
		{				
			if (fuzz_thread->LastMemoryInfo.Write &&
				!m_stacks.Find(CRange<ULONG_PTR>(reinterpret_cast<ULONG_PTR*>(fuzz_thread->LastMemoryInfo.Memory))))
			{
				//SetUnwriteable(fuzz_thread->LastMemoryInfo.Memory, fuzz_thread->LastMemoryInfo.Size);
			}
				
			DbgPrint("\n > @Epilogue %p %x %s\n", fuzz_thread->LastMemoryInfo.Memory, fuzz_thread->LastMemoryInfo.Size, fuzz_thread->LastMemoryInfo.Write ? "attempt to write" : "easy RE+ attempt");
			fuzz_thread->EpilogueProceeded();
			return true;
		}
	}

	return CSYSCALL::Syscall(reg);
}

__checkReturn
bool CProcess2Fuzz::PageFault( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	IRET* iret = PPAGE_FAULT_IRET(reg);
	BYTE* fault_addr = reinterpret_cast<BYTE*>(readcr2());

	if (readcr2() == FAST_CALL)
	{
		if (FAST_CALL == (ULONG_PTR)iret->Return)
		{
			//handle branch tracing - callback from HV
			iret->Return = m_extRoutines[ExtTrapTrace];
			return true;
		}
	}

	LOADED_IMAGE* img;
	if (m_loadedImgs.Find(LOADED_IMAGE(iret->Return), &img))
	{
		CThreadEvent* fuzz_thread;
		if (PsGetCurrentProcessId() == m_processId)
		{
			if (FAST_CALL == readcr2())
			{
				if (readcr2() == reg[DBI_IOCALL])
				{
					//invoke callback to monitor
					if (m_threads.Find(CThreadEvent(), &fuzz_thread))
					{
						if (m_epHook.IsHooked())
						{
							LOADED_IMAGE hook(m_epHook.GetAddrToHook());

							m_epHook.UninstallHook();

							if (m_loadedImgs.Find(hook, &img))
							{
								return fuzz_thread->EventCallback(img, reg, m_loadedImgs);
							}
							else
							{
								DbgPrint("\nnot found!!!!");
								KeBreak();
							}
						}

						return fuzz_thread->EventCallback(img, reg, m_loadedImgs);
					}
					KeBreak();
				}
			}
		}
		else
		{
			KeBreak();
			fuzz_thread = NULL;
			(void)m_threads.Find(CThreadEvent((HANDLE)reg[DBI_FUZZAPP_THREAD_ID], NULL), &fuzz_thread);
			if (fuzz_thread)
			{
				if (m_epHook.IsHooked())
					m_epHook.UninstallHook();
				if (fuzz_thread->MonitorFastCall(img, reg))
				{
					return true;
				}
			}
		}
	}


	//temporary for demo
	if (0x2340000 == (ULONG_PTR)fault_addr)
		return false;

	if (0x2340002 == (ULONG_PTR)fault_addr)
		KeBreak();

	if (m_nonWritePages.Find(CMemoryRange(fault_addr, sizeof(BYTE))))
	{
		KeBreak();
		m_nonWritePages.Pop(CMemoryRange(fault_addr, sizeof(BYTE)));
		if (!CMMU::IsWriteable(fault_addr))
		{
			CMMU::SetWriteable(fault_addr, sizeof(ULONG_PTR));
			//+set trap after instruction + clear BTF, to set unwriteable!

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
