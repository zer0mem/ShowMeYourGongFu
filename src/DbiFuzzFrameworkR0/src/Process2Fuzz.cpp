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

#include "../HyperVisor/Common/base/HVCommon.h"

CProcess2Fuzz::CProcess2Fuzz( 
	__inout PEPROCESS process, 
	__in HANDLE processId, 
	__inout_opt PS_CREATE_NOTIFY_INFO* createInfo 
	) : CProcessContext(process, processId, createInfo),
		m_mainImg(NULL),
		m_internalError(false),
		m_installed(false)
{
	RtlZeroMemory(m_extRoutines, sizeof(m_extRoutines));
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
		if (ResolveImageName(
				createInfo->ImageFileName->Buffer, 
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
	if (m_internalError)
		return;

	if (!imageInfo->SystemModeImage)
	{
		CImage* img = new CImage(fullImageName, imageInfo);
		if (img)
		{
			CIMAGEINFO_ID img_id(img->Image(), img);

			//drop overlapped images; handle unhook in ~coldpatch -> now it is unloaded img, unhooking == badidea
			while (m_loadedImgs.Pop(img_id));

			if (m_loadedImgs.Push(img_id))
			{
				img_id.Value = NULL;
				if (!m_mainImg)
					m_mainImg = img;

				if (CConstants::GetInstance().InAppModulesAVL().Find(&CHashString(img->ImageName())))
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
				}
			}
			else
			{
				if (!m_mainImg)
					m_internalError = true;
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

#include "DbiMonitor.h"

__checkReturn
bool CProcess2Fuzz::PageFault( 
	__in BYTE* faultAddr, 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	void* ep_hook = reinterpret_cast<void*>((ULONG_PTR)m_mainImg->Image().Begin() + m_mainImg->EntryPoint());
	if (!m_installed && m_mainImg && m_extRoutines[ExtMain])
		m_mainImg->SetUpNewRelHook(ep_hook, m_extRoutines[ExtMain]);
	
	if ((ULONG_PTR)faultAddr == FAST_CALL)
	{
		return R3CommPipe(faultAddr, reg);
	}
#if 0
	else//if TRAP is set fot PsGetCurrentThread() ... 
	{
		
	/*
	 * 8 Trap Flag 
	   (1) A single-step interrupt will occur after every instruction.
	   (0) Normal instruction execution  

	   !!!
	   ** Note: Trap Flag is always cleared when an 
	   interrupt is generated either by software or 
	   hardware.
	   !!!
	*/

		CThreadEvent* fuzz_thread;
		if (m_threads.Find(CThreadEvent(PsGetCurrentThreadId()), &fuzz_thread))
		{
			if (CDbiMonitor::GetInstance().GetBranchStack().IsEmpty() && fuzz_thread->IsTrapSet())
			{
				DbgPrint("\npagefault at : %p\n", faultAddr);
				KeBreak();
				IRET* iret = PPAGE_FAULT_IRET(reg);
				//iret->Flags |= TRAP;

				BRANCH_INFO branch_i;
				branch_i.DstEip = iret->Return;
				branch_i.SrcEip = iret->Return;
				branch_i.Flags = iret->Flags;
				CDbiMonitor::GetInstance().GetBranchStack().Push(branch_i);

				iret->Return = reinterpret_cast<const void*>(FAST_CALL);
				return false;
			}
		}
	}
#endif

	if (PsGetCurrentProcessId() == m_processId)
	{
		if (m_nonWritePages.Find(CMemoryRange(faultAddr, sizeof(BYTE))))
		{
			KeBreak();
			m_nonWritePages.Pop(CMemoryRange(faultAddr, sizeof(BYTE)));
			if (!CMMU::IsWriteable(faultAddr))
			{
				CMMU::SetWriteable(faultAddr, sizeof(ULONG_PTR));
				//+set trap after instruction + clear BTF, to set unwriteable!

				//sync problem, not locked and acces via ref, via ref counting ...
				return true;
			}
		}
	}

	return false;
}

__checkReturn
bool CProcess2Fuzz::R3CommPipe( 
	__in BYTE* faultAddr, 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	IRET* iret = PPAGE_FAULT_IRET(reg);

	if (FAST_CALL == (ULONG_PTR)iret->Return)
	{
		DbgPrint("\nHV FastIOCall - callback");
		//handle branch tracing - callback from HV
		iret->Return = m_extRoutines[ExtTrapTrace];
		if (iret->Flags & TRAP)
		{
			DbgPrint("\nbad mistake %p %x\n", &iret->Flags, iret->Flags);
			KeBreak();
		}
		iret->Flags &= (~TRAP);
		return true;
	}

	if (FAST_CALL == reg[DBI_IOCALL])
	{
		DbgPrint("\n reg[DBI_RETURN] %p ", reg[DBI_RETURN]);
		CIMAGEINFO_ID* img_id;
		if (m_loadedImgs.Find(CIMAGEINFO_ID(CRange<void>(iret->Return)), &img_id))
		{
			CImage* img = img_id->Value;
			CThreadEvent* fuzz_thread;
			if (PsGetCurrentProcessId() == m_processId)
			{
				//invoke callback to monitor
				if (m_threads.Find(CThreadEvent(), &fuzz_thread))
					return fuzz_thread->EventCallback(img, reg, m_loadedImgs);

				//not suposed to get here
				DbgPrint("\nUnresolved EventCallback .. wtf\n");
				KeBreak();
			}
			else
			{
				if (SYSCALL_ENUM_NEXT == reg[DBI_ACTION])
				{
					CMdl auto_cid(reinterpret_cast<void*>(reg[DBI_INFO_OUT]), sizeof(CID_ENUM));
					CID_ENUM* cid = reinterpret_cast<CID_ENUM*>(auto_cid.Map());
					if (cid)
					{
						fuzz_thread = NULL;

						if (!cid->ThreadId)
							(void)m_threads.Find(CThreadEvent(NULL), &fuzz_thread);
						else
							(void)m_threads.GetNext(CThreadEvent((HANDLE)((ULONG_PTR)cid->ThreadId)), &fuzz_thread);

						if (fuzz_thread)
						{
							cid->ProcId = m_processId;
							cid->ThreadId = fuzz_thread->ThreadId();
						}

						iret->Return = reinterpret_cast<const void*>((ULONG_PTR)iret->Return + SIZEOF_DBI_FASTCALL);
						return true;
					}
				}
				else
				{
					fuzz_thread = NULL;
					(void)m_threads.Find(CThreadEvent((HANDLE)reg[DBI_FUZZAPP_THREAD_ID], NULL), &fuzz_thread);
					if (fuzz_thread)
					{
						return fuzz_thread->MonitorFastCall(img, reg);
					}
				}
			}
		}
		else
		{
			DbgPrint("\n m_loadedImgs.Find fail ");
			KeBreak();
		}
	}

	return false;
}
