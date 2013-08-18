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


//---------------------------------------------------------------------
// ****************** DBI PROC ENVIROMENT WATCH DOGS ******************
//---------------------------------------------------------------------

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
		(void)m_threads.Push(thread_info);
	else
		(void)m_threads.Pop(thread_info);

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
		(void)m_threads.Push(thread_info);
	else
		(void)m_threads.Pop(thread_info);

	DbgPrint("\n REMOTE!ThreadNotifyRoutine %x %p %s\n", parentProcessId, PsGetCurrentProcess(), !!create ? "start" : "exit");
}


//--------------------------------------------------------------
// ****************** DBI MEMORY MNGMNT UTILS ******************
//--------------------------------------------------------------

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
				!fuzz_thread->Stack().IsInRange(reinterpret_cast<ULONG_PTR*>(fuzz_thread->LastMemoryInfo.Memory)))
			{
				SetUnwriteable(fuzz_thread->LastMemoryInfo.Memory, fuzz_thread->LastMemoryInfo.Size);
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


//-----------------------------------------------------------------
// ****************** DBI TOOL API COMMUNICATION ******************
//-----------------------------------------------------------------

__checkReturn
bool CProcess2Fuzz::PageFault( 
	__in BYTE* faultAddr, 
	__inout ULONG_PTR reg[REG_COUNT],
	__in_opt BRANCH_INFO* branchInfo /* = NULL */
	)
{
	if (PsGetCurrentProcessId() == m_processId)
	{
		void* ep_hook = reinterpret_cast<void*>((ULONG_PTR)m_mainImg->Image().Begin() + m_mainImg->EntryPoint());
		if (!m_installed && m_mainImg && m_extRoutines[ExtMain])
		{
			m_installed = m_mainImg->SetUpNewRelHook(ep_hook, m_extRoutines[ExtMain]);

			if (m_installed) DbgPrint("\nHook set at : %p\n", ep_hook);
		}
	}

	if (R3CommPipe(faultAddr, reg, branchInfo))
		return true;

	if (PsGetCurrentProcessId() == m_processId)
	{
		if (m_nonWritePages.Find(CMemoryRange(faultAddr, sizeof(BYTE))))
		{
			//KeBreak();
			DbgPrint("\nnon-writeable back to writeable!!\n");
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
	__inout ULONG_PTR reg[REG_COUNT],
	__in BRANCH_INFO* branchInfo
	)
{
	IRET* iret = PPAGE_FAULT_IRET(reg);

	if (FAST_CALL == (ULONG_PTR)iret->Return)
	{
		DbgPrint("\nHV FastIOCall - callback");
		KeBreak();
		return false;
	}

	//should be encapsulated under if (FAST_CALL == reg[DBI_IOCALL]) + second if, under if (PsGetCurrentProcessId() == m_processId)
	if (iret->Return == faultAddr)
	{
		if (PsGetCurrentProcessId() != m_processId)
		{
			DbgPrint("\nstrange page fault\n");
			KeBreak();
		}

		if (!branchInfo)
		{
			KeBreak();
			return false;
		}


		CThreadEvent* fuzz_thread;
		if (!m_threads.Find(CThreadEvent(), &fuzz_thread))
		{
			DbgPrint("\nunknown thread\n");
			KeBreak();
		}

		if (iret->Return == branchInfo->StackPtr)
		{
			DbgPrint("\n!!SmartTracer! %p == %s\n", iret->Return, m_stacks.Find(reinterpret_cast<const ULONG_PTR*>(iret->Return)) ? "in stacks..." : "not in stack ?!");

			if (!fuzz_thread->Stack().IsInRange(reinterpret_cast<const ULONG_PTR*>(iret->Return)))
			{
				DbgPrint("\nnot resolved stack range!!\n");
				KeBreak();
			}
			//handle branch tracing - callback from HV
			iret->Return = m_extRoutines[ExtTrapTrace];
			return true;
		}
	}

	if (FAST_CALL == reg[DBI_IOCALL])
	{
		if (m_loadedImgs.Find(CIMAGEINFO_ID(iret->Return)) &&
			(ULONG_PTR)iret->Return + SIZEOF_DBI_FASTCALL == reg[DBI_R3TELEPORT])
		{
			DbgPrint("\n reg[DBI_RETURN] %p [%p]", iret->Return, reg[DBI_RETURN]);

			if (PsGetCurrentProcessId() == m_processId)
			{
				CThreadEvent* fuzz_thread;
				if (m_threads.Find(CThreadEvent(), &fuzz_thread))
				{
					switch (reg[DBI_ACTION])
					{
					case SYSCALL_HOOK:
						{
							CIMAGEINFO_ID* img;
							if (m_loadedImgs.Find(CIMAGEINFO_ID(reinterpret_cast<void*>(reg[DBI_RETURN])), &img))
								return fuzz_thread->HookEvent(img->Value, reg);
						}
						break;
					case  SYSCALL_TRACE_FLAG:
						{
							CIMAGEINFO_ID* img;
							if (m_loadedImgs.Find(CIMAGEINFO_ID(iret->Return), &img))
							{
								//handle x86 -> x64, x64 -> x86 calls
								CIMAGEINFO_ID* img_id;

								CImage* dst_img;
								if (m_loadedImgs.Find(CIMAGEINFO_ID(branchInfo->DstEip), &img_id) && img_id->Value)
								{
									dst_img = img_id->Value;
									CImage* src_img;
									if (m_loadedImgs.Find(CIMAGEINFO_ID(branchInfo->SrcEip), &img_id) && img_id->Value)
									{
										src_img = img_id->Value;

										if (src_img->Is64() != dst_img->Is64() || src_img->IsSystem() || dst_img->IsSystem())
										{
											if (m_loadedImgs.Find(CIMAGEINFO_ID(reinterpret_cast<const void*>(reg[DBI_RETURN])), &img_id) && img_id->Value)
											{
												img_id->Value->SetUpNewRelHook(reinterpret_cast<void*>(reg[DBI_RETURN]), m_extRoutines[ExtMain]);
												branchInfo->Flags &= (~TRAP);
												DbgPrint("-----------> %p %p %p", branchInfo->DstEip, branchInfo->SrcEip, reg[DBI_RETURN]);
											}
										}
									}
								}

								return fuzz_thread->SmartTraceEvent(img->Value, reg, *branchInfo, m_loadedImgs);
							}
						}
						break;
					default:
						DbgPrint("\nuknown DBI ACTION!\n");
						KeBreak();
						break;
					}
				}
			}
			else
			{
				//enum threads ?
				switch (reg[DBI_ACTION])
				{
				case SYSCALL_ENUM_NEXT:
					{
						DbgPrint("SYSCALL_ENUM_NEXT");
						CMdl auto_cid(reinterpret_cast<void*>(reg[DBI_INFO_OUT]), sizeof(CID_ENUM));
						CID_ENUM* cid = reinterpret_cast<CID_ENUM*>(auto_cid.Map());
						if (cid)
						{
							CThreadEvent* fuzz_thread = NULL;

							if (!cid->ThreadId)
								(void)m_threads.Find(CThreadEvent(NULL), &fuzz_thread);
							else
								(void)m_threads.GetNext(CThreadEvent((HANDLE)((ULONG_PTR)cid->ThreadId)), &fuzz_thread);

							if (fuzz_thread)
							{
								cid->ProcId = m_processId;
								cid->ThreadId = fuzz_thread->ThreadId();
							}

							iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);
							return true;
						}
					}
					break;
				case SYSCALL_TRACE_FLAG:
					{
						CThreadEvent* fuzz_thread;
						if (m_threads.Find(CThreadEvent((HANDLE)reg[DBI_FUZZAPP_THREAD_ID], NULL), &fuzz_thread))
							return fuzz_thread->SmartTrace(reg);
					}
					break;
				default:
					break;
				}
				DbgPrint("\nunresolved MONITOR event\n");
				KeBreak();
			}
		}
		else
		{
			DbgPrint("\nstrange IRET %p -> %p\n", iret->Return, reg[DBI_R3TELEPORT]);
			KeBreak();
		}
	}		

	return false;
}
