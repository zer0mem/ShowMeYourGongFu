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

#define DIRTY_FLAG ((ULONG_PTR)1 << 32)

EXTERN_C void disable_branchtrace();

CProcess2Fuzz::CProcess2Fuzz( 
	__inout PEPROCESS process, 
	__in HANDLE processId, 
	__inout_opt PS_CREATE_NOTIFY_INFO* createInfo 
	) : CProcessContext(process, processId, createInfo),
		m_installed(false)
{
	RtlZeroMemory(m_extRoutines, sizeof(m_extRoutines));
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

void CProcess2Fuzz::ImageNotifyRoutine( 
	__in_opt UNICODE_STRING* fullImageName, 
	__in HANDLE processId,
	__in IMAGE_INFO* imageInfo
	)
{
	CProcessContext::ImageNotifyRoutine(fullImageName, processId, imageInfo);

	IMAGE* img_id;
	CRange<void> img(imageInfo->ImageBase);
	img.SetSize(imageInfo->ImageSize);
	if (m_loadedImgs.Find(img, &img_id) && img_id->Value)
	{
		if (CConstants::GetInstance().InAppModulesAVL().Find(&CHashString(img_id->Value->ImageName())))
		{
			KeBreak();
			CPE pe(imageInfo->ImageBase);
			const void* func_name;
			for (size_t i = 0; (func_name = CConstants::InAppExtRoutines(i)); i++)
				m_extRoutines[i] = pe.GetProcAddress(func_name);
		}
	}
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
	if (m_mem2watch.Find(CMemoryRange(reinterpret_cast<BYTE*>(memory), size)))
	{
		KeBreak();
		CMMU::SetValid(memory, size);
	}

	return false;
}

__checkReturn
bool CProcess2Fuzz::Syscall( 
	__inout ULONG_PTR reg[REG_COUNT],
	__in_opt BRANCH_INFO* branchInfo /* = NULL */
	)
{
	ULONG_PTR ring0rsp = reg[RSP];
	
	//if x86 then this called from PageFault handler, and RSP is original ...
	if (m_mainImg->Is64())
		reg[RSP] = (ULONG_PTR)(get_ring3_rsp() - 2);

	bool status = false;
	switch ((ULONG)reg[RAX])//DBI_ACTION
	{
	case SYSCALL_HOOK:
		if (m_processId == PsGetCurrentProcessId())
			status = DbiHook(reg);
		else//ERROR
			KeBreak();

		break;
	case SYSCALL_TRACE_FLAG:
		if (m_processId == PsGetCurrentProcessId())
			status = DbiTraceEvent(reg, branchInfo);
		else
			status = DbiRemoteTrace(reg);

		break;
	case SYSCALL_ENUM_NEXT:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiEnumThreads(reg);
		else//ERROR
			KeBreak();

		break;
	default:
		break;
	}

	reg[RSP] = ring0rsp;
	if (status)
		return true;

	return CSYSCALL::Syscall(reg);
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
	PFIRET* iret = PPAGE_FAULT_IRET(reg);

//HACKY PART OF PAGEFAULT >>> should be moved to more appropriate place ...
	if (FAST_CALL == (ULONG_PTR)iret->Return)
	{
		DbgPrint("\nHV FastIOCall - callback");
		KeBreak();
		return false;
	}

	if (PsGetCurrentProcessId() == m_processId)
	{
		CThreadEvent* fuzz_thread;
		if (GetFuzzThread(PsGetCurrentThreadId(), &fuzz_thread))
		{
			if (m_unresolvedThreads.Pop(fuzz_thread->ThreadId()))
			{
				if (!fuzz_thread->ResolveStack())
				{
					m_unresolvedThreads.Push(fuzz_thread->ThreadId());
					return false;
				}

				// { ************************** INSTAL EP HOOK ************************** 
				if (!m_installed && m_mainImg && m_extRoutines[ExtHook])
				{
					void* ep_hook = reinterpret_cast<void*>((ULONG_PTR)m_mainImg->Image().Begin() + m_mainImg->EntryPoint());
					m_installed = m_mainImg->SetUpNewRelHook(ep_hook, m_extRoutines[ExtHook]);

					if (m_installed) DbgPrint("\nHook set at : %p\n", ep_hook);
				}
				// } ************************** INSTAL EP HOOK ************************** 
			}

			// { ************************** HANDLE HV TRAP EXIT ************************** 
			if (iret->Return == faultAddr)
			{
				if (fuzz_thread->GetStack().IsInRange(reinterpret_cast<const ULONG_PTR*>(iret->Return)))
				{
					if (iret->Return == branchInfo->StackPtr)
					{
						//handle branch tracing - callback from HV
						iret->Return = m_extRoutines[ExtTrapTrace];
						return true;
					}
				}
			}
			// } ************************** HANDLE HV TRAP EXIT ************************** 
		}
	}
//HACKY PART OF PAGEFAULT >>> should be moved to more appropriate place ...

//X86 specific ...
	if (FAST_CALL == reg[DBI_IOCALL])
	{
		//additional check if it is communication from r3 dbi-monitor
		if ((ULONG_PTR)iret->Return + SIZEOF_DBI_FASTCALL == reg[DBI_R3TELEPORT])
			return Syscall(reg, branchInfo);
	}
//X86 specific ...


// { ************************** HANDLE PROTECTED MEMORY ACCESS ************************** 
	if (PsGetCurrentProcessId() == m_processId)
	{
		if (((ULONG_PTR)faultAddr & 0xFFF) == 0x367)
		{
			CVadScanner vad_scanner(PsGetCurrentThread());
						
			CVadNodeMemRange vad_mem;
			if (vad_scanner.FindVadMemoryRange(faultAddr, &vad_mem))
				(void)m_mem2watch.Push(CMemoryRange(reinterpret_cast<BYTE*>(PAGE_ALIGN(faultAddr)), PAGE_SIZE, vad_mem.GetFlags().UFlags | DIRTY_FLAG));
		}

		CMemoryRange* mem;
		if (m_mem2watch.Find(CMemoryRange(faultAddr, sizeof(BYTE)), &mem))
		{
			if (mem->MatchFlags(DIRTY_FLAG))
			{
				CThreadEvent* fuzz_thread;
				if (GetFuzzThread(PsGetCurrentThreadId(), &fuzz_thread))
					fuzz_thread->SetMemoryAccess(faultAddr, iret->ErrorCode.UErrCode, mem->Begin(), mem->GetSize());

				mem->SetFlags(mem->GetFlags() & ~DIRTY_FLAG);

				//not wrmsr but instead DEBUG REGISTERS!! -> per thread!
				//disable_branchtrace(); //-> VMX.cpp initialize vmm : vmwrite(VMX_VMCS64_GUEST_DR7, 0x400);

				wrmsr(IA32_DEBUGCTL, ~(BTF | LBR));//disable BTF -> special handling for wrmsr in HV
				iret->Flags |= TRAP; 

				//CMMU::SetWriteable(faultAddr, sizeof(ULONG_PTR));
				if (CMMU::IsAccessed(faultAddr))
				{
					CMMU::SetValid(faultAddr, sizeof(ULONG_PTR));
					return true;
				}
			}
		}
	}
// } ************************** HANDLE PROTECTED MEMORY ACCESS ************************** 

	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiHook( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	CThreadEvent* fuzz_thread;
	if (GetFuzzThread(PsGetCurrentThreadId(), &fuzz_thread))
	{
		CImage* img;
		if (GetImage(reinterpret_cast<void*>(reg[DBI_RETURN]), &img))
			return fuzz_thread->HookEvent(img, reg, &m_mem2watch);
	}

	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiTraceEvent( 
	__inout ULONG_PTR reg[REG_COUNT],
	__in BRANCH_INFO* branchInfo
	)
{
	PFIRET* iret = PPAGE_FAULT_IRET(reg);

	CThreadEvent* fuzz_thread;
	if (GetFuzzThread(PsGetCurrentThreadId(), &fuzz_thread))
	{
		CImage* img;
		if (GetImage(iret->Return, &img))
		{
			//handle x86 -> x64, x64 -> x86 calls
			if (branchInfo->SrcEip != MM_LOWEST_USER_ADDRESS)
			{
				branchInfo->Cr2 = NULL;

				CImage* dst_img;
				if (GetImage(branchInfo->DstEip, &dst_img))
				{
					CImage* src_img;
					if (GetImage(branchInfo->SrcEip, &src_img))
					{
						if (src_img->Is64() != dst_img->Is64() || src_img->IsSystem() || dst_img->IsSystem())
						{
							CImage* target_img;
							if (GetImage(reinterpret_cast<void*>(reg[DBI_RETURN]), &target_img))
							{
								target_img->SetUpNewRelHook(reinterpret_cast<void*>(reg[DBI_RETURN]), m_extRoutines[ExtHook]);
								branchInfo->Flags &= (~TRAP);
								DbgPrint("-----------> %p %p %p", branchInfo->DstEip, branchInfo->SrcEip, reg[DBI_RETURN]);

							}
						}


						DbgPrint("\n EventCallback <SYSCALL_TRACE_FLAG : %p)> : >> %p -%x [%ws (%s)] %p -%x [%ws (%s)] | dbg -> %ws //%p\n", 
							branchInfo->Flags,
							branchInfo->SrcEip, (ULONG_PTR)branchInfo->SrcEip - (ULONG_PTR)src_img->Image().Begin(), src_img->ImageName().Buffer, src_img->Is64() ? "x64" : "x86",
							branchInfo->DstEip, (ULONG_PTR)branchInfo->DstEip - (ULONG_PTR)dst_img->Image().Begin(), dst_img->ImageName().Buffer, dst_img->Is64() ? "x64" : "x86",
							img->ImageName().Buffer,  
							reg[DBI_RETURN]);
					}
				}
			}
			else
			{
				DbgPrint("\nLBR OFF\n");
				KeBreak();
				CMemoryRange* mem;
				if (m_mem2watch.Find(CMemoryRange(reinterpret_cast<const BYTE*>(fuzz_thread->GetMemoryAccess().Memory), sizeof(ULONG_PTR)), &mem) &&
					!mem->MatchFlags(DIRTY_FLAG))
				{
					mem->SetFlags(mem->GetFlags() | DIRTY_FLAG);
					DbgPrint("\n II. round : %p %s %s\n", fuzz_thread->GetMemoryAccess().Memory, CMMU::IsValid(fuzz_thread->GetMemoryAccess().Memory) ? "is valid" : "is NOT valid", CMMU::IsAccessed(fuzz_thread->GetMemoryAccess().Memory) ? "is accesed already" : "NOT accesed yet!");
					DbgPrint("\n !!!!!!!!!!!!!!! cr2 is in list .. %p %p\n", fuzz_thread->GetMemoryAccess().Memory, readcr2());
					KeBreak();
					CMMU::SetInvalid(fuzz_thread->GetMemoryAccess().Memory, sizeof(ULONG_PTR));
				}
				else
				{
					DbgPrint("\n cr2 not in list .. %p %p\n", fuzz_thread->GetMemoryAccess().Memory, readcr2());
					KeBreak();
				}
			}

			return fuzz_thread->SmartTraceEvent(img, reg, *branchInfo);
		}

	}
	
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiRemoteTrace( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	CThreadEvent* fuzz_thread;
	if (GetFuzzThread((HANDLE)reg[DBI_FUZZAPP_THREAD_ID], &fuzz_thread))
		return fuzz_thread->SmartTrace(reg);

	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiEnumThreads( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	PFIRET* iret = PPAGE_FAULT_IRET(reg);

	CMdl auto_cid(reinterpret_cast<void*>(reg[DBI_INFO_OUT]), sizeof(CID_ENUM));
	CID_ENUM* cid = reinterpret_cast<CID_ENUM*>(auto_cid.Map());
	if (cid)
	{
		THREAD* thread = NULL;
		if (!cid->ThreadId.Value)
			(void)m_threads.Find(NULL, &thread);
		else
			(void)m_threads.GetNext(cid->ThreadId.Value, &thread);

		if (thread && thread->Value)
		{
			cid->ProcId.Value = m_processId;
			cid->ThreadId.Value = thread->Value->ThreadId();
		}

		iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);
		return true;
	}
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiEnumMemory( 
	__inout ULONG_PTR reg[REG_COUNT]
)
{
	PFIRET* iret = PPAGE_FAULT_IRET(reg);

	CMdl auto_mem(reinterpret_cast<void*>(reg[DBI_INFO_OUT]), sizeof(MEMORY_ENUM));
	MEMORY_ENUM* mem = reinterpret_cast<MEMORY_ENUM*>(auto_mem.Map());
	if (mem)
	{
		CVadScanner vad_scanner(PsGetCurrentThread());

		CVadNodeMemRange vad_mem;
		//NULL is equivalent getlowerbound
		if (vad_scanner.GetNextVadMemoryRange(mem->Begin.Value, &vad_mem))
		{
			mem->Begin.Value = vad_mem.Begin();
			mem->Size.Value = vad_mem.GetSize();
			mem->Flags.Value = vad_mem.GetFlags().UFlags;
		}

		iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);
		return true;
	}
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiWatchMemoryAccess( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	PFIRET* iret = PPAGE_FAULT_IRET(reg);

	DbgPrint("\n I. currthread : %p ", PsGetCurrentThreadId());
	CEProcess eprocess(m_processId);
	CAutoEProcessAttach process(eprocess);

	if (eprocess.IsAttached())
	{
		DbgPrint(" > II. currthread : %p ", PsGetCurrentThreadId());
		KeBreak();

		THREAD* thread;
		(void)m_threads.Find(NULL, &thread);
		//is at least one thread ready ?
		if (thread && thread->Value)
		{
			//get the first one ... in the future, maybe mwatch acces per thread different memories ...
			HANDLE thread_id = thread->Value->ThreadId();
			CEthread ethread(thread_id);
			if (ethread.Initialize())
			{
				//for now support just aligned watching .. in other case more processing needed ...
				BYTE* mem2watch = reinterpret_cast<BYTE*>(PAGE_ALIGN(reg[DBI_MEM2WATCH]));
				size_t size = ALIGN(reg[DBI_SIZE2WATCH] + (reg[DBI_MEM2WATCH] - (ULONG_PTR)mem2watch) + PAGE_SIZE, PAGE_SIZE);

				CVadNodeMemRange vad_mem;
				if (ethread.VadScanner().FindVadMemoryRange(mem2watch, &vad_mem))
				{
					if (m_mem2watch.Push(CMemoryRange(mem2watch, size, vad_mem.GetFlags().UFlags | DIRTY_FLAG)))
					{
						for (size_t page_walker = 0; page_walker < size; page_walker += PAGE_SIZE)
							if (CMMU::IsAccessed(mem2watch + page_walker))
								CMMU::SetInvalid(mem2watch + page_walker, PAGE_SIZE);
					}
				}
				iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

				return true;
			}
		}
	}

	return false;
}
