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
	CThreadEvent* fuzz_thread;
	if (GetFuzzThread(PsGetCurrentThreadId(), &fuzz_thread))
	{
		if (fuzz_thread->IsMemory2Watch(memory, size))
		{
			KeBreak();
			CMMU::SetValid(memory, size);
		}
	}

	return false;
}

//--------------------------------------------------------
// ****************** DBI TARGET EVENTS ******************
//--------------------------------------------------------

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
			// { ************************** INSTAL EP HOOK ************************** 
			if (!m_installed && m_mainImg && m_extRoutines[ExtHook])
			{
				void* ep_hook = reinterpret_cast<void*>((ULONG_PTR)m_mainImg->Image().Begin() + m_mainImg->EntryPoint());
				m_installed = m_mainImg->SetUpNewRelHook(ep_hook, m_extRoutines[ExtHook]);

				if (m_installed) DbgPrint("\nHook set at : %p\n", ep_hook);
			}
			// } ************************** INSTAL EP HOOK ************************** 

			// { ************************** HANDLE HV TRAP EXIT ************************** 
			if (iret->Return == faultAddr)
			{
				//disabled due codecoverme.exe
				//if (fuzz_thread->GetStack().IsInRange(reinterpret_cast<const ULONG_PTR*>(iret->Return)))
				{
					if (iret->Return == branchInfo->StackPtr.Value)
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
		CThreadEvent* fuzz_thread;
		if (GetFuzzThread(PsGetCurrentThreadId(), &fuzz_thread))
		{

			if (((ULONG_PTR)faultAddr & 0xFFF) == 0x367)
			{
				CVadScanner vad_scanner(PsGetCurrentThread());

				CVadNodeMemRange vad_mem;
				if (vad_scanner.FindVadMemoryRange(faultAddr, &vad_mem))
					fuzz_thread->insert_tmp(CMemoryRange(reinterpret_cast<BYTE*>(PAGE_ALIGN(faultAddr)), PAGE_SIZE, vad_mem.GetFlags().UFlags | DIRTY_FLAG));
			}

			CMemoryRange* mem;
			if (fuzz_thread->GetMemory2Watch(faultAddr, sizeof(ULONG_PTR), &mem))
			{
				if (mem->MatchFlags(DIRTY_FLAG))
				{

					mem->SetFlags(mem->GetFlags() & ~DIRTY_FLAG);

					//disable BTF : not wrmsr but instead DEBUG REGISTERS!! -> per thread!
					//disable_branchtrace(); //-> VMX.cpp initialize vmm : vmwrite(VMX_VMCS64_GUEST_DR7, 0x400);

					wrmsr(IA32_DEBUGCTL, ~(BTF | LBR));//disable BTF -> special handling for wrmsr in HV
					iret->Flags |= TRAP; 

					if (CMMU::IsAccessed(faultAddr))
					{
						CMMU::SetValid(faultAddr, sizeof(ULONG_PTR));

						CThreadEvent* fuzz_thread;
						if (GetFuzzThread(PsGetCurrentThreadId(), &fuzz_thread))
							fuzz_thread->SetMemoryAccess(faultAddr, iret->ErrorCode, mem->Begin(), mem->GetSize(), mem->GetFlags());

						return true;
					}
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
			return fuzz_thread->HookEvent(img, reg);
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
			if (branchInfo->SrcEip.Value != MM_LOWEST_USER_ADDRESS)
			{
				branchInfo->Cr2.Value = NULL;

				CImage* dst_img;
				if (GetImage(branchInfo->DstEip.Value, &dst_img))
				{
					CImage* src_img;
					if (GetImage(branchInfo->SrcEip.Value, &src_img))
					{
						if (m_mainImg->Is64() != dst_img->Is64() || dst_img->IsSystem())
						{
							CImage* target_img;
							if (GetImage(reinterpret_cast<void*>(reg[DBI_RETURN]), &target_img))
							{
								target_img->SetUpNewRelHook(reinterpret_cast<void*>(reg[DBI_RETURN]), m_extRoutines[ExtHook]);
								branchInfo->Flags.Value &= (~TRAP);
								DbgPrint("-----------> %p %p %p", branchInfo->DstEip.Value, branchInfo->SrcEip.Value, reg[DBI_RETURN]);

							}
						}


						DbgPrint("\n EventCallback <SYSCALL_TRACE_FLAG : %p)> : >> %p -%x [%ws (%s)] %p -%x [%ws (%s)] | dbg -> %ws //%p\n", 
							branchInfo->Flags,
							branchInfo->SrcEip, (ULONG_PTR)branchInfo->SrcEip.Value - (ULONG_PTR)src_img->Image().Begin(), src_img->ImageName().Buffer, src_img->Is64() ? "x64" : "x86",
							branchInfo->DstEip, (ULONG_PTR)branchInfo->DstEip.Value - (ULONG_PTR)dst_img->Image().Begin(), dst_img->ImageName().Buffer, dst_img->Is64() ? "x64" : "x86",
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
				if (fuzz_thread->GetMemory2Watch(fuzz_thread->GetMemoryAccess().Memory.Value, sizeof(ULONG_PTR), &mem) &&
					!mem->MatchFlags(DIRTY_FLAG))
				{
					mem->SetFlags(mem->GetFlags() | DIRTY_FLAG);
					DbgPrint("\n II. round : %p %s %s\n", fuzz_thread->GetMemoryAccess().Memory, CMMU::IsValid(fuzz_thread->GetMemoryAccess().Memory.Value) ? "is valid" : "is NOT valid", CMMU::IsAccessed(fuzz_thread->GetMemoryAccess().Memory.Value) ? "is accesed already" : "NOT accesed yet!");
					DbgPrint("\n !!!!!!!!!!!!!!! cr2 is in list .. %p %p\n", fuzz_thread->GetMemoryAccess().Memory, readcr2());
					KeBreak();
					CMMU::SetInvalid(fuzz_thread->GetMemoryAccess().Memory.Value, sizeof(ULONG_PTR));
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

//------------------------------------------------------------
// ****************** DBI MONITOR CALLBACKS ******************
//------------------------------------------------------------

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

	CMdl auto_cid(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(CID_ENUM));
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
	CThreadEvent* fuzz_thread;
	if (GetFuzzThread((HANDLE)reg[DBI_FUZZAPP_THREAD_ID], &fuzz_thread))
		return fuzz_thread->EnumMemory(reg);	
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiWatchMemoryAccess( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	CThreadEvent* fuzz_thread;
	if (GetFuzzThread((HANDLE)reg[DBI_FUZZAPP_THREAD_ID], &fuzz_thread))
		return fuzz_thread->WatchMemoryAccess(reg);

	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiInit( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	CThreadEvent* fuzz_thread;
	if (GetFuzzThread((HANDLE)reg[DBI_FUZZAPP_THREAD_ID], &fuzz_thread))
	{
		CEProcess eprocess(m_processId);
		CAutoEProcessAttach attach(eprocess);
		if (eprocess.IsAttached())
			return fuzz_thread->Init(reg);
	}

	return false;
}

NTSYSAPI 
NTSTATUS 
NTAPI 
ZwSuspendThread( IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount OPTIONAL );

__checkReturn
bool CProcess2Fuzz::DbiSuspendThread( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	return false;
	/*
	CThreadEvent* fuzz_thread;
	if (GetFuzzThread((HANDLE)reg[DBI_FUZZAPP_THREAD_ID], &fuzz_thread))
	{
		PPAGE_FAULT_IRET(reg)->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);
		return NT_SUCCESS(ZwSuspendThread(fuzz_thread->ThreadId(), NULL));
	}
	return false;
	*/
}

__checkReturn
bool CProcess2Fuzz::DbiEnumModules( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	CMdl auto_module(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(MODULE_ENUM));
	MODULE_ENUM* module = reinterpret_cast<MODULE_ENUM*>(auto_module.Map());
	if (module)
	{
		PPAGE_FAULT_IRET(reg)->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

		IMAGE* img = NULL;
		if (!module->ImageBase.Value)
			(void)m_loadedImgs.Find(CRange<void>(NULL), &img);
		else
			(void)m_loadedImgs.GetNext(CRange<void>(module->ImageBase.Value), &img);

		if (img && img->Value)
		{
			module->ImageBase.Value = img->Value->Image().Begin();
			module->ImageSize.Value = img->Value->Image().GetSize();
			RtlZeroMemory(&module->ImageName.Value, sizeof(module->ImageName.Value));
			if (img->Value->ImageName().Length < sizeof(module->ImageName.Value))
				memcpy(&module->ImageName.Value, img->Value->ImageName().Buffer, img->Value->ImageName().Length);
		}

		return true;
	}
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiGetProcAddress( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	CMdl auto_api_param(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(MODULE_ENUM));
	PARAM_API* api_param = reinterpret_cast<PARAM_API*>(auto_api_param.Map());
	if (api_param)
	{
		PPAGE_FAULT_IRET(reg)->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

		CImage* img;
		if (GetImage(api_param->ModuleBase.Value, &img))
		{
			CEProcess eprocess(m_processId);
			CAutoEProcessAttach attach(eprocess);
			if (eprocess.IsAttached())
			{
				CMdl image_map(img->Image().Begin(), img->Image().GetSize());
				const void* img_base = image_map.Map();
				if (img_base)
				{
					CPE mz(img_base);
					if (mz.IsValid())
					{
						void* func_addr = mz.GetProcAddress(api_param->ApiName.Value);
						if (func_addr)
						{
							api_param->ApiAddr.Value = func_addr;
							return true;
						}
					}
				}
				else
				{
					KeBreak();
				}
			}
		}
	}
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiDumpMemory( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	PARAM_MEMCOPY params;
	if (ReadParamBuffer<PARAM_MEMCOPY>(reg, &params))
	{
		PPAGE_FAULT_IRET(reg)->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

		CMdl mdl_dbg(params.Dst.Value, params.Size.Value);
		void* dst = mdl_dbg.Map();
		if (dst)
		{
			CEProcess eprocess(m_processId);
			CAutoEProcessAttach attach(eprocess);
			if (eprocess.IsAttached())
			{
				CMdl mdl_mntr(params.Src.Value, params.Size.Value);
				void* src = mdl_mntr.Map();
				if (src)
				{
					memcpy(dst, src,params.Size.Value);
					return true;
				}
			}
		}
	}
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiPatchMemory( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	PARAM_MEMCOPY params;
	if (ReadParamBuffer<PARAM_MEMCOPY>(reg, &params))
	{
		PPAGE_FAULT_IRET(reg)->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

		CMdl mdl_mntr(params.Src.Value, params.Size.Value);
		void* src = mdl_mntr.Map();
		if (src)
		{
			CEProcess eprocess(m_processId);
			CAutoEProcessAttach attach(eprocess);
			if (eprocess.IsAttached())
			{
				CMdl mdl_dbg(params.Dst.Value, params.Size.Value);
				void* dst = mdl_dbg.Map();
				if (dst)
				{
					memcpy(dst, src, params.Size.Value);
					return true;
				}
			}
		}
	}
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiSetEip( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiSetHook( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	PARAM_HOOK params;
	if (ReadParamBuffer<PARAM_HOOK>(reg, &params))
	{
		PPAGE_FAULT_IRET(reg)->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

		CImage* img;
		if (GetImage(params.HookAddr.Value, &img))
		{
			CEProcess eprocess(m_processId);
			CAutoEProcessAttach attach(eprocess);
			if (eprocess.IsAttached())
			{
				img->SetUpNewRelHook(params.HookAddr.Value, m_extRoutines[ExtHook]);
				return true;
			}
		}
	}
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiRun( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	return false;
}


//-----------------------------------------------------------------
// ****************** DBI FASTCALL COMMUNICATION ******************
//-----------------------------------------------------------------

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
	case SYSCALL_ENUM_THREAD:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiEnumThreads(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_INIT:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiInit(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_PATCH_MEMORY:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiPatchMemory(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_DUMP_MEMORY:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiDumpMemory(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_ENUM_MODULES:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiEnumModules(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_ENUM_MEMORY:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiEnumMemory(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_WATCH_MEMORY:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiWatchMemoryAccess(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_GETPROCADDR:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiGetProcAddress(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_SET_EIP:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiSetEip(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_SET_HOOK:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiSetHook(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_RUN:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiRun(reg);
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
