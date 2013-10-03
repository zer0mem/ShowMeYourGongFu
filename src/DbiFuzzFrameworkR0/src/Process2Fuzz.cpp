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
	KeInitializeEvent(&teste, NotificationEvent, FALSE);
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
			//KeBreak();
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
	__in_opt TRACE_INFO* branchInfo /* = NULL */
	)
{
	ResolveThreads();
	PFIRET* iret = PPAGE_FAULT_IRET(reg);

//HACKY PART OF PAGEFAULT >>> should be moved to more appropriate place ...
	if (FAST_CALL == (ULONG_PTR)iret->Return)
	{
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
			}
			// } ************************** INSTAL EP HOOK ************************** 

			// { ************************** HANDLE HV TRAP EXIT ************************** 
			if (iret->Return == faultAddr)
			{
				//disabled due codecoverme.exe
				//if (fuzz_thread->GetStack().IsInRange(reinterpret_cast<const ULONG_PTR*>(iret->Return)))//codecoverme.exe ohack
				{
					if (iret->Return == branchInfo->StackPtr.Value)
					{
						//handle branch tracing - callback from HV
						KeBreak();
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
	if (FAST_CALL == reg[DBI_IOCALL] && FAST_CALL == (ULONG_PTR)faultAddr)
	{
		KeBreak();
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

					CThreadEvent* fuzz_thread;
					if (GetFuzzThread(PsGetCurrentThreadId(), &fuzz_thread))
						//temporary this set also as valid ... 
						fuzz_thread->RegisterMemoryAccess(faultAddr, iret->ErrorCode, mem->Begin(), mem->GetSize(), mem->GetFlags());

					if (CMMU::IsAccessed(faultAddr))
					{
						CMMU::SetValid(faultAddr, sizeof(ULONG_PTR));
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
	__in TRACE_INFO* branchInfo
	)
{
	CThreadEvent* fuzz_thread;
	if (GetFuzzThread(PsGetCurrentThreadId(), &fuzz_thread))
	{
		CImage* img;
		//reg[RCX] == return from syscall
		if (GetImage(reinterpret_cast<void*>(reg[SReturn]), &img))
		{
			//handle x86 -> x64, x64 -> x86 calls
			if (branchInfo->PrevEip.Value != MM_LOWEST_USER_ADDRESS)
			{
				CImage* dst_img;
				if (GetImage(branchInfo->Eip.Value, &dst_img))
				{
					//CImage* src_img;
					//if (GetImage(branchInfo->PrevEip.Value, &src_img))
					{
						if (m_mainImg->Is64() != dst_img->Is64() || dst_img->IsSystem())
						{
							CImage* target_img;
							if (GetImage(reinterpret_cast<void*>(reg[DBI_RETURN]), &target_img))
							{
								target_img->SetUpNewRelHook(reinterpret_cast<void*>(reg[DBI_RETURN]), m_extRoutines[ExtHook]);
								branchInfo->Flags.Value &= (~TRAP);
								//DbgPrint("-----------> %p %p %p", branchInfo->Eip.Value, branchInfo->PrevEip.Value, reg[DBI_RETURN]);

							}
						}

						/*
						DbgPrint("\n EventCallback <SYSCALL_TRACE_FLAG : %p)> : >> %p -%x [%ws (%s)] %p -%x [%ws (%s)] | dbg -> %ws //%p\n", 
							branchInfo->Flags,
							branchInfo->PrevEip, (ULONG_PTR)branchInfo->PrevEip.Value - (ULONG_PTR)src_img->Image().Begin(), src_img->ImageName().Buffer, src_img->Is64() ? "x64" : "x86",
							branchInfo->Eip, (ULONG_PTR)branchInfo->Eip.Value - (ULONG_PTR)dst_img->Image().Begin(), dst_img->ImageName().Buffer, dst_img->Is64() ? "x64" : "x86",
							img->ImageName().Buffer,  
							reg[DBI_RETURN]);
						*/
					}
				}
			}
			else
			{
				CMemoryRange* mem;
				if (fuzz_thread->GetMemory2Watch(fuzz_thread->GetMemoryAccess().Memory.Value, sizeof(ULONG_PTR), &mem) &&
					!mem->MatchFlags(DIRTY_FLAG))
				{
					mem->SetFlags(mem->GetFlags() | DIRTY_FLAG);
					CMMU::SetInvalid(fuzz_thread->GetMemoryAccess().Memory.Value, sizeof(ULONG_PTR));
				}
			}

			return fuzz_thread->SmartTraceEvent(reg, *branchInfo);
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
	CMdl auto_cid(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(CID_ENUM));
	CID_ENUM* cid = reinterpret_cast<CID_ENUM*>(auto_cid.WritePtrUser());
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
	MODULE_ENUM* module = reinterpret_cast<MODULE_ENUM*>(auto_module.WritePtrUser());
	if (module)
	{
		IMAGE* img = NULL;
		if (!module->ImageBase.Value)
			(void)m_loadedImgs.Find(CRange<void>(module->ImageBase.Value), &img);
		else
			(void)m_loadedImgs.GetNext(CRange<void>(module->ImageBase.Value), &img);

		if (img && img->Value)
		{
			module->ImageBase.Value = img->Value->Image().Begin();
			module->ImageSize.Value = img->Value->Image().GetSize();
			module->Is64.Value = img->Value->Is64();
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
	CMdl auto_api_param(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(PARAM_API));
	PARAM_API* api_param = reinterpret_cast<PARAM_API*>(auto_api_param.WritePtr());
	if (api_param)
	{
		CImage* img;
		if (GetImage(api_param->ModuleBase.Value, &img))
		{
			CEProcess eprocess(m_processId);
			CAutoEProcessAttach attach(eprocess);
			if (eprocess.IsAttached())
			{
				api_param->ApiAddr.Value = CPE::GetProcAddressSafe(api_param->ApiName.Value, img->Image().Begin());
				return true;
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
		CMdl mdl_dbg(params.Dst.Value, params.Size.Value);
		void* dst = mdl_dbg.WritePtr();
		if (dst)
		{
			CEProcess eprocess(m_processId);
			CAutoEProcessAttach attach(eprocess);
			if (eprocess.IsAttached())
			{
				CMdl mdl_mntr(params.Src.Value, params.Size.Value);
				const void* src = mdl_mntr.ReadPtr();
				if (src)
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
bool CProcess2Fuzz::DbiPatchMemory( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	PARAM_MEMCOPY params;
	if (ReadParamBuffer<PARAM_MEMCOPY>(reg, &params))
	{
		CMdl mdl_mntr(params.Src.Value, params.Size.Value);
		const void* src = mdl_mntr.ReadPtr();
		if (src)
		{
			CEProcess eprocess(m_processId);
			CAutoEProcessAttach attach(eprocess);
			if (eprocess.IsAttached())
			{
				CMdl mdl_dbg(params.Dst.Value, params.Size.Value);
				void* dst = mdl_dbg.WritePtr();
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
bool CProcess2Fuzz::DbiSetHook( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	PARAM_HOOK params;
	if (ReadParamBuffer<PARAM_HOOK>(reg, &params))
	{
		CImage* img;
		if (GetImage(params.HookAddr.Value, &img))
		{
			CEProcess eprocess(m_processId);
			CAutoEProcessAttach attach(eprocess);
			if (eprocess.IsAttached())
			{
				return img->SetUpNewRelHook(params.HookAddr.Value, m_extRoutines[ExtHook]);
			}
		}
	}
	return false;
}

//-----------------------------------------------------------------
// ****************** DBI FASTCALL COMMUNICATION ******************
//-----------------------------------------------------------------

__checkReturn
bool CProcess2Fuzz::Syscall( 
	__inout ULONG_PTR reg[REG_COUNT],
	__in_opt TRACE_INFO* branchInfo /* = NULL */
	)
{
	ULONG_PTR ring0rsp = reg[RSP];

	//if x86 then this called from PageFault handler, and RSP is original ...
	if (m_mainImg->Is64())
		reg[RSP] = (ULONG_PTR)(get_ring3_rsp() - 2);

	bool status = false;
	switch ((ULONG)reg[RAX])//DBI_ACTION
	{
	case 0x666:
		KeBreak();

		if (m_processId == PsGetCurrentProcessId())
			status = DbiTraceEvent(reg, branchInfo);
		else
			status = DbiRemoteTrace(reg);

		break;
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

	case SYSCALL_SET_HOOK:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiSetHook(reg);
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

void CProcess2Fuzz::ResolveThreads()
{
	if (m_processId == PsGetCurrentProcessId())
	{
		HANDLE* thread_id = NULL;
		m_unresolvedThreads.Find(NULL, &thread_id);

		if (thread_id)
		{
			do
			{
				THREAD* thread;
				if (m_threads.Find(*thread_id, &thread) && thread->Value)
				{
					CThreadEvent* thread_event = thread->Value;
					if (thread_event->ResolveThread())
					{
						m_loadedImgs.Pop(CRange<void>(thread_event->GetStack().Begin(), thread_event->GetStack().End()));
						m_unresolvedThreads.Pop(*thread_id);
					}
				}
				else
				{
					m_unresolvedThreads.Pop(*thread_id);
				}

			} while(m_unresolvedThreads.GetNext(*thread_id, &thread_id));
		}
	}
}
