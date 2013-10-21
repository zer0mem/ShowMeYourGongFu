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
			//KeBreak();
			CPE pe(imageInfo->ImageBase);
			const void* func_name;
			for (size_t i = 0; (func_name = CConstants::InAppExtRoutines(i)); i++)
				m_extRoutines[i] = pe.GetProcAddress(func_name);

			DbgPrint("\n#######################################\n# CODECOVERME.EXE ID %p\n#######################################", PsGetCurrentProcessId());
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
		if (m_mem2watch.Find(CMemoryRange(static_cast<BYTE*>(memory), size)))
			CMMU::SetValid(memory, size);
	}

	return false;
}

//--------------------------------------------------------
// ****************** DBI TARGET EVENTS ******************
//--------------------------------------------------------

#include "DbiMonitor.h"

__checkReturn
bool CProcess2Fuzz::PageFault( 
	__in BYTE* faultAddr, 
	__inout ULONG_PTR reg[REG_COUNT]
	)
{
	ResolveThreads();
	PFIRET* pf_iret = PPAGE_FAULT_IRET(reg);
	
	if (PsGetCurrentProcessId() == m_processId)
	{
		CThreadEvent* fuzz_thread;
		if (GetFuzzThread(PsGetCurrentThreadId(), &fuzz_thread))
		{
			//TODO : if no monitor-thread paired then just freeze this thread!!

			// { ************************** HANDLE HV TRAP EXIT ************************** 
			if (faultAddr == pf_iret->IRet.Return)
			{
				//if rip potentionaly points to kernel mode
				if (!CRange<void>(MM_LOWEST_USER_ADDRESS, MM_HIGHEST_USER_ADDRESS).IsInRange(pf_iret->IRet.Return))
				{
					//try except blog ? -> indeed use this address as ptr to kernel struct-> 
					//TODO : check if it is really our kernel object !!!!!
					const CAutoTypeMalloc<TRACE_INFO>* trace_info = reinterpret_cast< const CAutoTypeMalloc<TRACE_INFO>* >(pf_iret->IRet.Return);
					if (fuzz_thread->GetStack().IsInRange(trace_info->GetMemory()->StateInfo.IRet.StackPointer))
					{
						fuzz_thread->SmartTraceEvent(reg, trace_info->GetMemory(), pf_iret);

						//TEST INT3 system of hooks
						if (!(trace_info->GetMemory()->StateInfo.IRet.Flags & TRAP))
						{
							CImage* img;
							GetImage(trace_info->GetMemory()->StateInfo.IRet.Return, &img);
							if (img->IsHooked(trace_info->GetMemory()->StateInfo.IRet.Return))
							{
								DbgPrint("\nunhooking processing\n");
								img->UninstallHook(trace_info->GetMemory()->StateInfo.IRet.Return);
							}
							else
							{
								DbgPrint("\nunhooking failed\n");
							}
						}

						//push back to trace_info queue
						CDbiMonitor::m_branchInfoQueue.Push(const_cast<CAutoTypeMalloc<TRACE_INFO>*>(trace_info));
						//handle branch tracing - callback from HV
						pf_iret->IRet.Return = const_cast<void*>(m_extRoutines[ExtWaitForDbiEvent]);

						return true;
					}
				}
			}
			// } ************************** HANDLE HV TRAP EXIT ************************** 

			// { ************************** HANDLE PROTECTED MEMORY ACCESS ************************** 
			CMemoryRange* mem;
			if (m_mem2watch.Find(CMemoryRange(faultAddr, sizeof(ULONG_PTR)), &mem))//bullshit, what if another thread raise to this point ??
			{
				fuzz_thread->RegisterMemoryAccess(reg, faultAddr, mem, pf_iret);

				pf_iret->IRet.Return = const_cast<void*>(m_extRoutines[ExtWaitForDbiEvent]);
				return true;
			}
			// } ************************** HANDLE PROTECTED MEMORY ACCESS ************************** 
		}
	}
	return false;
}

/////////////////////////////////////////////////////////////////////////////////////
///							TRACER - tracing
/////////////////////////////////////////////////////////////////////////////////////

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

/////////////////////////////////////////////////////////////////////////////////////
///							TRACER CALLBACKS - HOOKS
/////////////////////////////////////////////////////////////////////////////////////

__checkReturn
bool CProcess2Fuzz::DbiSetAddressBreakpoint( 
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

__checkReturn
bool CProcess2Fuzz::DbiSetMemoryBreakpoint( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	PARAM_MEM2WATCH params;
	if (ReadParamBuffer<PARAM_MEM2WATCH>(reg, &params))
	{
		//for now support just aligned watching .. in other case more processing needed ...
		BYTE* mem2watch = reinterpret_cast<BYTE*>(PAGE_ALIGN(params.Memory.Value));
		size_t size = ALIGN((params.Size.Value + ((ULONG_PTR)params.Memory.Value - (ULONG_PTR)mem2watch) + PAGE_SIZE), PAGE_SIZE);

		CVadNodeMemRange vad_mem;
		if (m_vad.FindVadMemoryRange(mem2watch, &vad_mem))
		{
			if (m_mem2watch.Push(CMemoryRange(mem2watch, size, vad_mem.GetFlags().UFlags | DIRTY_FLAG)))
			{
				for (size_t page_walker = 0; page_walker < size; page_walker += PAGE_SIZE)
					if (CMMU::IsAccessed(mem2watch + page_walker))
						CMMU::SetInvalid(mem2watch + page_walker, PAGE_SIZE);
			}
		}
		return true;
	}
	return false;
}

/////////////////////////////////////////////////////////////////////////////////////
///							THREADS WALKER
/////////////////////////////////////////////////////////////////////////////////////

__checkReturn
bool CProcess2Fuzz::DbiEnumThreads( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	CMdl auto_cid(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(CID_ENUM));
	CID_ENUM* cid = static_cast<CID_ENUM*>(auto_cid.WritePtrUser());
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

/////////////////////////////////////////////////////////////////////////////////////
///							MODULE MONITOR
/////////////////////////////////////////////////////////////////////////////////////

__checkReturn
bool CProcess2Fuzz::DbiEnumModules( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	CMdl auto_module(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(MODULE_ENUM));
	MODULE_ENUM* module = static_cast<MODULE_ENUM*>(auto_module.WritePtrUser());
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
	PARAM_API* api_param = static_cast<PARAM_API*>(auto_api_param.WritePtr());
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

/////////////////////////////////////////////////////////////////////////////////////
///							MEMORY DUMPER
/////////////////////////////////////////////////////////////////////////////////////
__checkReturn
bool CProcess2Fuzz::DbiEnumMemory( 
	__inout ULONG_PTR reg[REG_COUNT]
	)
{
	CMdl auto_mem(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(MEMORY_ENUM));
	MEMORY_ENUM* mem = static_cast<MEMORY_ENUM*>(auto_mem.WritePtrUser());
	if (mem)
	{
		CVadNodeMemRange vad_mem;
		//NULL is equivalent getlowerbound
		if (m_vad.GetNextVadMemoryRange(mem->Begin.Value, &vad_mem))
		{
			mem->Begin.Value = vad_mem.Begin();
			mem->Size.Value = vad_mem.GetSize();
			mem->Flags.Value = vad_mem.GetFlags().UFlags;
		}

		return true;
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
				const void* src = mdl_mntr.ReadPtrUser();
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
				KeBreak();
				CMdl mdl_dbg(params.Dst.Value, params.Size.Value);
				void* dst = mdl_dbg.WritePtrUser();
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

//-----------------------------------------------------------------
// ****************** DBI FASTCALL COMMUNICATION ******************
//-----------------------------------------------------------------

__checkReturn
bool CProcess2Fuzz::Syscall( 
	__inout ULONG_PTR reg[REG_COUNT]
	)
{
	ULONG_PTR ring0rsp = reg[RSP];

	reg[RSP] = (ULONG_PTR)(get_ring3_rsp() - 2);

	bool status = false;
	switch ((ULONG)reg[SYSCALL_ID])//DBI_ACTION
	{
//tracer
	case SYSCALL_INIT:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiInit(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_TRACE_FLAG:
		if (m_processId == PsGetCurrentProcessId())//ERROR
			KeBreak();
		else
			status = DbiRemoteTrace(reg);

		break;

//'hooks' - tracer callbacks
	case SYSCALL_SET_MEMORY_BP:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiSetMemoryBreakpoint(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_SET_ADDRESS_BP:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiSetAddressBreakpoint(reg);
		else//ERROR
			KeBreak();

		break;

//threads walker
	case SYSCALL_ENUM_THREAD:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiEnumThreads(reg);
		else//ERROR
			KeBreak();

		break;

//module monitor
	case SYSCALL_ENUM_MODULES:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiEnumModules(reg);
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_GETPROCADDR:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiGetProcAddress(reg);
		else//ERROR
			KeBreak();

		break;

//memory dumper
	case SYSCALL_ENUM_MEMORY:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiEnumMemory(reg);
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

CProcess2Fuzz::~CProcess2Fuzz()
{
	CMemoryRange* mem = NULL;
	m_mem2watch.Find(CMemoryRange(NULL, 1), &mem);
	if (mem)
	{
		do
		{
			CMMU::SetValid(mem->Begin(), mem->GetSize());
		} while(m_mem2watch.GetNext(*mem, &mem));
	}
}
