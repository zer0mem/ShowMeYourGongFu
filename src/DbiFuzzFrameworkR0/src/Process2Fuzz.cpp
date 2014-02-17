/**
 * @file Process.cpp
 * @author created by: Peter Hlavaty
 */

#include "drv_common.h"

#include "Process2Fuzz.h"

#include "../../Common/utils/HashString.hpp"
#include "../../Common/Kernel/MMU.hpp"
#include "../../Common/utils/VADWalker.h"

#include "../../Common/utils/SafePE.hpp"
#include "../../Common/FastCall/FastCall.h"

#include "../../minihypervisor/MiniHyperVisorProject/HyperVisor/Common/base/HVCommon.h"

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
	if (m_loadedImgs.Find(img, &img_id) && img_id->Obj)
	{
		if (CConstants::GetInstance().InAppModulesAVL().Find(&CHashString(img_id->Obj->ImageName())))
		{
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
		CMemoryRange* mem;

		// { ************************** touching memory by kernel; OS needs to read from it, or readprocessmemory ?
		//when frmwrk will be switched to r0 tracing, this branch -handling kernel touch- should be else branch of next branch {if getfuzzthread(currentthreadid}else{this}}
		if (m_mem2watch.Find(CMemoryRange(faultAddr, sizeof(ULONG_PTR)), &mem) && !IsUserModeAddress(pf_iret->IRet.Return))
		{
			DbgPrint("\n\n@@KERNEL TOUCH!!\n\n");
			KeBreak();//TODO -> doimplement touching monitored memory by kernel
			if (CMMU::IsAccessed(faultAddr))
				CMMU::SetValid(mem->Begin(), mem->GetSize());

			m_mem2watch.Pop(*mem);

			THREAD* thread;
			if (m_threads.Find(NULL, &thread))
			{
				do
				{
					thread->Obj->FreezeThreadRequest(MemoryTouchByKernel);
				} while(m_threads.GetNext(thread->Obj->ThreadId(), &thread));
			}

			return false;//not handled! -> process original PageFault handler!!!
		}
		// } ************************** touching memory by kernel!

		bool handled = false;
		CThreadEvent* fuzz_thread;
		if (GetFuzzThread(PsGetCurrentThreadId(), &fuzz_thread))
		{
			// { ************************** if no monitor-thread paired then just freeze this thread!!
			if (fuzz_thread->IsNecessaryToFreeze() && m_extRoutines[ExtWaitForDbiEvent])
			{
				//freeze in user mode!!
				if (IsUserModeAddress(pf_iret->IRet.Return))
				{
					if (fuzz_thread->FreezeThread(reg, pf_iret))
						handled = true;
					else
						DbgPrint("\n\n FREEZE ACC FAIL\n\n");
				}
			}
			// } ************************** if no monitor-thread paired then just freeze this thread!!

			// { ************************** HANDLE PROTECTED MEMORY ACCESS ************************** 
			else if (m_mem2watch.Find(CMemoryRange(faultAddr, sizeof(ULONG_PTR)), &mem))
			{
				if (!IsUserModeAddress(pf_iret->IRet.Return))
				{
					DbgPrint("\n\nKERNEL MODE!!!\n\n");
				}
				
				if (!CMMU::IsValid(faultAddr))
				{
					if (fuzz_thread->RegisterMemoryAccess(reg, faultAddr, mem, pf_iret))
						handled = true;
				}
			}
			// } ************************** HANDLE PROTECTED MEMORY ACCESS ************************** 

			// { ************************** HANDLE HV TRAP EXIT ************************** 
			else if (faultAddr == pf_iret->IRet.Return)
			{
				//if rip potentionaly points to kernel mode
				if (!IsUserModeAddress(pf_iret->IRet.Return))
				{
					//try except blog ? -> indeed use this address as ptr to kernel struct-> 
					//TODO : check if it is really our kernel object !!!!!
					TRACE_INFO* trace_info_container = reinterpret_cast< TRACE_INFO* >(pf_iret->IRet.Return);
					TRACE_INFO* trace_info = trace_info_container;
					if (fuzz_thread->GetStack().IsInRange(trace_info->StateInfo.IRet.StackPointer))
					{
						if (fuzz_thread->SmartTraceEvent(reg, trace_info, pf_iret))
							handled = true;
						else
							DbgPrint("\n\n TRAP ACC FAIL\n\n");

						//push back to trace_info queue
						CDbiMonitor::m_branchInfoStack.Push(const_cast<TRACE_INFO*>(trace_info_container));
					}
				}
			}
			// } ************************** HANDLE HV TRAP EXIT ************************** 


			if (handled)
			{
				//KeWaitForDbiEvent ...
				pf_iret->IRet.Return = const_cast<void*>(m_extRoutines[ExtWaitForDbiEvent]);
				return true;
			}
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
		return fuzz_thread->Init(reg);

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
	__inout ULONG_PTR reg[REG_COUNT],
	__in ULONG syscallId
	)
{
	PARAM_HOOK params;
	if (ReadParamBuffer<PARAM_HOOK>(reg, &params))
	{
		CImage* img;
		if (GetImage(params.HookAddr, &img))
		{
			CAutoProcessIdAttach eprocess(m_processId);
			if (eprocess.IsAttached())
			{
				if (SYSCALL_SET_ADDRESS_BP == syscallId)
				{
					return img->SetUpNewRelHook(params.HookAddr, m_extRoutines[ExtHook]);
				}
				else
				{
					if (img->IsHooked(params.HookAddr))
						img->UninstallHook(params.HookAddr);

					return !img->IsHooked(params.HookAddr);
				}
			}
		}
	}
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiSetMemoryBreakpoint( 
	__inout ULONG_PTR reg[REG_COUNT],
	__in ULONG syscallId
	)
{
	size_t size = 0;
	BYTE* mem2watch = NULL;
	CVadNodeMemRange vad_mem;

	CApcLvl irql;
	{
		CMdl auto_mem(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(PARAM_MEM2WATCH));
		PARAM_MEM2WATCH* mem = static_cast<PARAM_MEM2WATCH*>(auto_mem.WritePtrUser());
		if (mem)
		{
			mem2watch = reinterpret_cast<BYTE*>(PAGE_ALIGN(mem->Memory));
			size = ALIGN((mem->Size + (reinterpret_cast<ULONG_PTR>(mem->Memory) - reinterpret_cast<ULONG_PTR>(mem2watch)) + PAGE_SIZE), PAGE_SIZE);

			if (m_vad.FindVadMemoryRange(mem2watch, vad_mem))
			{
				mem->Size = size;
				mem->Memory = mem2watch;		
			}
		}
	}

	//separated to two blocks because here we attach to monitored process == write user ptr will be invalid!

	bool succ = false;
	if (mem2watch)
	{
		CAutoProcessIdAttach eprocess(m_processId);
		if (eprocess.IsAttached())
		{
			switch (syscallId)
			{
			case SYSCALL_SET_ACCESS_BP:
				if (m_mem2watch.Push(CMemoryRange(mem2watch, size, vad_mem.GetFlags().UFlags)))
				{
					CMMU::SetInvalid(mem2watch, size);
					succ = true;
				}
				break;
			case SYSCALL_UNSET_ACCESS_BP:
				if (m_mem2watch.Pop(CMemoryRange(mem2watch, size, vad_mem.GetFlags().UFlags)))
				{
					CMMU::SetValid(mem2watch, size);
					succ = true;
				}
				break;			

			default:
				break;
			}
		}
	}

	return succ;
}

/////////////////////////////////////////////////////////////////////////////////////
///							THREADS WALKER
/////////////////////////////////////////////////////////////////////////////////////

__checkReturn
bool CProcess2Fuzz::DbiEnumThreads( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	CApcLvl irql;
	CMdl auto_cid(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(CID_ENUM));
	CID_ENUM* cid = static_cast<CID_ENUM*>(auto_cid.WritePtrUser());
	if (cid)
	{
		THREAD* thread = NULL;
		if (!cid->ThreadId)
			(void)m_threads.Find(NULL, &thread);
		else
			(void)m_threads.GetNext(cid->ThreadId, &thread);

		if (thread && thread->Obj)
		{
			cid->ProcId = m_processId;
			cid->ThreadId = thread->Obj->ThreadId();
		}

		return true;
	}
	return false;
}

__checkReturn
bool CProcess2Fuzz::DbiSuspendThread( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	CThreadEvent* fuzz_thread;
	if (GetFuzzThread((HANDLE)reg[DBI_FUZZAPP_THREAD_ID], &fuzz_thread))
	{
		fuzz_thread->FreezeThreadRequest(ThreadSuspended);
		return true;
	}
	return false;
}

/////////////////////////////////////////////////////////////////////////////////////
///							MODULE MONITOR
/////////////////////////////////////////////////////////////////////////////////////

__checkReturn
bool CProcess2Fuzz::DbiEnumModules( 
	__inout ULONG_PTR reg[REG_COUNT] 
	)
{
	CApcLvl irql;
	CMdl auto_module(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(MODULE_ENUM));
	MODULE_ENUM* module = static_cast<MODULE_ENUM*>(auto_module.WritePtrUser());
	if (module)
	{
		IMAGE* img = NULL;
		if (!module->ImageBase)
			(void)m_loadedImgs.Find(CRange<void>(module->ImageBase), &img);
		else
			(void)m_loadedImgs.GetNext(CRange<void>(module->ImageBase), &img);

		if (img && img->Obj)
		{
			module->ImageBase = img->Obj->Image().Begin();
			module->ImageSize = img->Obj->Image().GetSize();
			module->Is64 = img->Obj->Is64();
			RtlZeroMemory(&module->ImageName, sizeof(module->ImageName));
			if (img->Obj->ImageName().Length < sizeof(module->ImageName))
				memcpy(&module->ImageName, img->Obj->ImageName().Buffer, img->Obj->ImageName().Length);
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
	CApcLvl irql;
	CMdl auto_api_param(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(PARAM_API));
	PARAM_API* api_param = static_cast<PARAM_API*>(auto_api_param.WritePtr());
	if (api_param)
	{
		CImage* img;
		if (GetImage(api_param->ModuleBase, &img))
		{
			CAutoProcessIdAttach eprocess(m_processId);
			if (eprocess.IsAttached())
			{
				api_param->ApiAddr = CSafePE::GetProcAddressSafe(api_param->ApiName, img->Image().Begin());
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
	CApcLvl irql;
	CMdl auto_mem(reinterpret_cast<void*>(reg[DBI_PARAMS]), sizeof(MEMORY_ENUM));
	MEMORY_ENUM* mem = static_cast<MEMORY_ENUM*>(auto_mem.WritePtrUser());

	if (mem)
	{
		CVadNodeMemRange vad_mem;
		//NULL is equivalent getlowerbound
		if (m_vad.GetNextVadMemoryRange(mem->Begin, vad_mem))
		{
			mem->Begin = vad_mem.Begin();
			mem->Size = vad_mem.GetSize();
			mem->Flags = vad_mem.GetFlags().UFlags;
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
		CApcLvl irql;
		CMdl mdl_dbg(params.Dst, params.Size);
		void* dst = mdl_dbg.WritePtr();
		if (dst)
		{
			CAutoProcessIdAttach eprocess(m_processId);
			if (eprocess.IsAttached())
			{
				CMdl mdl_mntr(params.Src, params.Size);
				const void* src = mdl_mntr.ForceReadPtrUser();
				if (src)
				{
					memcpy(dst, src, params.Size);
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
		CApcLvl irql;
		CMdl mdl_mntr(params.Src, params.Size);
		const void* src = mdl_mntr.ReadPtr();
		if (src)
		{
			CAutoProcessIdAttach eprocess(m_processId);
			if (eprocess.IsAttached())
			{
				CMdl mdl_dbg(params.Dst, params.Size);
				void* dst = mdl_dbg.ForceWritePtrUser();
				if (dst)
				{
					memcpy(dst, src, params.Size);
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
	switch (static_cast<ULONG>(reg[SYSCALL_ID]))//DBI_ACTION
	{
//tracer
	case SYSCALL_INIT:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiInit(reg);
		else//ObjOR
			KeBreak();

		break;

	case SYSCALL_TRACE_FLAG:
		if (m_processId == PsGetCurrentProcessId())//ERROR
			KeBreak();
		else
			status = DbiRemoteTrace(reg);

		break;

//'hooks' - tracer callbacks
	case SYSCALL_SET_ACCESS_BP:
	case SYSCALL_UNSET_ACCESS_BP:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiSetMemoryBreakpoint(reg, static_cast<ULONG>(reg[SYSCALL_ID]));
		else//ERROR
			KeBreak();

		break;

	case SYSCALL_SET_ADDRESS_BP:
	case SYSCALL_UNSET_ADDRESS_BP:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiSetAddressBreakpoint(reg, static_cast<ULONG>(reg[SYSCALL_ID]));
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

//suspend thread!
	case SYSCALL_FREEZE_THREAD:
		if (m_processId != PsGetCurrentProcessId())
			status = DbiSuspendThread(reg);
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
				if (m_threads.Find(*thread_id, &thread) && thread->Obj)
				{
					CThreadEvent* thread_event = thread->Obj;
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
