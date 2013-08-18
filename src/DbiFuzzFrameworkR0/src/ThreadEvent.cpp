/**
 * @file ThreadEvent.cpp
 * @author created by: Peter Hlavaty
 */

#include "stdafx.h"

#include "ThreadEvent.h"
#include "../../Common/FastCall/FastCall.h"
#include "../../Common/Kernel/Process.hpp"
#include "../../Common/Kernel/MemoryMapping.h"

#include "../../HyperVisor/Common/base/HVCommon.h"

EXTERN_C void syscall_instr_prologue();
EXTERN_C void syscall_instr_epilogue();

//need to call _dynamic_initializer_for__cSyscallSize_
//static const size_t cSyscallSize = (ULONG_PTR)syscall_instr_epilogue - (ULONG_PTR)syscall_instr_prologue;
#define cSyscallSize ((ULONG_PTR)syscall_instr_epilogue - (ULONG_PTR)syscall_instr_prologue)

EXTERN_C ULONG_PTR* get_ring3_rsp();

CThreadEvent::CThreadEvent() : 
	THREAD_INFO(PsGetCurrentThreadId(), NULL),
	m_currentThreadInfo(NULL),
	m_monitorThreadInfo(NULL)
{
	WaitForSyscallCallback = false;
}

CThreadEvent::CThreadEvent(
	__in HANDLE threadId, 
	__in HANDLE parentProcessId /* = NULL */
	) : THREAD_INFO(threadId, parentProcessId),
		m_currentThreadInfo(PsGetCurrentProcessId()),
		m_monitorThreadInfo(parentProcessId)
{
	WaitForSyscallCallback = false;
}


//--------------------------------------------------------------
// ****************** MEMORY MNGMNT DBI UTILS ******************
//--------------------------------------------------------------

__checkReturn
bool CThreadEvent::WaitForSyscallEpilogue()
{
	return WaitForSyscallCallback;
}

void CThreadEvent::SetCallbackEpilogue( 
	__in ULONG_PTR reg[REG_COUNT], 
	__in void* memory, 
	__in size_t size, 
	__in bool write, 
	__in_opt void* pageFault /*= NULL */ 
	)
{
	WaitForSyscallCallback = true;

	*GeneralPurposeContext = *reg;
	LastMemoryInfo.SetInfo(memory, size, write);

	//invoke SYSCALL again after syscall is finished!
	reg[RCX] -= cSyscallSize;
	/*
	ULONG_PTR* r3stack = get_ring3_rsp();
	//set return againt to SYSCALL instr
	*r3stack -= cSyscallSize;
	*/
}

void CThreadEvent::EpilogueProceeded()
{
	WaitForSyscallCallback = false;
}


//--------------------------------------------------------
// ****************** DBI TRACE HELPERS ******************
//--------------------------------------------------------

__checkReturn 
bool CThreadEvent::FlipSemaphore( 
	__in const EVENT_THREAD_INFO& eventThreadInfo
	)
{
	if (eventThreadInfo.EventSemaphor)
	{
		CEProcess eprocess(eventThreadInfo.ProcessId);
		CAutoProcessAttach process(eprocess.GetEProcess());
		if (process.IsAttached())
		{
			CMdl event_semaphor(eventThreadInfo.EventSemaphor, sizeof(BYTE));
			volatile CHAR* semaphor = reinterpret_cast<volatile CHAR*>(event_semaphor.Map());
			if (semaphor)
			{
				return (0 == InterlockedExchange8(semaphor, 1));
			}
		}
	}
	return false;
}

void CThreadEvent::SetIret( 
	__in bool is64, 
	__inout void* iretAddr, 
	__in const void* iret, 
	__in ULONG_PTR segSel, 
	__in ULONG_PTR flags 
	)
{
	size_t iret_size = IRetCount * (is64 ? sizeof(ULONG_PTR) : sizeof(ULONG));
	CMdl r_auto_context(reinterpret_cast<const void*>(iretAddr), iret_size);
	void* iret_ctx = r_auto_context.Map();
	if (iret_ctx)
	{
		if (is64)
			SetIret<ULONG_PTR>(reinterpret_cast<ULONG_PTR*>(iret_ctx), iret, segSel, flags);
		else
			SetIret<ULONG>(reinterpret_cast<ULONG*>(iret_ctx), iret, segSel, flags);
	}
}


//----------------------------------------------------------------------
// ****************** MONITOR DLL INJECTED DBI HELPER ******************
//----------------------------------------------------------------------

__checkReturn
bool CThreadEvent::HookEvent(
	__in CImage* img, 
	__in ULONG_PTR reg[REG_COUNT] 
	)
{
	IRET* iret = PPAGE_FAULT_IRET(reg);
	void* ret = reinterpret_cast<void*>(reg[DBI_RETURN] - SIZE_REL_CALL);
	DbgPrint("\n\ncheck hook : %p\n\n", ret);
	
	if (img->IsHooked(ret))
	{
		img->UninstallHook(ret);
		DbgPrint("\nunhooked! %p\n", ret);
	}

	BRANCH_INFO branch;
	branch.SrcEip = ret;
	branch.DstEip = ret;
	if (m_currentThreadInfo.SetContext(img->Is64(), reg, &branch))
	{
		iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);
		
		SetIret(img->Is64(), reinterpret_cast<void*>(reg[DBI_IRET]), ret, iret->CodeSegment, m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS] | TRAP);

		DbgPrint("\n 1. EventCallback <SYSCALL_MAIN> : [%ws -> %p] <- %p [%p] %x\n", img->ImageName().Buffer, ret, reg[DBI_R3TELEPORT], reg, m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS]);
		return true;
	}

	KeBreak();
	DbgPrint("\nEROOR\n");
	return false;
}

__checkReturn
bool CThreadEvent::SmartTraceEvent( 
	__in CImage* img, 
	__in ULONG_PTR reg[REG_COUNT], 
	__in const BRANCH_INFO& branchInfo, 
	__in CLockedAVL<CIMAGEINFO_ID>& imgs 
	)
{
	IRET* iret = PPAGE_FAULT_IRET(reg);

	BRANCH_INFO branch = branchInfo;

	if (m_currentThreadInfo.SetContext(img->Is64(), reg, &branch))
	{
		m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[DBI_FLAGS] = branch.Flags;
		iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

		SetIret(img->Is64(), reinterpret_cast<void*>(reg[DBI_IRET]), branch.DstEip, iret->CodeSegment, branch.Flags | TRAP);

		//temporary dbg info
		CIMAGEINFO_ID* img_id;
		CImage* dst_img;
		imgs.Find(CIMAGEINFO_ID(CRange<void>(branch.DstEip)), &img_id);
		dst_img = img_id->Value;
		CImage* src_img;
		imgs.Find(CIMAGEINFO_ID(CRange<void>(branch.SrcEip)), &img_id);
		src_img = img_id->Value;
		CImage* dbg_img;
		imgs.Find(CIMAGEINFO_ID(CRange<void>(iret->Return)), &img_id);
		dbg_img = img_id->Value;


		DbgPrint("\n EventCallback <SYSCALL_TRACE_FLAG : %p)> : >> %p [%ws] %p [%ws] | dbg -> %ws vs %ws\nreg[ecx] : %p ; reg[eax] : %p //%p\n", 
			branch.Flags,
			branch.SrcEip, src_img->ImageName().Buffer, 
			branch.DstEip, dst_img->ImageName().Buffer, 
			img->ImageName().Buffer,  
			dbg_img->ImageName().Buffer, 
			m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[RCX],
			m_currentThreadInfo.DbiOutContext.GeneralPurposeContext[RAX],
			reg[DBI_R3TELEPORT]);
		
		if (!FlipSemaphore(m_monitorThreadInfo))
		{
			DbgPrint("\nUnFlipped semaphore ...\n");
		}
		return true;
	}

	KeBreak();
	DbgPrint("\nEROOR\n");
	return false;
}


//----------------------------------------------------------
// ****************** MONITOR DLL DBI API ******************
//----------------------------------------------------------

//invoked from monitor
__checkReturn
bool CThreadEvent::SmartTrace( 
	__in ULONG_PTR reg[REG_COUNT]
)
{
	IRET* iret = PPAGE_FAULT_IRET(reg);
	m_monitorThreadInfo.ProcessId = PsGetCurrentProcessId();
	m_monitorThreadInfo.EventSemaphor = reinterpret_cast<void*>(reg[DBI_SEMAPHORE]);

	m_currentThreadInfo.DumpContext(reg);

	iret->Return = reinterpret_cast<const void*>(reg[DBI_R3TELEPORT]);

	bool dbg_cont = FlipSemaphore(m_currentThreadInfo);
	if (!dbg_cont)
		KeBreak();
	return true;
}
