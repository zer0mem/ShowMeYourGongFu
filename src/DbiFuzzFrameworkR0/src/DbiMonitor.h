/**
 * @file Syseneter.h
 * @author created by: Peter Hlavaty
 */

#ifndef __SYSENETER_H__
#define __SYSENETER_H__

#include "../../Common/base/Common.h"
#include "../../Common/base/Singleton.hpp"

#include "../../Cronos/src/Cronos.h"

#include "../../Common/utils/ProcessorWalker.hpp"
#include "../Common/utils/ProcessMonitor.hpp"
#include "Process2Fuzz.h"

#include "../../Common/base/AutoMalloc.h"

#include "../../Common/utils/Queue.hpp"

class CDbiMonitor : 
	public CCRonos,
	public CSingleton<CDbiMonitor>
{
	//static CDbiMonitor* m_instance;
	static CDbiMonitor m_instance;
	CDbiMonitor();
public:	
	~CDbiMonitor();

	void Install();

	void* GetSysCall(
		__in BYTE coreId
		);

	static
	void* GetPFHandler(
		__in BYTE coreId
		);

	static
	void SetPFHandler( 
		__in BYTE coreId, 
		__in void* pfHndlr 
		);

	__forceinline
	__checkReturn
	bool GetProcess(
		__in HANDLE processId,
		__inout CProcess2Fuzz** process
		);	

	static CQueue< CAutoTypeMalloc<TRACE_INFO> > m_branchInfoQueue;

	static
	void CreateThread()
	{
		KeBreak();
		CAutoTypeMalloc<TRACE_INFO>* trace_info = m_branchInfoQueue.Create();
		if (trace_info)
		{
			::new(trace_info) CAutoTypeMalloc<TRACE_INFO>;
			trace_info->GetMemory()->StateInfo.ErrorCode.UErrCode = 3;
			m_branchInfoQueue.Push(trace_info);

			trace_info = m_branchInfoQueue.Pop();
			DbgPrint("\n poped expt : %p", trace_info->GetMemory()->StateInfo.ErrorCode.UErrCode);
			m_branchInfoQueue.Push(trace_info);
		}
	}

	static
	void RemoveThread()
	{
		KeBreak();
		//add if -> for if not succesfull create thread .. some kind of counter ...
		CAutoTypeMalloc<TRACE_INFO>* trace_info = m_branchInfoQueue.Pop();
		ASSERT(trace_info);

		m_branchInfoQueue.Remove(trace_info);
	}

	static
	void InstallPageFaultHooks();

	static
	void DisablePatchGuard(
		__in BYTE coreId
		);

protected:
	static
	void HookProtectionMSR(
		__inout ULONG_PTR reg[REG_COUNT]
	);
	static
	void TrapHandler(
		__inout ULONG_PTR reg[REG_COUNT]
	);
	static
	void CPUIDCALLBACK(
		__inout ULONG_PTR reg[REG_COUNT] 
	);
	static 
	void WrMsrSpecialBTF(
		__inout ULONG_PTR reg[REG_COUNT] 
	);

	virtual __checkReturn
	bool SetVirtualizationCallbacks();

	virtual
	void PerCoreAction(
		__in BYTE coreId
		);

	void HookSyscallMSR(
		__in const void* hook
		);


	static
	void AntiPatchGuard(
		__inout ULONG_PTR reg[REG_COUNT] 
	);

	CProcessMonitor<CProcess2Fuzz> m_procMonitor;

protected:
	void* m_syscalls[MAX_PROCID];
	static void* PageFaultHandlerPtr[MAX_PROCID];

	static KEVENT m_patchGuardEvents[MAX_PROCID];
};

#endif //__SYSENETER_H__
