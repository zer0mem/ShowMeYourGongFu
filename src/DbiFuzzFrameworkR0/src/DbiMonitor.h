/**
 * @file Syseneter.h
 * @author created by: Peter Hlavaty
 */

#ifndef __SYSENETER_H__
#define __SYSENETER_H__

#include "../../Common/base/Common.h"
#include "../../Common/base/Singleton.hpp"

#include "../../HyperVisor/src/Cronos.h"

#include "../../Common/utils/ProcessorWalker.hpp"
#include "../../Common/utils/ProcessMonitor.hpp"
#include "Process2Fuzz.h"

#include "../../Common/base/MemoryObj.hpp"

#include "../../Common/utils/Queue.hpp"

//need to refactor and clean up this messy class .. 
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
	CRefObjWorker<HANDLE, CProcess2Fuzz>* GetProcessWorker();	

	static CStack< TRACE_INFO > m_branchInfoStack;

	static
	void CreateThread()
	{
		KeBreak();
		TRACE_INFO* trace_info = m_branchInfoStack.Create();
		{
			::new(trace_info) TRACE_INFO;
			m_branchInfoStack.Push(trace_info);
		}
	}

	static
	void RemoveThread()
	{
		KeBreak();
		//add if -> for if not succesfull create thread .. some kind of counter ...
		TRACE_INFO* trace_info = m_branchInfoStack.Pop();
		ASSERT(trace_info);

		m_branchInfoStack.Remove(trace_info);
	}


protected:
	void InstallPageFaultHooks();

	static
	void VMMRDMSR(
		__inout ULONG_PTR reg[REG_COUNT]
	);
	static
	void VMMEXCEPTION(
		__inout ULONG_PTR reg[REG_COUNT]
	);
	static
	void VMMCPUID(
		__inout ULONG_PTR reg[REG_COUNT] 
	);
	static 
	void VMMWRMSR(
		__inout ULONG_PTR reg[REG_COUNT] 
	);

	virtual 
	__checkReturn
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
	static void* m_pageFaultHandlerPtr[MAX_PROCID];
};

#endif //__SYSENETER_H__
