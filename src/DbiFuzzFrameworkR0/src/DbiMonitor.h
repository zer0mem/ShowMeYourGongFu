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

#include "../Common/Stack.hpp"

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

	void* GetPFHandler(
		__in BYTE coreId
		);

	CStack& GetPrintfStack();

	__forceinline
	__checkReturn
	bool GetProcess(
		__in HANDLE processId,
		__inout CProcess2Fuzz** process
		);

/*
	static
	CDbiMonitor& GetInstance();
*/
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


	virtual __checkReturn
	bool SetVirtualizationCallbacks();

	virtual
	void PerCoreAction(
		__in BYTE coreId
		);

	void HookSyscallMSR(
		__in const void* hook
		);

	CStack m_printfStack;
	CProcessMonitor<CProcess2Fuzz> m_procMonitor;

protected:
	void* m_syscalls[MAX_PROCID];
	void* PageFaultHandlerPtr[MAX_PROCID];
};

#endif //__SYSENETER_H__
