/**
 * @file FuzzProcess.h
 * @author created by: Peter Hlavaty
 */

#ifndef __FUZZPROCESS_H__
#define __FUZZPROCESS_H__

#include "../../Common/base/Common.h"
#include "Common/Constants.h"
#include "../../Common/utils/ProcessCtx.h"
#include "../../Common/utils/LockedContainers.hpp"
#include "../../Common/utils/SyscallCallbacks.hpp"
#include "../../Common/utils/MemoryRange.h"

#include "../../Common/utils/DelayLoadEntryPointHook.hpp"

#include "ThreadEvent.h"

class CProcess2Fuzz : 
	public CProcessContext,
	public CSyscallCallbacks
{
public:
	explicit CProcess2Fuzz(
		__inout PEPROCESS process,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		);

	~CProcess2Fuzz();

	static
	__checkReturn
	bool WatchProcess(
		__inout PEPROCESS eprocess,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		);

	void ProcessNotifyRoutineEx(
		__inout PEPROCESS eprocess,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		);

	void ChildProcessNotifyRoutineEx(
		__inout PEPROCESS eprocess,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		);

	void ImageNotifyRoutine(
		__in_opt UNICODE_STRING* fullImageName,
		__in HANDLE processId,
		__in IMAGE_INFO* imageInfo
		);

	void ThreadNotifyRoutine(
		__in HANDLE processId,
		__in HANDLE threadId,
		__in BOOLEAN create
		);

	void RemoteThreadNotifyRoutine(
		__in HANDLE processId,
		__in HANDLE threadId,
		__in BOOLEAN create
		);

	__checkReturn
	virtual bool Syscall(
		__inout ULONG_PTR reg[REG_COUNT]
		);

	__checkReturn
	bool PageFault(
		__inout ULONG_PTR reg[REG_COUNT]
		);

protected:
	__checkReturn
	bool VirtualMemoryCallback(
		__in void* memory,
		__in size_t size,
		__in bool write,
		__inout ULONG_PTR reg[REG_COUNT],
		__inout_opt BYTE* buffer = NULL
		) override;

	void SetUnwriteable(
		__in const void* addr,
		__in size_t size
		);

protected:
	CDelayLoadMzEntryPointHook m_epHook;

	const void* m_extRoutines[ExtCount];

	CLockedAVL< CThreadEvent > m_threads;
	CLockedAVL<CHILD_PROCESS> m_childs;
	CLockedAVL<LOADED_IMAGE> m_loadedImgs;
	CLockedAVL<CMemoryRange> m_nonWritePages;
	CLockedAVL< CRange<ULONG_PTR> > m_stacks;
};

#endif //__FUZZPROCESS_H__
