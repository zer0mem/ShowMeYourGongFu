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

#include "ThreadEvent.h"
#include "ImageInfo.h"

class CProcess2Fuzz : 
	public CProcessContext<CThreadEvent, CHILD_PROCESS, CImage>,
	public CSyscallCallbacks
{
public:
	explicit CProcess2Fuzz(
		__inout PEPROCESS process,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		);

	static
	__checkReturn
	bool WatchProcess(
		__inout PEPROCESS eprocess,
		__in HANDLE processId,
		__inout_opt PS_CREATE_NOTIFY_INFO* createInfo
		);

	void ImageNotifyRoutine(
		__in_opt UNICODE_STRING* fullImageName,
		__in HANDLE processId,
		__in IMAGE_INFO* imageInfo
		);

	__checkReturn
	bool Syscall(
		__inout ULONG_PTR reg[REG_COUNT]
		);

	__checkReturn
	bool PageFault( 
		__in BYTE* faultAddr, 
		__inout ULONG_PTR reg[REG_COUNT]
	);

protected:
	void ResolveThreads();

	__checkReturn
	bool VirtualMemoryCallback(
		__in void* memory,
		__in size_t size,
		__in bool write,
		__inout ULONG_PTR reg[REG_COUNT],
		__inout_opt BYTE* buffer = NULL
		) override;

	__checkReturn
	__forceinline
	bool GetFuzzThread(
		__in HANDLE threadId,
		__inout CThreadEvent** fuzzThread = NULL
		)
	{
		THREAD* thread;
		if (m_threads.Find(threadId, &thread) && thread->Value)
		{
			if (fuzzThread)
				*fuzzThread = thread->Value;
			return true;
		}
		return false;
	}

	__checkReturn
	__forceinline
	bool GetImage(
		__in const void* addr,
		__inout CImage** img = NULL
		)
	{
		IMAGE* img_info;
		if (m_loadedImgs.Find(CRange<void>(addr), &img_info) && img_info->Value)
		{
			if (img)
				*img = img_info->Value;
			return true;
		}
		return false;
	}

private:
	__checkReturn
	bool DbiHook(
		__inout ULONG_PTR reg[REG_COUNT]
		);

	__checkReturn
	bool DbiTraceEvent(
		__inout ULONG_PTR reg[REG_COUNT],
		__in TRACE_INFO* branchInfo
		);

	__checkReturn
	bool DbiRemoteTrace(
		__inout ULONG_PTR reg[REG_COUNT]
	);

	__checkReturn
	bool DbiEnumThreads(
		__inout ULONG_PTR reg[REG_COUNT]
		);
		
	__checkReturn
	bool DbiSuspendThread(
		__inout ULONG_PTR reg[REG_COUNT]
		);

	__checkReturn
	bool DbiEnumMemory(
		__inout ULONG_PTR reg[REG_COUNT]
		);
		
	__checkReturn
	bool DbiWatchMemoryAccess(
		__inout ULONG_PTR reg[REG_COUNT]
		);
		
	__checkReturn
	bool DbiInit(
		__inout ULONG_PTR reg[REG_COUNT]
		);		
		
	__checkReturn
	bool DbiEnumModules(
		__inout ULONG_PTR reg[REG_COUNT]
		);	
		
	__checkReturn
	bool DbiGetProcAddress(
		__inout ULONG_PTR reg[REG_COUNT]
		);
		
	__checkReturn
	bool DbiDumpMemory(
		__inout ULONG_PTR reg[REG_COUNT]
		);
		
	__checkReturn
	bool DbiPatchMemory(
		__inout ULONG_PTR reg[REG_COUNT]
		);

	__checkReturn
	bool DbiSetHook(
		__inout ULONG_PTR reg[REG_COUNT]
	);

protected:
	bool m_installed;

	const void* m_extRoutines[ExtCount];
};

#endif //__FUZZPROCESS_H__
