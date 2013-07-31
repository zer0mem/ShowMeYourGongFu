/**
 * @file drv_common.h
 * @author created by: Peter Hlavaty
 *
 * Variables likely to change, have to be excluded, and obtained as param fron ring3 [windbg pykd parser]
 *
 */

#ifndef __DRV_COMMON_H__
#define __DRV_COMMON_H__

#pragma pack(push, 1)

#include "../Common/base/Common.h"
#include "../Common/utils/Vad.h"

//x64
#define VADAddressCreationLock 0x358
#define VADWorkingSetMutex 0x4e8
#define VADSameThreadApcFlags 0x434
#define VADFlags 0x2fc
#define VADVadRoot 0x590

struct _MM_AVL_NODE
{
	void* Parent;
	void* LeftChild;
	void* RightChild;
};

struct _MMVAD_SHORT
{
	_MM_AVL_NODE VadNode;
	ULONG StartingVpn;
	ULONG EndingVpn;
	void* PushLock;
	MMVAD_FLAGS Flags;
};

struct _MM_AVL_TABLE
{
	_MM_AVL_NODE BalancedRoot;
	struct
	{
		union
		{
			ULONG_PTR AvlInfo;
			struct  
			{
				ULONG_PTR DepthOfTree : 5;
				ULONG_PTR TableType : 3;
				ULONG_PTR NumberGenericTableElements : 56;
			};
		};
	};
	void* NodeHint;
	void* NodeFreeHint;
};

#pragma pack(pop)

#endif //__DRV_COMMON_H__
