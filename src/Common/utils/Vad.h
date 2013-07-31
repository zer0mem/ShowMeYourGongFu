/**
 * @file Vad.h
 * @author created by: Peter Hlavaty
 *
 * Variables not likely to change, seems to be 'safe' to implement it
 *
 */

#ifndef __VAD_H__
#define __VAD_H__

#pragma pack(push, 1)

struct SAME_THREAD_APC_FLAGS 
{
	struct 
	{
		BYTE Spare : 1;
		BYTE StartAddressInvalid : 1;
		BYTE EtwCalloutActive : 1;
		BYTE OwnsProcessWorkingSetExclusive : 1;
		BYTE OwnsProcessWorkingSetShared : 1;
		BYTE OwnsSystemCacheWorkingSetExclusive : 1;
		BYTE OwnsSystemCacheWorkingSetShared : 1;
		BYTE OwnsSessionWorkingSetExclusive : 1;
	};
	struct 
	{
		BYTE OwnsSessionWorkingSetShared : 1;
		BYTE OwnsProcessAddressSpaceExclusive : 1;
		BYTE OwnsProcessAddressSpaceShared : 1;
		BYTE SuppressSymbolLoad : 1;
		BYTE Prefetching : 1;
		BYTE OwnsVadExclusive : 1;
		BYTE OwnsChangeControlAreaExclusive : 1;
		BYTE OwnsChangeControlAreaShared : 1;
	};
};

struct VM_FLAGS
{
	struct  
	{
		ULONG CreateReported : 1;
		ULONG NoDebugInherit   : 1;
		ULONG ProcessExiting   : 1;
		ULONG ProcessDelete    : 1;
		ULONG Wow64SplitPages  : 1;
		ULONG VmDeleted        : 1;
		ULONG OutswapEnabled   : 1;
		ULONG Outswapped       : 1;
		ULONG ForkFailed       : 1;
		ULONG Wow64VaSpace4Gb  : 1;
		ULONG AddressSpaceInitialized : 1;
		ULONG SetTimerResolution : 1;
		ULONG BreakOnTermination : 1;
		ULONG DeprioritizeViews : 1;
		ULONG WriteWatch       : 1;
		ULONG ProcessInSession : 1;
		ULONG OverrideAddressSpace : 1;
		ULONG HasAddressSpace  : 1;
		ULONG LaunchPrefetched : 1;
		ULONG Background       : 1;
		ULONG VmTopDown        : 1;
		ULONG ImageNotifyDone  : 1;
		ULONG PdeUpdateNeeded  : 1;
		ULONG VdmAllowed       : 1;
		ULONG CrossSessionCreate : 1;
		ULONG ProcessInserted  : 1;
		ULONG DefaultIoPriority : 1;
		ULONG ProcessSelfDelete : 1;
		ULONG SetTimerResolutionLink : 1;
	};
};

struct MMVAD_FLAGS
{
	ULONG VadType          : 3;
	ULONG Protection       : 5;
	ULONG PreferredNode    : 6;
	ULONG NoChange         : 1;
	ULONG PrivateMemory    : 1;
	ULONG Teb              : 1;
	ULONG PrivateFixup     : 1;
	ULONG Spare            : 13;
	ULONG DeleteInProgress : 1;
};

struct AVL_INFO
{
	ULONG_PTR DepthOfTree : 5;
	ULONG_PTR TableType : 3;
	ULONG_PTR NumberGenericTableElements : 56;
};

#pragma pack(pop)

#endif
