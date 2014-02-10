/**
 * @file Undoc.h
 * @author created by: Peter Hlavaty
 */

#ifndef __UNDOC_HEADER_H__
#define __UNDOC_HEADER_H__

typedef void MM_AVL_TABLE;
typedef void MM_AVL_NODE;
typedef void MMVAD_SHORT;

struct VAD_SHORT;

typedef void* PKKERNEL_ROUTINE;
typedef void* PKRUNDOWN_ROUTINE;
typedef void* PKNORMAL_ROUTINE;

typedef enum{
	OriginalApcEnvironment = 0,
	AttachedApcEnvironment,
	CurrentApcEnvironment
} KAPC_ENVIRONMENT;

EXTERN_C VOID NTAPI KeInitializeApc(
	__in PKAPC Apc,
	__in PETHREAD Thread,
	__in KAPC_ENVIRONMENT Environment,
	__in PKKERNEL_ROUTINE KernelRoutine,
	__in_opt PKRUNDOWN_ROUTINE RundownRoutine,
	__in_opt PKNORMAL_ROUTINE NormalRoutine,
	__in KPROCESSOR_MODE	ProcessorMode,
	__in PVOID NormalContext
	);

EXTERN_C BOOLEAN NTAPI KeInsertQueueApc(
	__in PKAPC Apc,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2,
	__in KPRIORITY Increment
	);
/*
EXTERN_C BOOLEAN NTAPI KeRemoveQueueApc(
	__in PKAPC Apc
	);
*/
typedef BOOLEAN(NTAPI *KeRemoveQueueApc)(
	__in PKAPC Apc
	);

#endif //__UNDOC_HEADER_H__
