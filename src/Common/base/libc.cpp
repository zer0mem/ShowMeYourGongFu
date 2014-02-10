/**
 * @file libc.cpp
 * @author created by: Peter Hlavaty
 */

#include "StdAfx.h"

#include "../../Common/utils/Undoc.hpp"

#ifndef _LIBC_POOL_TAG
#define _LIBC_POOL_TAG	'colM'
#endif

typedef struct _MEMBLOCK
{
	size_t	size;
	
	char data[0];
} MEMBLOCK;

EXTERN_C
__drv_when(return!=0, __drv_allocatesMem(pBlock))
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__bcount_opt(size)
void* __cdecl malloc(__in size_t size)
{
	MEMBLOCK *pBlock = (MEMBLOCK*)ExAllocatePoolWithTag(NonPagedPoolCacheAlignedMustS, size + sizeof(MEMBLOCK), _LIBC_POOL_TAG);
	if (NULL == pBlock)
		return NULL;

	pBlock->size = size;
	
	return pBlock->data;
}

EXTERN_C
__drv_when(return!=0, __drv_allocatesMem(inblock))
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__bcount_opt(size)
void* __cdecl realloc(__in_opt void *ptr, __in size_t size)
{
	MEMBLOCK *inblock = (NULL != ptr) ? CONTAINING_RECORD(ptr, MEMBLOCK, data) : NULL;

	if (0 == size)
	{
		// freeing all
		if (NULL != inblock)
			ExFreePoolWithTag(inblock, _LIBC_POOL_TAG);
		return NULL;
	}

	// alloc new block
	MEMBLOCK *outblock = (MEMBLOCK*)ExAllocatePoolWithTag(NonPagedPoolCacheAlignedMustS, size + sizeof(MEMBLOCK), _LIBC_POOL_TAG);
	if (NULL == outblock)
		return NULL;

	outblock->size = size;

	if (NULL != inblock)
	{
		// copy from old one
		memcpy(outblock->data, inblock->data, min(inblock->size, outblock->size));
		// and then free it
		ExFreePoolWithTag(inblock, _LIBC_POOL_TAG);
	}
	return outblock->data;
}

EXTERN_C
__drv_maxIRQL(DISPATCH_LEVEL)
void __cdecl free(__inout_opt __drv_freesMem(Mem) void *ptr)
{
	if (NULL != ptr)
		ExFreePoolWithTag(CONTAINING_RECORD(ptr, MEMBLOCK, data), _LIBC_POOL_TAG);
}

__drv_when(return!=0, __drv_allocatesMem(ptr))
__checkReturn
__drv_maxIRQL(DISPATCH_LEVEL)
__bcount_opt(size)
void* operator new(
	size_t size
	)
{
	void* ptr = malloc(size);
	return ptr;
}

__drv_maxIRQL(DISPATCH_LEVEL)
void operator delete(
	void* ptr
	)
{
	if (ptr)
		free(ptr);
}

EXTERN_C void __kebreak();

struct ATEXIT_ENTRY
{
	ATEXIT_ENTRY(
		__in void ( __cdecl *destructor)( void ),
		__in ATEXIT_ENTRY* next
		)
	{
		Destructor = destructor;
		Next = next;
	}
	
	~ATEXIT_ENTRY()
	{
		Destructor();
	}

	void (_cdecl *Destructor)();
	struct ATEXIT_ENTRY* Next;
};

static ATEXIT_ENTRY *gTopAtexitEntry = 0;

EXTERN_C
int __cdecl atexit(
	__in void ( __cdecl *destructor)( void )
	)
{
	if (destructor)
	{
		ATEXIT_ENTRY *entry = new ATEXIT_ENTRY(destructor, gTopAtexitEntry);
		if (entry)
		{
			gTopAtexitEntry = entry;
			return 1;
		}
	}
	return 0;
}

#if defined(_IA64_) || defined(_AMD64_)
#pragma section(".CRT$XCA",long,read)
__declspec(allocate(".CRT$XCA")) void (*__ctors_begin__[1])(void)={0};
#pragma section(".CRT$XCZ",long,read)
__declspec(allocate(".CRT$XCZ")) void (*__ctors_end__[1])(void)={0};
#pragma data_seg()
#else
#pragma data_seg(".CRT$XCA")
void (*__ctors_begin__[1])(void)={0};
#pragma data_seg(".CRT$XCZ")
void (*__ctors_end__[1])(void)={0};
#pragma data_seg()
#endif

#pragma data_seg(".STL$A")
void (*___StlStartInitCalls__[1])(void)={0};
#pragma data_seg(".STL$L")
void (*___StlEndInitCalls__[1])(void)={0};
#pragma data_seg(".STL$M")
void (*___StlStartTerminateCalls__[1])(void)={0};
#pragma data_seg(".STL$Z")
void (*___StlEndTerminateCalls__[1])(void)={0};
#pragma data_seg()

EXTERN_C
void __cdecl doexit(
	__in int /*code*/, 
	__in int quick, 
	__in int /*retcaller*/
	)
{
	UNREFERENCED_PARAMETER(quick);

	for (ATEXIT_ENTRY* entry = gTopAtexitEntry; entry; entry = entry->Next)
	{
		ATEXIT_ENTRY* next = entry->Next;
		delete next;
	}
}

DRIVER_OBJECT* gDriverObject = NULL;

EXTERN_C
int __cdecl _cinit(
	__in int
	)
{
	if (NT_VERIFY(gDriverObject && CUndoc::IsInitialized()))
	{
		for (void (**ctor)(void) = __ctors_begin__ + 1; 
			ctor < __ctors_end__; 
			ctor++)
		{
			(*ctor)();
		}
	}

	return 0;
}
