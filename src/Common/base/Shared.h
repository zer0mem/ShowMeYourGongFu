/**
 * @file Shared.h
 * @author created by: Peter Hlavaty
 */

#ifndef __SHARED_H__
#define __SHARED_H__

//--------------------------------------------------------------
// ****************** DEFINE TYPES -> based.h ******************
//--------------------------------------------------------------

// windows types
typedef unsigned long long  QWORD, *PQWORD, *LPQWORD;
typedef unsigned long	DWORD,	*PDWORD,	*LPDWORD;
typedef unsigned short	WORD,	*PWORD,		*LPWORD;
typedef unsigned char	BYTE,	*PBYTE,		*LPBYTE;
typedef unsigned int	UINT,	*PUINT,		*LPUINT;
typedef int				BOOL,	*PBOOL,		*LPBOOL;
typedef void					*PVOID,		*LPVOID;

typedef signed char SBYTE;
typedef signed short SWORD;
typedef signed long int SDWORD;

typedef char CHAR;
typedef short SHORT;
typedef long LONG;
typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef unsigned long ULONG;

typedef BYTE BOOLEAN;

typedef const void *LPCVOID;

typedef QWORD ULONG_PTR;

typedef ULONG_PTR size_t;
typedef void* HANDLE;


//-----------------------------------------------------
// ****************** DEFINE HELPERS ******************
//-----------------------------------------------------

enum EnumIRET
{
	IReturn = 0,
	ICodeSegment,
	IFlags,
	IRsp,
	IStackSegment,
	IRetCount
};

#pragma pack(push, 1)

typedef struct _ERROR_CODE
{
	union
	{
		ULONG UErrCode;
		struct  
		{
			ULONG_PTR Present : 1;
			ULONG_PTR WriteAccess : 1;
			ULONG_PTR Ring3 : 1;
		};
	};
} ERROR_CODE;

typedef struct _IRET
{
	void* Return;
	ULONG_PTR CodeSegment;
	ULONG_PTR Flags;
	ULONG_PTR* StackPointer;
	ULONG_PTR StackSegment;
} IRET;

typedef struct _PFIRET
{
	ERROR_CODE ErrorCode;
	IRET IRet;
} PFIRET;

#pragma pack(pop)


//------------------------------------------------------------------
// ****************** DEFINE PUSHAQ order of regs ******************
//------------------------------------------------------------------

enum RegSetx86
{
	RDI = 0, 
	RSI,
	RBP,
	RSP,
	RBX,
	RDX,
	RCX,
	RAX,
	REG_X86_COUNT
};

enum RegSetx64
{
	R15 = REG_X86_COUNT,
	R14,
	R13,
	R12,
	R11,
	R10,
	R9,
	R8,
	REG_X64_COUNT
};

#define REG_COUNT REG_X64_COUNT

enum RegFastCallX64Volatile
{
	VOLATILE_REG_RCX = 0,
	VOLATILE_REG_RDX,
	VOLATILE_REG_R8,
	VOLATILE_REG_R9,
	VOLATILE_REG_COUNT
};

#endif //__SHARED_H__
