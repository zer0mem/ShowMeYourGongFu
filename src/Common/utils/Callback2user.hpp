/**
 * @file Callback2user.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __CALLBACK2USER_H__
#define __CALLBACK2USER_H__

#include "ROP.h"
#include "../Kernel/MMU.hpp"
#include "../Kernel/MemoryMapping.h"
#include "../Kernel/UserModeMemory.hpp"
#include "../base/Common.h"

#define user32__fnDWORD (ULONG)2
#define WIN32_ERROR_SUCCESS 0L

#define KG2U_ERROR_NOTRESOLVED_CALLBACK 1

#define PARAM_SET(num, param) m_input[CALLBACK_PARAM0 + num] = *reinterpret_cast<ULONG_PTR*>(&param)
#define FUNCTION_SET(fnc) reinterpret_cast<void**>(m_input)[CALLBACK_FUNCTION] = const_cast<void*>(fnc);

DECLARE_GLOBAL_CONST_UNICODE_STRING(gNtKeUserModeCallback, L"KeUserModeCallback");

template<class TYPE>
class CCallback2User
{
#define INPUT_BUFFER_COUNT 0x100
public:
	CCallback2User(
		__in void* ntdllZwCallbackReturn,
		__in void* targetFunction,
		__in ULONG_PTR* userStack
		) : m_ntdllZwCallbackReturn(ntdllZwCallbackReturn),
			m_targetFunction(targetFunction),
			m_userStack(userStack)
	{
		m_NtKeUserModeCallback = MmGetSystemRoutineAddress(const_cast<UNICODE_STRING*>(&gNtKeUserModeCallback));
	}

	virtual
	__checkReturn
	TYPE CallOneParamApi(
		__inout_bcount(size) void** output,
		__inout size_t* size
		) = 0;

	void* GetInputBuffer()
	{
		return m_input;
	}

	ULONG GetInputBufferSize()
	{
		return static_cast<ULONG>(sizeof(m_input));
	}

protected:
	_IRQL_requires_max_(PASSIVE_LEVEL)
	bool InvokeCall(
		__inout void** output,
		__inout size_t* osize
		)
	{
		if (!KeAreApcsDisabled())
		{
			if (m_NtKeUserModeCallback)
			{
				return NT_SUCCESS(
					(*(NTSTATUS (*)(ULONG, void*, ULONG, void**, size_t*))(m_NtKeUserModeCallback))(
						user32__fnDWORD, 
						GetInputBuffer(), 
						GetInputBufferSize(), 
						output, 
						osize
					));
			}
		}
		return false;
	}

protected:
	void* m_ntdllZwCallbackReturn;
	void* m_targetFunction;
	ULONG_PTR* m_userStack;

	ULONG_PTR m_input[INPUT_BUFFER_COUNT];

private:
	const void* m_NtKeUserModeCallback;
};

//invasive, but universal
template<class TYPE, class PARAM>
class CCpl3Code :
	public CCallback2User<TYPE>
{
#define SIZE_OF_CODE 0x30
#define TOP_OF_STACK_4__fnDWORD 0x7 //move to top of stack at user32!_fnDWORD
#define DEEP_OF_INPUT_STACK 0xC //is deep of input from original stack

protected:
	CCpl3Code(
		__in void* ntdllZwCallbackReturn,
		__in void* targetFunction,
		__in ULONG_PTR* userStack
		) : CCallback2User(ntdllZwCallbackReturn, targetFunction, userStack)
	{
		m_cpl3Code = NULL;
	}
public:
	_IRQL_requires_max_(PASSIVE_LEVEL)
	__checkReturn
	TYPE CallOneParamApi(
		__inout_bcount(size) void** output,
		__inout size_t* size
		)
	{
		if (m_cpl3Code && InvokeCall(output, size))
			return (sizeof(TYPE) == *size && *output && *static_cast<const TYPE*>(*output));

		return false;
	}

	__checkReturn
	bool InjectCpl3Code(
		__in PARAM param
		)
	{
		if (m_cpl3Code)
		{
			PARAM_SET(0, m_ntdllZwCallbackReturn);
			m_input[CALLBACK_PARAM1] = GetInputBufferSize();//PARAM_SET(1,
			PARAM_SET(2, m_targetFunction);
			PARAM_SET(3, param);
			FUNCTION_SET(m_cpl3Code);
		}
		return !!m_cpl3Code;
	}

protected:
//CODE WITH CPL3, executed in ring3!!
	static 
	void UserCallback(
		__in void* ntdllZwCallbackReturn,
		__in ULONG inputSize,
		__in void* targetFunction,
		__in PARAM param,
		__in void* inputFindHelper
		)
	{
		void* input = &inputFindHelper + TOP_OF_STACK_4__fnDWORD + DEEP_OF_INPUT_STACK;

		TYPE res = ((*(TYPE (*)(PARAM))(targetFunction))(param));

		(*(void (*)(void*, ULONG, NTSTATUS))(ntdllZwCallbackReturn))(
			&res,
			static_cast<ULONG>(sizeof(res)),
			WIN32_ERROR_SUCCESS
			);
	}

protected:
	const void* m_cpl3Code;
};

template<class TYPE, class PARAM>
class CCpl3MDLCode :
	public CCpl3Code<TYPE, PARAM>
{
public:
	CCpl3MDLCode(
		__in void* ntdllZwCallbackReturn,
		__in void* targetFunction,
		__in ULONG_PTR* userStack
		) : CCpl3Code(ntdllZwCallbackReturn, targetFunction, userStack),
			m_sharedCode(reinterpret_cast<const void*>(UserCallback), SIZE_OF_CODE)
	{
		CApcLvl irql;
		if (irql.SufficienIrql())
		{
			m_cpl3Code = m_sharedCode.ReadPtrToUser();
			if (m_cpl3Code)
				CMMU::SetExecutable(m_cpl3Code, SIZE_OF_CODE);
		}
	};

	~CCpl3MDLCode()
	{
		if (m_cpl3Code)
		{
			CDispatchLvl irql;
			if (irql.SufficienIrql())
				CMMU::SetUnExecutable(m_cpl3Code, SIZE_OF_CODE);
		}
	}

protected:
	CMdl m_sharedCode;
};

template<class TYPE, class PARAM>
class CCpl3AllocCode :
	public CCpl3Code<TYPE, PARAM>
{
public:
	_IRQL_requires_max_(PASSIVE_LEVEL)	
	CCpl3AllocCode(
		__in void* ntdllZwCallbackReturn,
		__in void* targetFunction,
		__in ULONG_PTR* userStack
		) : CCpl3Code(ntdllZwCallbackReturn, targetFunction, userStack),
			m_userModeMem(SIZE_OF_CODE, PAGE_EXECUTE_READWRITE, NtCurrentProcess())
	{
		if (m_userModeMem.GetCount() >= SIZE_OF_CODE)
		{
			void* mem = m_userModeMem.GetMemory();
			if (mem)
			{
				memcpy(mem, UserCallback, SIZE_OF_CODE);
				m_cpl3Code = mem;
			}
		}		
	};

	_IRQL_requires_max_(PASSIVE_LEVEL)
	~CCpl3AllocCode()
	{
	}

protected:
	CUserModeMem<BYTE> m_userModeMem;
};

//not invasive, but OS version dependent!
template<class TYPE, class PARAM>
class CRop : 
	public CCallback2User<TYPE>
{
public:
	CRop(
		__in void* ntdllZwCallbackReturn,
		__in void* targetFunction,
		__in ULONG_PTR* userStack
		) : CCallback2User(ntdllZwCallbackReturn, targetFunction, userStack)
	{
	}

	void GenerateRopGadgets(
		__in PARAM param
		)
	{
		m_input[ROP_RCX] = *reinterpret_cast<ULONG_PTR*>(&param); //param to targetFunction
		m_input[ROP_R13] = (ROP_OUTPUT_FROM_FUNCTION + 1) * sizeof(void*); //output size to NtCallbackReturn
		m_input[ROP_R14] = 0; //ERROR_SUCCESS to NtCallbackReturn

		//needs hardcoded offsets, user interaction or ROP builder
		DbgPrint("\n\n\
eq %p user32!gSharedInfo; \
eq %p user32!GetAsyncKeyState+0x99; eq %p ntdll!LdrpGetProcedureAddress+0x171; eq %p KERNELBASE!_GSHandlerCheckCommon+0x8c; \
eq %p ntdll!LdrpVerifyAlternateResourceModule+0xd5; eq %p ntdll!RtlpWalkLowFragHeapSegment+0x5c; \n\n", 
				m_userStack,				//exported
				&m_input[ROP_SETRCX],		//pattern find
				&m_input[ROP_setVars1],		//pattern find
				&m_input[ROP_setVars2],		//pattern find
				&m_input[ROP_SET_STACK1],	//pattern find
				&m_input[ROP_SET_STACK2]	//pattern find
		);

		m_input[ROP_R9] = reinterpret_cast<ULONG_PTR>(m_userStack - 6);//or qword [R9 + 0x30], BYTE(qword [R9 + 0x30])

		KeBreak();

		m_input[ROP_ntCallbackReturn] = reinterpret_cast<ULONG_PTR>(m_ntdllZwCallbackReturn);
		m_input[ROP_targetFunctionAddr] = reinterpret_cast<ULONG_PTR>(m_targetFunction);
		m_input[ROP_RBP] = m_input[ROP_ntCallbackReturn];//rbp needs to be readable!!
	}

	_IRQL_requires_max_(PASSIVE_LEVEL)
	__checkReturn
	TYPE CallOneParamApi(
		__inout_bcount(size) void** output,
		__inout size_t* size
		)
	{
		if (InvokeCall(output, size))
		{
			if (*output)
			{
				const ULONG_PTR* res = reinterpret_cast<const ULONG_PTR*>(*output);
				if (*size == m_input[ROP_R13])
					return *reinterpret_cast<const TYPE*>(&res[ROP_OUTPUT_FROM_FUNCTION]);
			}
		}
		return false;
	}
};

#endif //__CALLBACK2USER_H__
