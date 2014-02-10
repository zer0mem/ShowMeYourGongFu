/**
 * @file SubProcessTagResolver.hpp
 * @author created by: Peter Hlavaty
 */

//some interesting code for UM - resolving service name by threadId, functional just for os > winxp, just concept now

#ifndef __SUBPROCESSTAGRESOLVER_H__
#define __SUBPROCESSTAGRESOLVER_H__

#include "../base/Common.h"
#include "PE.hpp"
#include "AutoHandle.hpp"

#include <memory>

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef enum _SC_SERVICE_TAG_QUERY_TYPE
{
	ServiceNameFromTagInformation = 1,
	ServiceNamesReferencingModuleInformation,
	ServiceNameTagMappingInformation
} SC_SERVICE_TAG_QUERY_TYPE, *PSC_SERVICE_TAG_QUERY_TYPE;

typedef struct _SC_SERVICE_TAG_QUERY
{
	ULONG ProcessId;
	ULONG ServiceTag;
	ULONG Unknown;
	PVOID Buffer;
} SC_SERVICE_TAG_QUERY, *PSC_SERVICE_TAG_QUERY;

#define ERROR_SUCCESS 0L

typedef NTSTATUS(NTAPI* _ZwQueryInformationThread)(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef ULONG(NTAPI *_I_QueryTagInformation)(
	__in PVOID Unknown,
	__in SC_SERVICE_TAG_QUERY_TYPE QueryType,
	__inout PSC_SERVICE_TAG_QUERY Query
	);

_ZwQueryInformationThread ZwQueryInformationThread = NULL;
_I_QueryTagInformation I_QueryTagInformation = NULL;

//for sharing buffer via unique_ptr from I_QueryTagInformation, 
//on which is necessary to perform LocalFree
class CLocalBuffer
{
public:
	CLocalBuffer(
		__inout void* buffer
		) : m_buffer(buffer)
	{
	}

	~CLocalBuffer()
	{
		if (m_buffer)
			LocalFree(m_buffer);
	}

	__checkReturn
		void* GetData()
	{
		return m_buffer;
	}

private:
	void* m_buffer;
};

namespace CUmVars
{
	const ULONG* TebSubProcessTag(
		__in const void* teb
		)
	{
#ifdef _WIN64
		size_t sub_process_tag = 0x1720;
#else
		size_t sub_process_tag = 0xf60;
#endif
		return reinterpret_cast<const ULONG*>(static_cast<const BYTE*>(teb) + sub_process_tag);
	}
};

//alex ionescu blog : http://www.alex-ionescu.com/?p=52
//example how to use it : http://wj32.org/wp/2010/03/30/howto-use-i_querytaginformation/
//f.e. check Process Hacker src -> http://processhacker.sourceforge.net/doc/modsrv_8c_source.html 
//MAIN LOGIC :
class CSubProcessTagResolver
{
public:
	CSubProcessTagResolver()
	{
		RtlZeroMemory(&query, sizeof(query));
		InitFunctions();
	}

	NTSTATUS ResolveServiceName(
		__in DWORD procId, 
		__in DWORD threadId,
		__inout std::unique_ptr<CLocalBuffer>& buff
		)
	{
		if (!m_funcInitialized)
			return STATUS_UNSUCCESSFUL;

		query.ProcessId = procId;
		COpenProcess oprocess(procId);
		if (oprocess.IsReferenced())
		{
			COpenThread othread(threadId);
			if (othread.IsReferenced())
			{
				THREAD_BASIC_INFORMATION basicInfo = { 0 };
				NTSTATUS nt_status = ZwQueryInformationThread(
					othread.GetHandle(), 
					ThreadBasicInformation, 
					&basicInfo, 
					sizeof(basicInfo), 
					NULL);

				if (NT_SUCCESS(nt_status))
				{
					nt_status = ReadProcessMemory(
						oprocess.GetHandle(), 
						const_cast<ULONG*>(CUmVars::TebSubProcessTag(basicInfo.TebBaseAddress)), 
						&query.ServiceTag, 
						sizeof(query.ServiceTag), 
						NULL);

					if (NT_SUCCESS(nt_status))
					{
						query.Unknown = 0;
						query.Buffer = NULL;
						ULONG e_status = I_QueryTagInformation(NULL, ServiceNameFromTagInformation, &query);
						if (ERROR_SUCCESS == e_status)
						{
							buff = boost::unique_ptr<CLocalBuffer>(new CLocalBuffer(query.Buffer));
							return STATUS_SUCCESS;
						}
						return STATUS_UNSUCCESSFUL;
					}
				}
			}
		}
		return STATUS_ACCESS_DENIED;
	}
protected:
	SC_SERVICE_TAG_QUERY query;

	//TEMPORARY, TODO : resolve by imports
private:
	__checkReturn
		void InitFunctions()
	{
		if (!I_QueryTagInformation ||
			!ZwQueryInformationThread)
		{		
			HMODULE sechost = GetModuleHandleA("sechost.dll");
			if (sechost)
			{
				CPE pe(sechost);			
				I_QueryTagInformation = reinterpret_cast<_I_QueryTagInformation>(pe.GetProcAddress("I_QueryTagInformation"));
			}

			HMODULE ntdll = GetModuleHandleA("ntdll.dll");
			if (ntdll)
			{
				CPE pe(ntdll);			
				ZwQueryInformationThread = reinterpret_cast<_ZwQueryInformationThread>(pe.GetProcAddress("ZwQueryInformationThread"));
			}
		}
		m_funcInitialized = (I_QueryTagInformation && ZwQueryInformationThread);
	}

	bool m_funcInitialized;
};

#endif //__SUBPROCESSTAGRESOLVER_H__
