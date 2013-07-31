/**
 * @file HashString.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __HASHSTRING_H__
#define __HASHSTRING_H__

#include "../Common/base/Common.h"

class CHashString
{
public:
	CHashString()
	{
		m_hash = 0;
		m_uniString.Length = 0;
		m_uniString.MaximumLength = 0;
		m_uniString.Buffer = NULL;
	}

	CHashString(__in const UNICODE_STRING& str)
	{
		m_hash = CalculateHash(str);
		m_uniString = str;
	}

	__forceinline
	ULONG GetHash()
	{
		return m_hash;
	}

	__forceinline
	UNICODE_STRING GetString()
	{
		return m_uniString;
	}

	static
	__forceinline 
	ULONG CalculateHash( 
	__in const UNICODE_STRING& entry 
	)
	{
		ULONG hash;
		NTSTATUS status = RtlHashUnicodeString(&entry, TRUE, HASH_STRING_ALGORITHM_DEFAULT, &hash);

		if (NT_SUCCESS(status))
			return hash;

		return 0;
	}

	friend 
	__forceinline
	bool operator>(
		__in const CHashString& left, 
		__in const CHashString& right
		)
	{
		return (
			((CHashString&)left).GetHash() > ((CHashString&)right).GetHash() || 
			(((CHashString&)left).GetHash() == ((CHashString&)right).GetHash() && 
			RtlCompareUnicodeString(&((CHashString&)left).GetString(), &((CHashString&)right).GetString(), TRUE) > 0)
			);
	}

	friend
	__forceinline
	bool operator==(
		__in const CHashString& left, 
		__in const CHashString& right
	)
	{
		return (
			((CHashString&)left).GetHash() == ((CHashString&)right).GetHash() && 
			RtlEqualUnicodeString(&((CHashString&)left).GetString(), &((CHashString&)right).GetString(), TRUE)
			);
	}

protected:
	ULONG m_hash;
	UNICODE_STRING m_uniString;
};

#endif //__HASHSTRING_H__
