/**
 * @file IRQL.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __IRQL_H__
#define __IRQL_H__

#include "../base/Common.h"
#include "../base/instrinsics.h"

class CIRQL
{
protected:
	explicit CIRQL(
		BYTE irqlLevel
		)
	{
		KeRaiseIrql(irqlLevel, &m_oldIRQL);
	}
public:
	~CIRQL()
	{
		KeLowerIrql(m_oldIRQL);
	}
protected:
	KIRQL m_oldIRQL;
};

class CDispatchLvl : public CIRQL
{
public:
	CDispatchLvl() : CIRQL(DISPATCH_LEVEL)
	{
	}
};

class CApcLvl : public CIRQL
{
public:
	CApcLvl() : CIRQL(APC_LEVEL)
	{
	}
};

class CPassiveLvl : public CIRQL
{
public:
	CPassiveLvl() : CIRQL(PASSIVE_LEVEL)
	{
	}
};

class CDisableInterrupts
{
public:
	CDisableInterrupts()
	{
		cli();
	}

	~CDisableInterrupts()
	{
		sti();
	}
};

#endif //__IRQL_H__
