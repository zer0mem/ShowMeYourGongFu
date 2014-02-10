/**
 * @file RefCounter.hpp
 * @author created by: Peter Hlavaty
 */

#ifndef __REFCOUNTER_H__
#define __REFCOUNTER_H__

#include "../utils/LockedContainers.hpp"
#include "ComparableId.hpp"

//necessary to ID be NULL-able ?
//TODO : this NULL-ability change ?
template<class ID, class TYPE>
struct OBJ_HOLDER :
	public COMPARABLE_ID_PTR<ID, TYPE>
{
	OBJ_HOLDER(
		__in const ID& id = NULL, 
		__in_opt TYPE* obj = NULL
		) : COMPARABLE_ID_PTR(id, obj)
	{
	}

	ID& GetId()
	{
		return Id;
	}
};

class CRefCounter
{
public:
	CRefCounter() : m_referenceCounter(1)
	{
	}

	__checkReturn 
	bool IncreaseReferenceHolders()
	{
		LONG ref_count = InterlockedIncrement(&m_referenceCounter);

		//max reference count reached!
		if (1 >= ref_count)
		{
			InterlockedDecrement(&m_referenceCounter);
			return false;
		}

		return true;
	}

	__checkReturn 
	LONG DecreaseReferenceHolders()
	{
		return InterlockedDecrement(&m_referenceCounter);
	}

private:
	LONG m_referenceCounter;
};

//TYPE necessary to inherit CRefCounter!!
//LOCKED-SORTED CONTAINER needs to be ID-UNIQUE!!
template<class ID, class TYPE>
class CRefWorker : 
	public CLockedAVL< OBJ_HOLDER<ID, TYPE> >
{
public:
	void ReleaseRef(
		__in_opt TYPE* obj
		)
	{
		if (NULL != obj && 0 == obj->DecreaseReferenceHolders())
			delete obj;
	}

	__checkReturn 
	bool ObtainRef(
		__in const ID& id,
		__out TYPE** obj
		)
	{
		RSRC_LOCK_RW
		OBJ_HOLDER<ID, TYPE>* robj;
		
		if (m_avl.Find(&OBJ_HOLDER<ID, TYPE>(id), &robj))
		{
			if (robj->GetId() == id)
			{
				//possibility to have uninitialized object here
				if (robj->Obj)
					if (!robj->Obj->IncreaseReferenceHolders())
						return false;//object pending to delete

				//  I. return referenced object
				// II. return not initialized object
				*obj = robj->Obj;
				return true;
			}
		}
		return false;
	}
};

template<class ID, class TYPE>
class CRefObjWorker :
	protected CRefWorker<ID, TYPE>
{
public:
	void Drop(
		__in const ID& id
		)
	{
		TYPE* obj = NULL;

		{
			RSRC_LOCK_RW

			OBJ_HOLDER<ID, TYPE>* robj;
			if (m_avl.Find(&OBJ_HOLDER<ID, TYPE>(id), &robj))
			{
				obj = robj->Obj;
				//avoid deleting in spinlock
				robj->Obj = NULL;
				m_avl.Remove(robj);
			}
		}

		//pair with referencing in default constructor!!
		ReleaseRef(obj);
	}

	bool Push(
		__in const ID& id
		)
	{
		return CLockedAVL::Push(OBJ_HOLDER<ID, TYPE>(id));
	}

	//in most cases, not initialized is not the case to solved
	//  I. cause -> no found ? == nothing you want to remove
	// II. cause -> already initialized ? == you do not want to remove it! 
	bool Initialize(
		__in const ID& id,
		__in TYPE* obj,
		__out_opt bool* allocated = NULL
		)
	{
		if (allocated)
			*allocated = !!obj;

		//if obj is null, then it is no use to init by null, 
		//it is already done by "Push" method
		if (obj)
		{
			{
				RSRC_LOCK_RO

				// lookup process context in list
				OBJ_HOLDER<ID, TYPE>* robj;
				if (m_avl.Find(&OBJ_HOLDER<ID, TYPE>(id), &robj))
				{
					if (robj->GetId() == id && NULL == robj->Obj)
					{
						robj->Obj = obj;
						return true;
					}
				}
			}

			//not found, or ID is used ? --> delete
			//delete outside of spinlock!
			delete obj;
		}
		return false;
	}


	//force inline
	__forceinline
	void ReleaseRef(
		__in_opt TYPE* obj
		)
	{
		CRefWorker::ReleaseRef(obj);
	}

	__checkReturn 
	__forceinline
	bool ObtainRef(
		__in const ID& id,
		__out TYPE** obj
		)
	{
		return CRefWorker::ObtainRef(id, obj);
	}
};

template<class WORKER, class ID, class TYPE>
class CAutoRef
{
public:
	explicit CAutoRef(
		__in WORKER* refWorker, 
		__in const ID& id
		) : m_refWorker(refWorker), 
			m_obj(NULL),
			m_referenced(false)
	{
		m_referenced = m_refWorker->ObtainRef(id, &m_obj);
	}

	~CAutoRef() 
	{
		if (m_referenced)
			m_refWorker->ReleaseRef(m_obj);
	}

	TYPE* GetObj()
	{
		return m_obj;
	}

	__checkReturn
	bool IsReferenced()
	{
		return m_referenced;
	}

	__checkReturn 
	bool IsInitialized()
	{
		return (NULL != m_obj);
	}

protected:
	TYPE* m_obj;
	bool m_referenced;
	WORKER* m_refWorker;
};

#endif //__REFCOUNTER_H__
