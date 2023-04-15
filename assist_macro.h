/********************************************************************
	Created:		2019-03-26
	Author:			xuduo;
	Version:		1.0.0(°æ±¾ºÅ);
	Description:	¸¨Öúºê;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2019-03-26    |	1.0.0	 |	xuduo		  | Create file
----------------------------------------------------------------------------
  2019-03-27    |	1.0.1	 |	chips		  | update DEFINE_PROPERTY
----------------------------------------------------------------------------
  2019-04-04	|	1.0.2	 |	xuduo		  | update DISABLE_COPY
----------------------------------------------------------------------------
  2019-04-09	|	1.0.3	 |	xuduo		  | update SINGLETON_DEFINITION
----------------------------------------------------------------------------
*********************************************************************/

#pragma once

#define SINGLETON_DEFINITION(type)			\
public:		static type& GetInstance() { static type __instance; return __instance; }

#define SAFE_DELETE(p) do { if ((p)) delete (p); (p) = nullptr; } while (0)

#define DEFINE_DLL_FUNCTION(func, type, dll)	\
	auto func = reinterpret_cast<type>(GetProcAddress(GetModuleHandleW(L##dll), #func));

#define DISABLE_COPY(type)					\
private:	type(const type&);				\
private:	type& operator=(const type&);

#define DEFINE_PROPERTY(type, name)			\
private:									\
	type m_##name;							\
public:										\
void name(const type v)						\
{											\
	m_##name = v;							\
}											\
type name()	const							\
{											\
	return m_##name;						\
}											\

#define DEFINE_PROPERTY_REF(type, name)		\
private:									\
	type m_##name;							\
public:										\
void name(const type& v)					\
{											\
	m_##name = v;							\
}											\
const type& name() const					\
{											\
	return m_##name;						\
}											\
type& name()								\
{											\
	return m_##name;						\
}											\

#define DEFINE_PROPERTY_READONLY(type, name)	\
protected:										\
	type m_##name;								\
public:											\
type name()	const								\
{												\
	return m_##name;							\
}	

#define DEFINE_PROPERTY_REF_READONLY(type, name)		\
protected:												\
	type m_##name;										\
public:													\
const type& name() const								\
{														\
	return m_##name;									\
}														\
type& name()											\
{														\
	return m_##name;									\
}	


//ÊÇ·ñ¿ªÆôÄÚ´æ¼à¿Ø;
#ifdef OBJECT_MEMORY_MONITOR
#define OBJECT_MEMORY_MONITOR_CTOR(type) ThreadTaskManager::GetInstance().OnObjectCtor(#type);
#define OBJECT_MEMORY_MONITOR_DTOR(type) ThreadTaskManager::GetInstance().OnObjectDtor(#type);
#else
#define OBJECT_MEMORY_MONITOR_CTOR(type) ;
#define OBJECT_MEMORY_MONITOR_DTOR(type) ;
#endif // OBJECT_MEMORY_MONITOR

