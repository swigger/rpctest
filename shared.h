#pragma once

string errmsg(DWORD msg);
uint32_t BE32(uint32_t v);
uint64_t BE64(uint64_t v);
uint32_t xrand();

void UUID2String(const GUID *const guid, char *const s);
bool String2UUID(const char * input, GUID * guid);
void FILETIME2String(const FILETIME * ft, char * s);
string utf16to8(const WCHAR * s, int n);
void get_random_bytes(void * buf, size_t sz);

void Sha256(BYTE *data, size_t len, BYTE *hash);
int8_t Sha256Hmac(BYTE* key, BYTE*  data, DWORD len, BYTE*  hmac);

size_t dump_hex(uintptr_t spos, const void * buf, size_t sz, FILE * fo);
const char * dump_hex(uintptr_t stpos, const void * buf, size_t sz, string & sa);

extern void(*logfunc)(int level, const char * msg, ...);

struct name_wrap
{
	const char * name;
	name_wrap(const char * p) : name(p) {}
};
template <class T, int N>
struct serialize_str_wrap_t
{
	T(&obj)[N];
	serialize_str_wrap_t(T(&obj)[N]) :obj(obj) {}
};

struct PolicyBinary
{
	template <class T>
	static int unserialize(const char * doc, size_t docsz, const char * name, T &  obj)
	{
		if (docsz < sizeof(T)) return -1;
		memcpy(&obj, doc, sizeof(T));
		return sizeof(T);
	}
	template <class T, int N>
	static int unserialize_arr(const char * doc, size_t docsz, const char * name, uint32_t nelem, T(&arr)[N])
	{
		if (docsz < nelem * sizeof(T)) return -1;
		if (N < nelem) return -1;
		memcpy(&arr[0], doc, sizeof(T)*nelem);
		return sizeof(T)*nelem;
	}

	template <class T, int N>
	static int serialize_arr(const char * name, string & doc, uint32_t nelem, const T(&arr)[N])
	{
		if (N < nelem) return -1;
		doc.append((char*)&arr[0], sizeof(T)*nelem);
		return sizeof(T)*nelem;
	}

	template <class T>
	static int serialize(const char * name, string & doc, const T & obj)
	{
		doc.append((char*)&obj, sizeof(T));
		return sizeof(T);
	}
	template <class T, int N>
	static int serialize(const char * name, string & doc, const serialize_str_wrap_t<T,N> & obj)
	{
		uint32_t slen = 0;
		for (; obj.obj[slen]; ++slen);
		return serialize_arr(name, doc, slen+1, obj.obj);
	}
};

template <class POLICY>
class CSerialize
{
protected:
	intptr_t m_errpos;
	size_t m_pos;
	string m_doc;
	const char * m_nextname;

public:
	CSerialize()
	{
		reset("");
	}
	CSerialize(crefstr doc)
	{
		reset(doc);
	}

	void reset(crefstr doc)
	{
		m_doc = doc;
		m_errpos = -1;
		m_pos = 0;
		m_nextname = 0;
	}
	intptr_t errpos() const
	{
		return m_errpos;
	}
	const string & get_doc() const
	{
		return m_doc;
	}

	template <class T>
	CSerialize & operator >> (T & obj)
	{
		uns(nullptr, obj);
		return *this;
	}
	template <class T>
	CSerialize & operator << (const T & obj)
	{
		s(m_nextname, obj);
		return *this;
	}
	template <>
	CSerialize & operator << (const name_wrap & obj)
	{
		m_nextname = obj.name;
		return *this;
	}


	template <class T>
	bool uns(const char * name, T & obj)
	{
		if (m_errpos >= 0) return false;
		if (m_pos >= m_doc.size())
		{
			m_errpos = m_pos;
			return false;
		}

		int n = POLICY::unserialize(m_doc.data() + m_pos, m_doc.size() - m_pos, name, obj);
		if (n < 0)
		{
			m_errpos = m_pos;
			return false;
		}
		m_pos += n;
		return true;
	}
	template <class T, int N>
	bool uns_arr(const char * name, T(&arr)[N], uint32_t nelem)
	{
		if (m_errpos >= 0) return false;
		if (m_pos >= m_doc.size())
		{
			m_errpos = m_pos;
			return false;
		}

		int n = POLICY::unserialize_arr(m_doc.data() + m_pos, m_doc.size() - m_pos, name, nelem, obj);
		if (n < 0)
		{
			m_errpos = m_pos;
			return false;
		}
		m_pos += n;
		return true;
	}

	template <class T>
	bool s(const char * name, T & obj)
	{
		if (m_errpos >= 0) return false;
		int n = POLICY::serialize(name, m_doc, obj);
		if (n < 0)
		{
			m_errpos = m_doc.size();
			return false;
		}
		return true;
	}
	template <class T, int N>
	bool s_arr(const char * name, uint32_t cnt, T(&obj)[N])
	{
		if (m_errpos >= 0) return false;
		int n = POLICY::serialize_arr<T,N>(name, m_doc, cnt, obj);
		if (n < 0)
		{
			m_errpos = m_doc.size();
			return false;
		}
		return true;
	}
};


template <class Iter>
bool all_same(Iter beg, Iter end)
{
	if (beg == end) return true;
	auto v = *beg;
	for (++beg; beg != end; ++beg)
	{
		if (*beg != v)
			return false;
	}
	return true;
}
