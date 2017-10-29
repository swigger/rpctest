#include "stdafx.h"
#include "shared.h"
#include "kms_io.h"
#include "dbgdump.h"

struct PolicyTextView
{
	template <class T>
	static int unserialize(const char * doc, size_t docsz, const char * name, T &  obj)
	{
		return -1;
	}
	template <class T, int N>
	static int unserialize_arr(const char * doc, size_t docsz, const char * name, uint32_t nelem, T(&arr)[N])
	{
		return -1;
	}
	template <class T>
	static int serialize(const char * name, string & doc, const T &  obj)
	{
		char buf[100];
		int n = sprintf(buf, "%llx", (int64_t)obj);
		if (n > sizeof(T) * 2)
			memmove(buf, buf + n - 2 * sizeof(T), 2 * sizeof(T) + 1);

		doc += name;
		doc += ": 0x";
		doc += buf;
		doc += "\n";
		return 0;
	}
	template <>
	static int serialize(const char * name, string & doc, const GUID &  obj)
	{
		char buf[100];
		UUID2String(&obj, buf);
		doc += name;
		doc += ": ";
		doc += buf;
		doc += "\n";
		return 0;
	}
	template <>
	static int serialize(const char * name, string & doc, const FILETIME &  obj)
	{
		char buf[100];
		FILETIME2String(&obj, buf);
		doc += name;
		doc += ": ";
		doc += buf;
		doc += "\n";
		return 0;
	}

	template <int N>
	static int serialize(const char * name, string & doc, const BYTE(&obj)[N])
	{
		char buf[2 * N + 2];
		for (uint32_t i = 0; i < N; i ++)
			sprintf(buf + 2*i, "%02x", obj[i]);
		buf[2 * N] = 0;

		doc += name;
		doc += ": <BIN>";
		doc += buf;
		doc += "\n";
		return 0;
	}
	template <int N>
	static int serialize(const char * name, string & doc, const WCHAR(&obj)[N])
	{
		string s = utf16to8(obj, N);
		doc += name;
		doc += ": <STR>";
		doc += s;
		doc += "\n";
		return 0;
	}
};

#define  NameValue(x) name_wrap(strchr(#x,'.')+1) << x

void dbg_dump_req(const REQUEST_V6& r)
{
	CSerialize<PolicyTextView> ss;
	ss << NameValue(r.Version)
		<< NameValue(r.IV)
		<< NameValue(r.RequestBase.Version)
		<< NameValue(r.RequestBase.VMInfo)
		<< NameValue(r.RequestBase.LicenseStatus)
		<< NameValue(r.RequestBase.BindingExpiration)
		<< NameValue(r.RequestBase.AppID)
		<< NameValue(r.RequestBase.ActID)
		<< NameValue(r.RequestBase.KMSID)
		<< NameValue(r.RequestBase.CMID)
		<< NameValue(r.RequestBase.N_Policy)
		<< NameValue(r.RequestBase.ClientTime)
		<< NameValue(r.RequestBase.CMID_prev)
		<< NameValue(r.RequestBase.WorkstationName);
	printf("%s", ss.get_doc().c_str());
}

void dbg_dump_responce(const RESPONSE_V6& rv6)
{
	CSerialize<PolicyTextView> ssv;

	ssv << NameValue(rv6.Version)
		<< NameValue(rv6.IV)
		<< NameValue(rv6.ResponseBase.Version)
		<< NameValue(rv6.ResponseBase.PIDSize)
		<< NameValue(rv6.ResponseBase.KmsPID)
		<< NameValue(rv6.ResponseBase.CMID)
		<< NameValue(rv6.ResponseBase.ClientTime)
		<< NameValue(rv6.ResponseBase.Count)
		<< NameValue(rv6.ResponseBase.VLActivationInterval)
		<< NameValue(rv6.ResponseBase.VLRenewalInterval)
		<< NameValue(rv6.RandomXoredIVs)
		<< NameValue(rv6.Hash)
		<< NameValue(rv6.HwId)
		<< NameValue(rv6.XoredIVs)
		<< NameValue(rv6.HMAC);
	printf("%s", ssv.get_doc().c_str());
}
