#include "stdafx.h"
#include "kms_io.h"
#include "aes.h"
#include "shared.h"
#include "dbgdump.h"

static const CKMSServer::VLKData g_vlks[] =
{
	/* 0 */ { 96,199000000,217999999,10 },
	/* 1 */ { 206,471000000,530999999,50 },
	/* 2 */ { 206,234000000,255999999,10 },
	/* 3 */ { 206,437000000,458999999,10 },
	/* 4 */ { 3858,0,14999999,50 }
};

static const CKMSServer::KmsData_Raw g_kmss[] = {
	{ "{D27CD636-1962-44E9-8B4F-27B6C23EFB85}", 0, "Windows 10 Unknown (Volume)" },
	{ "{7BA0BF23-D0F5-4072-91D9-D55AF5A481B6}", 4, "Windows 10 Chs" },
	{ "{969FE3C0-A3EC-491A-9F25-423605DEB365}", 0, "Windows 10 2016 (Volume)" },
	{ "{E1C51358-FE3E-4203-A4A2-3B6B20C9734E}", 0, "Windows 10 (Retail)" },
	{ "{58E2134F-8E11-4D17-9CB2-91069C151148}", 0, "Windows 10 2015 (Volume)" },
	{ "{7FDE5219-FBFA-484A-82C9-34D1AD53E856}", 0, "Windows 7" },
	{ "{BBB97B3B-8CA4-4A28-9717-89FABD42C4AC}", 0, "Windows 8 (Retail)" },
	{ "{3C40B358-5948-45AF-923B-53D21FCC7E79}", 0, "Windows 8 (Volume)" },
	{ "{6D646890-3606-461A-86AB-598BB84ACE82}", 0, "Windows 8.1 (Retail)" },
	{ "{CB8FC780-2C05-495A-9710-85AFFFC904D7}", 0, "Windows 8.1 (Volume)" },
	{ "{5F94A0BB-D5A0-4081-A685-5819418B2FE0}", 0, "Windows Preview" },
	{ "{33E156E4-B76F-4A52-9F91-F641DD95AC48}", 0, "Windows Server 2008 A (Web and HPC)" },
	{ "{8FE53387-3087-4447-8985-F75132215AC9}", 0, "Windows Server 2008 B (Standard and Enterprise)" },
	{ "{8A21FDF3-CBC5-44EB-83F3-FE284E6680A7}", 0, "Windows Server 2008 C (Datacenter)" },
	{ "{0FC6CCAF-FF0E-4FAE-9D08-4370785BF7ED}", 0, "Windows Server 2008 R2 A (Web and HPC)" },
	{ "{CA87F5B6-CD46-40C0-B06D-8ECD57A4373F}", 0, "Windows Server 2008 R2 B (Standard and Enterprise)" },
	{ "{B2CA2689-A9A8-42D7-938D-CF8E9F201958}", 0, "Windows Server 2008 R2 C (Datacenter)" },
	{ "{8665CB71-468C-4AA3-A337-CB9BC9D5EAAC}", 0, "Windows Server 2012" },
	{ "{8456EFD3-0C04-4089-8740-5B7238535A65}", 0, "Windows Server 2012 R2" },
	{ "{6E9FC069-257D-4BC4-B4A7-750514D32743}", 0, "Windows Server 2016" },
	{ "{6D5F5270-31AC-433E-B90A-39892923C657}", 0, "Windows Server Preview" },
	{ "{212A64DC-43B1-4D3D-A30C-2FC69D2095C6}", 0, "Windows Vista" },
	{ "{E85AF946-2E25-47B7-83E1-BEBCEBEAC611}", 1, "Office 2010" },
	{ "{E6A6F1BF-9D40-40C3-AA9F-C77BA21578C0}", 2, "Office 2013" },
	{ "{AA4C7968-B9DA-4680-92B6-ACB25E2F866C}", 2, "Office 2013 (Pre-Release)" },
	{ "{85B5F61B-320B-4BE3-814A-B76B2BFAFC82}", 3, "Office 2016" },
};

CKMSServer::CKMSServer()
{
	// HostType and OSBuild
	static const KMSHostOS  HostOSs[] =
	{
		{ 55041, 6002 }, // Windows Server 2008 SP2
		{ 55041, 7601 }, // Windows Server 2008 R2 SP1
		{ 5426, 9200 }, // Windows Server 2012
		{ 6401, 9600 }, // Windows Server 2012 R2
		{ 3612, 14393 }, // Windows Server 2016
	};
	m_os = HostOSs[xrand() % _countof(HostOSs)];

	for (int i = 0; i < _countof(g_kmss); ++i)
	{
		KmsData kd;
		kd.EPidIdx = g_kmss[i].EpidIndex;
		kd.name = g_kmss[i].name;
		String2UUID(g_kmss[i].Guid, &kd.guid);
		m_kmsd.insert(kd);
	}
}

CKMSServer & CKMSServer::Instance()
{
	static CKMSServer srv;
	return srv;
}

void CKMSServer::RandPid(const GUID & kmsguid, WCHAR * outpid, int * ncount)
{
	KmsData kdtmp;
	kdtmp.guid = kmsguid;
	auto it = m_kmsd.find(kdtmp);
	if (it == m_kmsd.end())
	{
		//kms data not found, assume default?
		char gn[100];
		UUID2String(&kmsguid, gn);
		logfunc(-1, "kmsguid %s not founnd, assume windows.", gn);
		kdtmp.EPidIdx = 0;
		kdtmp.name = "Windows (Unknown)";
	}
	else
	{
		kdtmp.EPidIdx = it->EPidIdx;
		kdtmp.name = it->name;
	}
	
	uint32_t keyid = xrand() % (g_vlks[kdtmp.EPidIdx].MaxKeyId - g_vlks[kdtmp.EPidIdx].MinKeyId) + g_vlks[kdtmp.EPidIdx].MinKeyId;
	if (keyid > 999999999) keyid = 999999999;
	LCID lang = 1033;
	char pid[100];
	time_t t = time(0);
	struct tm  * tt = localtime(&t);

	sprintf(pid, "%05d-%05d-%03d-%06d-03-%d-%d.0000-%03d%d",
		m_os.Type, g_vlks[kdtmp.EPidIdx].GroupId, 
		keyid/1000000, keyid%1000000,
		lang, m_os.Build, 
		tt->tm_yday, tt->tm_year+1900);
	for (int i = 0; ; ++i)
	{
		outpid[i] = pid[i];
		if (!pid[i]) break;
	}
	*ncount = g_vlks[kdtmp.EPidIdx].MinActiveClients;
}

static int8_t CreateV6Hmac(const void *const encrypt_start, uint32_t encryptSize, int8_t tolerance, FILETIME *ft, BYTE * hmac)
{
	BYTE hash[32];
	const uint8_t halfHashSize = sizeof(hash) / 2;

	// Generate a time slot that changes every 4.11 hours.
	// Request and repsonse time must match +/- 1 slot.
	// When generating a response tolerance must be 0.
	// If verifying the hash, try tolerance -1, 0 and +1. One of them must match.
	uint64_t timeSlot = ((*(uint64_t*)(ft) / TIME_C1 * TIME_C2 + TIME_C3) + (tolerance * TIME_C1));

	// The time slot is hashed with SHA256 so it is not so obvious that it is time
	Sha256((BYTE*)&timeSlot, sizeof(timeSlot), hash);

	// The last 16 bytes of the hashed time slot are the actual HMAC key
	if (!Sha256Hmac(hash + halfHashSize, (BYTE*)encrypt_start,	encryptSize, hash))
	{
		return FALSE;
	}

	memcpy(hmac, hash + halfHashSize, halfHashSize);
	return TRUE;
}

static bool create_response_base(RESPONSE * base, const REQUEST * req)
{
	int cnt = 0;
	base->Version = req->Version;
	CKMSServer::Instance().RandPid(req->KMSID, base->KmsPID, &cnt);
	base->PIDSize = (uint32_t)wcslen(base->KmsPID) * 2 + 2;
	memcpy(&base->CMID, &req->CMID, sizeof(req->CMID));
	memcpy(&base->ClientTime, &req->ClientTime, sizeof(req->ClientTime));

	base->VLActivationInterval = 60 * 5;     // Time in minutes when clients should retry activation if it was unsuccessful (default 5 hours)
	base->VLRenewalInterval = 15 * 24 * 30;  // Time in minutes when clients should renew KMS activation (default 15 days)
	base->Count = std::max<uint32_t>(cnt, req->N_Policy*2);   // Current activated machines. KMS server counts up to N_Policy << 1 then stops
	return true;
}

static int kms_io56(AesCtx * aesCtx, const string & req, string & reqout)
{
	REQUEST_V6 r;
	memset(&r, 0, sizeof(r));
	CSerialize<PolicyBinary> ss(req);
	ss  >> r.Version 
		>> r.IV 
		>> r.RequestBase.Version
		>> r.RequestBase.VMInfo
		>> r.RequestBase.LicenseStatus
		>> r.RequestBase.BindingExpiration
		>> r.RequestBase.AppID
		>> r.RequestBase.ActID
		>> r.RequestBase.KMSID
		>> r.RequestBase.CMID
		>> r.RequestBase.N_Policy
		>> r.RequestBase.ClientTime
		>> r.RequestBase.CMID_prev
		>> r.RequestBase.WorkstationName;
	if (ss.errpos() >= 0) return E_INVALIDARG;

	dbg_dump_req(r);

	WORD majorVer = r.Version >> 16;
	RESPONSE_V6 rv6;
	memset(&rv6, 0, sizeof(rv6));
	if (!create_response_base(&rv6.ResponseBase, &r.RequestBase))
		return E_FAIL;
	rv6.Version = r.Version;
	get_random_bytes(rv6.RandomXoredIVs, sizeof(rv6.RandomXoredIVs));
	Sha256(rv6.RandomXoredIVs, sizeof(rv6.RandomXoredIVs), rv6.Hash);
	// Xor Random bytes with decrypted request IV
	XorBlock(r.IV, rv6.RandomXoredIVs);

	if (majorVer == 6)
	{
		static unsigned char defhwid[] = { 0x3A, 0x1C, 0x04, 0x96, 0x00, 0xB6, 0x00, 0x76 };// HwId from the Ratiborus VM
		memcpy_obj(rv6.HwId, defhwid);
		get_random_bytes(rv6.IV, sizeof(rv6.IV));
		// Just copy decrypted request IV (using Null IV) here. Note this is identical
		// to XORing non-decrypted request and reponse IVs
		memcpy_obj(rv6.XoredIVs, r.IV);
	}
	else
	{
		memcpy_obj(rv6.IV, r.IV);
	}

	CSerialize<PolicyBinary> sst;
	sst << rv6.Version
		<< rv6.IV
		<< rv6.ResponseBase.Version
		<< rv6.ResponseBase.PIDSize
		<< serialize_str_wrap_t<WCHAR, PID_BUFFER_SIZE>(rv6.ResponseBase.KmsPID)
		<< rv6.ResponseBase.CMID
		<< rv6.ResponseBase.ClientTime
		<< rv6.ResponseBase.Count
		<< rv6.ResponseBase.VLActivationInterval
		<< rv6.ResponseBase.VLRenewalInterval
		<< rv6.RandomXoredIVs
		<< rv6.Hash;
	if (majorVer == 6)
	{
		sst << rv6.HwId
			<< rv6.XoredIVs;
		if (sst.errpos() >= 0) return E_FAIL;

		CreateV6Hmac(sst.get_doc().c_str() + 4, (uint32_t) sst.get_doc().size() - 4, 0, &rv6.ResponseBase.ClientTime, rv6.HMAC);
		sst << rv6.HMAC;
	}
	else
	{
		if (sst.errpos() >= 0) return E_FAIL;
	}

	string doc = sst.get_doc();
	size_t sz = doc.size() - 4;

	doc.append((char*)rv6.HMAC, 16); //append 16 bytes for padding.
	AesEncryptCbc(aesCtx, NULL, (BYTE*) &doc[4], &sz);
	if (doc.size() < sz + 4) return E_FAIL;
	doc.resize(sz + 4);
	reqout.swap(doc);
	return 0;
}

static void AesCmacV4(const void *data, size_t len, BYTE *hash)
{
	size_t i;
	BYTE mac[AES_BLOCK_BYTES] = { 0x80 };
	AesCtx Ctx;
	string dcopy;

	dcopy.append((char*)data, len);
	dcopy.append((char*)mac, AES_BLOCK_BYTES);
	mac[0] = 0;

	AesInitKey(&Ctx, AesKeyV4, FALSE, V4_KEY_BYTES);
	for (i = 0; i <= len; i += AES_BLOCK_BYTES)
	{
		XorBlock((const BYTE*)dcopy.c_str() + i, mac);
		AesEncryptBlock(&Ctx, mac);
	}
	memcpy(hash, mac, AES_BLOCK_BYTES);
}

static int kms_io4(const string& reqin, string & reqout)
{
	REQUEST_V4 * req = (REQUEST_V4*) reqin.c_str();
	if (reqin.size() != sizeof(REQUEST_V4)) return E_INVALIDARG;
	RESPONSE_V4 res;
	if (!create_response_base(&res.ResponseBase, &req->RequestBase))
		return E_FAIL;

	CSerialize<PolicyBinary> sst;
	sst << res.ResponseBase.Version
		<< res.ResponseBase.PIDSize
		<< serialize_str_wrap_t<WCHAR, PID_BUFFER_SIZE>(res.ResponseBase.KmsPID)
		<< res.ResponseBase.CMID
		<< res.ResponseBase.ClientTime
		<< res.ResponseBase.Count
		<< res.ResponseBase.VLActivationInterval
		<< res.ResponseBase.VLRenewalInterval;
	AesCmacV4(sst.get_doc().c_str(), sst.get_doc().size(), res.MAC);
	sst << res.MAC;
	reqout = sst.get_doc();
	return 0;
}


int kms_io(const void * reqin, size_t reqinsz, string & reqout)
{
	if (reqinsz < sizeof(REQUEST))
		return E_INVALIDARG;
	
	WORD majorVer = ((WORD*)reqin)[1];
	BYTE padsz;

	string reqcopy((char*)reqin, reqinsz);
	AesCtx aesCtx;
	switch (majorVer)
	{
	case 4:
		if (reqinsz < sizeof(REQUEST_V4)) return E_INVALIDARG;
		return kms_io4(reqcopy, reqout);
		break;
	case 5: case 6:
		if ((reqinsz - 4) % AES_BLOCK_BYTES) return E_INVALIDARG;
		if (majorVer == 5 && reqinsz < sizeof(REQUEST_V5)) return E_INVALIDARG;
		if (majorVer == 6 && reqinsz < sizeof(REQUEST_V6)) return E_INVALIDARG;

		if (majorVer == 5)
			AesInitKey(&aesCtx, AesKeyV5, false, AES_KEY_BYTES);
		else
			AesInitKey(&aesCtx, AesKeyV6, true, AES_KEY_BYTES);
		AesDecryptCbc(&aesCtx, NULL, (BYTE*) &reqcopy[4], reqinsz - 4);
		padsz = reqcopy.back();
		if (padsz >= 1 && padsz <= 16 && all_same(reqcopy.c_str()+reqinsz-padsz, reqcopy.c_str()+reqinsz-1))
		{
			reqcopy.resize(reqinsz - padsz);
			return kms_io56(&aesCtx, reqcopy, reqout);
		}
		else
			return E_INVALIDARG;
		break;
	default:
		break;
	}
	return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
}

//init globally.
intptr_t g_init_xxx = (intptr_t)&CKMSServer::Instance();
