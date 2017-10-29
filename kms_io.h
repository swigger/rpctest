#pragma once

#define PID_BUFFER_SIZE 64
// Constants for V6 time stamp interval
#define TIME_C1 0x00000022816889BDULL
#define TIME_C2 0x000000208CBAB5EDULL
#define TIME_C3 0x3156CD5AC628477AULL

typedef struct {
	DWORD Version;
	DWORD VMInfo;                   // 0 = client is bare metal / 1 = client is VM
	DWORD LicenseStatus;            // 0 = Unlicensed, 1 = Licensed (Activated), 2 = OOB grace, 3 = OOT grace, 4 = NonGenuineGrace, 5 = Notification, 6 = extended grace
	DWORD BindingExpiration;        // Expiration of the current status in minutes (e.g. when KMS activation or OOB grace expires).
	GUID AppID;                     // Can currently be Windows, Office2010 or Office2013 (see kms.c, table AppList).
	GUID ActID;                     // Most detailed product list. One product key per ActID (see kms.c, table ExtendedProductList). Is ignored by KMS server.
	GUID KMSID;                     // This is actually what the KMS server uses to grant or refuse activation (see kms.c, table BasicProductList).
	GUID CMID;                      // Client machine id. Used by the KMS server for counting minimum clients.
	DWORD N_Policy;                 // Minimum clients required for activation.
	FILETIME ClientTime;            // Current client time.
	GUID CMID_prev;                 // previous client machine id. All zeros, if it never changed.
	WCHAR WorkstationName[64];      // Workstation name. FQDN if available, NetBIOS otherwise.
} /*__packed*/ REQUEST;

typedef struct {
	REQUEST RequestBase;            // Base request
	BYTE MAC[16];                   // Aes 160 bit CMAC
} /*__packed*/ REQUEST_V4;

typedef struct {
	DWORD Version;                  // unencrypted version info
	BYTE IV[16];                    // IV
	REQUEST RequestBase;            // Base Request
	BYTE Pad[4];                    // since this struct is fixed, we use fixed PKCS pad bytes
} /*__packed*/ REQUEST_V5, REQUEST_V6;

typedef struct {
	DWORD Version;
	DWORD PIDSize;                  // Size of PIDData in bytes.
	WCHAR KmsPID[PID_BUFFER_SIZE];  // ePID (must include terminating zero)
	GUID CMID;                      // Client machine id. Must be the same as in request.
	FILETIME ClientTime;            // Current client time. Must be the same as in request.
	DWORD Count;                    // Current activated machines. KMS server counts up to N_Policy << 1 then stops
	DWORD VLActivationInterval;     // Time in minutes when clients should retry activation if it was unsuccessful (default 2 hours)
	DWORD VLRenewalInterval;        // Time in minutes when clients should renew KMS activation (default 7 days)
} /*__packed*/ RESPONSE;

typedef struct {
	RESPONSE ResponseBase;          // Base response
	BYTE MAC[16];                   // Aes 160 bit CMAC
} /*__packed*/ RESPONSE_V4;

typedef struct {					// not used except for sizeof(). Fields are the same as RESPONSE_V6
	DWORD Version;
	BYTE IV[16];
	RESPONSE ResponseBase;
	BYTE RandomXoredIVs[16];
	BYTE Hash[32];
} /*__packed*/ RESPONSE_V5;

typedef struct {
	DWORD Version;
	BYTE IV[16];
	RESPONSE ResponseBase;
	BYTE RandomXoredIVs[16];		// If RequestIV was used for decryption: Random ^ decrypted Request IV ^ ResponseIV. If NULL IV was used for decryption: Random ^ decrypted Request IV
	BYTE Hash[32];					// SHA256 of Random used in RandomXoredIVs
	BYTE HwId[8];					// HwId from the KMS server
	BYTE XoredIVs[16];				// If RequestIV was used for decryption: decrypted Request IV ^ ResponseIV. If NULL IV was used for decryption: decrypted Request IV.
	BYTE HMAC[16];					// V6 Hmac (low 16 bytes only), see kms.c CreateV6Hmac
	//BYTE Pad[10];					// Pad is variable sized. So do not include in struct
} /*__packed*/ RESPONSE_V6;

#define RESPONSE_RESULT_OK ((1 << 10) - 1) //(9 bits)
typedef union
{
	uint32_t mask;
	struct
	{
		uint32_t HashOK : 1;
		uint32_t TimeStampOK : 1;
		uint32_t ClientMachineIDOK : 1;
		uint32_t VersionOK : 1;
		uint32_t IVsOK : 1;
		uint32_t DecryptSuccess : 1;
		uint32_t HmacSha256OK : 1;
		uint32_t PidLengthOK : 1;
		uint32_t RpcOK : 1;
		uint32_t IVnotSuspicious : 1;
		uint32_t reserved3 : 1;
		uint32_t reserved4 : 1;
		uint32_t reserved5 : 1;
		uint32_t reserved6 : 1;
		uint32_t effectiveResponseSize : 9;
		uint32_t correctResponseSize : 9;
	};
} RESPONSE_RESULT;

typedef BYTE hwid_t[8];

class CKMSServer
{
public:
	struct KMSHostOS
	{
		uint16_t Type;
		uint16_t Build;
	};
	struct KmsData {
		GUID guid;
		uint32_t EPidIdx;
		const char * name;
	};
	struct VLKData {
		DWORD GroupId;
		DWORD MinKeyId;
		DWORD MaxKeyId;
		DWORD MinActiveClients;
	};
	struct KmsData_Raw
	{
		const char * Guid;
		uint32_t EpidIndex;
		const char * name;
	};
protected:
	struct KmsData_hash {
		uint64_t operator () (const KmsData & d) const
		{
			uint64_t  * pe = (uint64_t*)&d.guid;
			return pe[0] ^ pe[1];
		}
	};
	struct KmsData_eq {
		bool operator () (const KmsData & l, const KmsData & r) const
		{
			return IsEqualGUID(l.guid, r.guid);
		}
	};

protected:
	KMSHostOS m_os;
	std::unordered_set<KmsData, KmsData_hash, KmsData_eq> m_kmsd;

protected:
	CKMSServer();
public:
	uint32_t Type() const { return m_os.Type; }
	uint32_t Build() const { return m_os.Build; }
	static CKMSServer & Instance();
	void RandPid(const GUID & kmsguid, WCHAR * outpid, int * ncount);
};

int kms_io(const void * reqin, size_t reqinsz, string & reqout);
