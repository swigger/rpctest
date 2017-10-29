#include "stdafx.h"
#include "aes.h"
#include "kms_i.h"
#include "kms_io.h"
#include "shared.h"
#include "dbgdump.h"

GUID SkuGuid, KmsGuid, AppGuid;


// Create Encrypted KMS Client Request Data for KMS Protocol Version 6
BYTE* CreateRequestV6(size_t *size, const REQUEST* requestBase)
{
	*size = sizeof(REQUEST_V6);

	// Temporary Pointer for access to REQUEST_V5 structure
	REQUEST_V6 *request = (REQUEST_V6 *)malloc(sizeof(REQUEST_V6));

	// KMS Protocol Version
	request->Version = requestBase->Version;

	// Initialize the IV
	get_random_bytes(request->IV, sizeof(request->IV));

	// Set KMS Client Request Base
	memcpy(&request->RequestBase, requestBase, sizeof(REQUEST));

	// Encrypt KMS Client Request
	size_t encryptSize = sizeof(request->RequestBase);
	AesCtx Ctx;
	int_fast8_t v6 = request->Version >= 0x60000;
	AesInitKey(&Ctx, v6 ? AesKeyV6 : AesKeyV5, v6, 16);
	AesEncryptCbc(&Ctx, request->IV, (BYTE*)(&request->RequestBase), &encryptSize);

	// Return Proper Request Data
	return (BYTE*)request;
}

#define V6_UNENCRYPTED_SIZE	( \
								sizeof(((RESPONSE_V6*)0)->Version) + \
								sizeof(((RESPONSE_V6*)0)->IV) \
							)

#define V4_POST_EPID_SIZE 	( \
								sizeof(((RESPONSE*)0)->CMID) + \
								sizeof(((RESPONSE*)0)->ClientTime) + \
								sizeof(((RESPONSE*)0)->Count) + \
								sizeof(((RESPONSE*)0)->VLActivationInterval) + \
								sizeof(((RESPONSE*)0)->VLRenewalInterval) \
							)

#define V5_POST_EPID_SIZE 	( \
								V4_POST_EPID_SIZE + \
								sizeof(((RESPONSE_V6*)0)->RandomXoredIVs) + \
								sizeof(((RESPONSE_V6*)0)->Hash) \
							)
#define V6_POST_EPID_SIZE 	( \
								V5_POST_EPID_SIZE + \
								sizeof(((RESPONSE_V6*)0)->HwId) + \
								sizeof(((RESPONSE_V6*)0)->XoredIVs) + \
								sizeof(((RESPONSE_V6*)0)->HMAC) \
							)


/*
* Checks whether Length of ePID is valid
*/
static uint8_t checkPidLength(const RESPONSE *const responseBase)
{
	unsigned int i;

	if (responseBase->PIDSize > (PID_BUFFER_SIZE << 1)) return FALSE;
	if (responseBase->KmsPID[(responseBase->PIDSize >> 1) - 1]) return FALSE;

	for (i = 0; i < (responseBase->PIDSize >> 1) - 2; i++)
	{
		if (!responseBase->KmsPID[i]) return FALSE;
	}

	return TRUE;
}


/*
* Creates the HMAC for v6
*/
static int_fast8_t CreateV6Hmac(BYTE *const encrypt_start, const size_t encryptSize, int_fast8_t tolerance)
{
	BYTE hash[32];
	const uint8_t halfHashSize = sizeof(hash) >> 1;
	BYTE *responseEnd = encrypt_start + encryptSize;

	// This is the time from the response
	FILETIME* ft = (FILETIME*)(responseEnd - V6_POST_EPID_SIZE + sizeof(((RESPONSE*)0)->CMID));

	// Generate a time slot that changes every 4.11 hours.
	// Request and repsonse time must match +/- 1 slot.
	// When generating a response tolerance must be 0.
	// If verifying the hash, try tolerance -1, 0 and +1. One of them must match.

	uint64_t timeSlot = ((*(uint64_t*)(ft) / TIME_C1 * TIME_C2 + TIME_C3) + (tolerance * TIME_C1));

	// The time slot is hashed with SHA256 so it is not so obvious that it is time
	Sha256((BYTE*)&timeSlot, sizeof(timeSlot), hash);

	// The last 16 bytes of the hashed time slot are the actual HMAC key
	if (!Sha256Hmac
	(
		hash + halfHashSize,									// Use last 16 bytes of SHA256 as HMAC key
		encrypt_start,											// hash only the encrypted part of the v6 response
		(DWORD)(encryptSize - sizeof(((RESPONSE_V6*)0)->HMAC)),	// encryptSize minus the HMAC itself
		hash													// use same buffer for resulting hash where the key came from
	))
	{
		return FALSE;
	}

	memcpy(responseEnd - sizeof(((RESPONSE_V6*)0)->HMAC), hash + halfHashSize, halfHashSize);
	return TRUE;
}


static RESPONSE_RESULT VerifyResponseV5(RESPONSE_RESULT result, REQUEST_V5* request_v5, RESPONSE_V5* response_v5)
{
	// Check IVs: in V5 (and only v5) request and response IVs must match
	result.IVsOK = !memcmp(request_v5->IV, response_v5->IV, sizeof(request_v5->IV));

	// V5 has no Hmac, always set to TRUE
	result.HmacSha256OK = TRUE;

	return result;
}

static RESPONSE_RESULT VerifyResponseV6(RESPONSE_RESULT result, RESPONSE_V6* response_v6, REQUEST_V6* request_v6, BYTE* const rawResponse)
{
	// Check IVs
	result.IVsOK = !memcmp // In V6 the XoredIV is actually the request IV
	(
		response_v6->XoredIVs,
		request_v6->IV,
		sizeof(response_v6->XoredIVs)
	);

	result.IVnotSuspicious = !!memcmp // If IVs are identical, it is obviously an emulator
	(
		request_v6->IV,
		response_v6->IV,
		sizeof(request_v6->IV)
	);

	// Check Hmac
	int_fast8_t tolerance;
	BYTE OldHmac[sizeof(response_v6->HMAC)];

	result.HmacSha256OK = FALSE;

	memcpy	// Save received HMAC to compare with calculated HMAC later
	(
		OldHmac,
		response_v6->HMAC,
		sizeof(response_v6->HMAC)
	);

	//AesEncryptBlock(Ctx, Response_v6->IV); // CreateV6Hmac needs original IV as received over the network

	for (tolerance = -1; tolerance < 2; tolerance++)
	{
		CreateV6Hmac
		(
			rawResponse + sizeof(response_v6->Version),                          // Pointer to start of the encrypted part of the response
			(size_t)result.correctResponseSize - sizeof(response_v6->Version),   // size of the encrypted part
			tolerance                                                            // tolerance -1, 0, or +1
		);

		result.HmacSha256OK = !memcmp // Compare both HMACs
		(
			OldHmac,
			rawResponse + (size_t)result.correctResponseSize - sizeof(response_v6->HMAC),
			sizeof(OldHmac)
		);

		if (result.HmacSha256OK) break;
	}

	return result;
}


/*
* Decrypts a KMS v5 or v6 response received from a server.
* hwid must supply a valid 16 byte buffer for v6. hwid is ignored in v5
*/
RESPONSE_RESULT DecryptResponseV6(RESPONSE_V6* response_v6, int responseSize, BYTE* const response, const BYTE* const rawRequest, BYTE* hwid)
{
	RESPONSE_RESULT result;
	result.mask = (DWORD)~0; // Set all bits in the results mask to 1. Assume success first.
	result.effectiveResponseSize = responseSize;

	int copySize1 =
		sizeof(response_v6->Version);

	// Decrypt KMS Server Response (encrypted part starts after RequestIV)
	responseSize -= copySize1;

	AesCtx Ctx;
	int_fast8_t v6 = ((RESPONSE_V6*)response)->Version >= 0x60000;

	AesInitKey(&Ctx, v6 ? AesKeyV6 : AesKeyV5, v6, AES_KEY_BYTES);
	AesDecryptCbc(&Ctx, NULL, response + copySize1, responseSize);

	// Check padding
	BYTE* lastPadByte = response + (size_t)result.effectiveResponseSize - 1;

	// Must be from 1 to 16
	if (!*lastPadByte || *lastPadByte > AES_BLOCK_BYTES)
	{
		result.DecryptSuccess = FALSE;
		return result;
	}

	// Check if pad bytes are all the same
	BYTE* padByte;
	for (padByte = lastPadByte - *lastPadByte + 1; padByte < lastPadByte; padByte++)
	{
		if (*padByte != *lastPadByte)
		{
			result.DecryptSuccess = FALSE;
			return result;
		}
	}

	// Add size of Version, KmsPIDLen and variable size PID
	DWORD pidSize = ((RESPONSE_V6*)response)->ResponseBase.PIDSize;

	copySize1 +=
		V6_UNENCRYPTED_SIZE +
		sizeof(response_v6->ResponseBase.PIDSize) +
		(pidSize <= PID_BUFFER_SIZE << 1 ? pidSize : PID_BUFFER_SIZE << 1);

	// Copy part 1 of response up to variable sized PID
	memcpy(response_v6, response, copySize1);

	// ensure PID is null terminated
	response_v6->ResponseBase.KmsPID[PID_BUFFER_SIZE - 1] = 0;

	// Copy part 2
	size_t copySize2 = v6 ? V6_POST_EPID_SIZE : V5_POST_EPID_SIZE;
	memcpy(&response_v6->ResponseBase.CMID, response + copySize1, copySize2);

	// Decrypting the response is finished here. Now we check the results for validity
	// A basic client doesn't need the stuff below this comment but we want to use vlmcs
	// as a debug tool for KMS emulators.

	REQUEST_V6* request_v6 = (REQUEST_V6*)rawRequest;
	DWORD decryptSize = sizeof(request_v6->IV) + sizeof(request_v6->RequestBase) + sizeof(request_v6->Pad);

	AesDecryptCbc(&Ctx, NULL, request_v6->IV, decryptSize);

	// Check that all version informations are the same
	result.VersionOK =
		request_v6->Version == response_v6->ResponseBase.Version &&
		request_v6->Version == response_v6->Version &&
		request_v6->Version == request_v6->RequestBase.Version;

	// Check Base Request
	result.PidLengthOK = checkPidLength(&((RESPONSE_V6*)response)->ResponseBase);
	result.TimeStampOK = !memcmp(&response_v6->ResponseBase.ClientTime, &request_v6->RequestBase.ClientTime, sizeof(FILETIME));
	result.ClientMachineIDOK = IsEqualGUID(response_v6->ResponseBase.CMID, request_v6->RequestBase.CMID);

	// Rebuild Random Key and Sha256 Hash
	BYTE HashVerify[sizeof(response_v6->Hash)];
	BYTE RandomKey[sizeof(response_v6->RandomXoredIVs)];

	memcpy(RandomKey, request_v6->IV, sizeof(RandomKey));
	XorBlock(response_v6->RandomXoredIVs, RandomKey);
	Sha256(RandomKey, sizeof(RandomKey), HashVerify);

	result.HashOK = !memcmp(response_v6->Hash, HashVerify, sizeof(HashVerify));

	// size before encryption (padding not included)
	result.correctResponseSize =
		(v6 ? sizeof(RESPONSE_V6) : sizeof(RESPONSE_V5))
		- sizeof(response_v6->ResponseBase.KmsPID)
		+ response_v6->ResponseBase.PIDSize;

	// Version specific stuff
	if (v6)
	{
		// Copy the HwId
		memcpy(hwid, response_v6->HwId, sizeof(response_v6->HwId));

		// Verify the V6 specific part of the response
		result = VerifyResponseV6(result, response_v6, request_v6, response);
	}
	else // V5
	{
		// Verify the V5 specific part of the response
		result = VerifyResponseV5(result, request_v6, (RESPONSE_V5*)response_v6);
	}

	// padded size after encryption
	result.correctResponseSize += (~(result.correctResponseSize - sizeof(response_v6->ResponseBase.Version)) & 0xf) + 1;

	return result;
}


static void CreateRequestBase(REQUEST *Request)
{
	Request->Version = 0x60000;
	Request->VMInfo = 0; //is_vm (VMInfo);
	Request->LicenseStatus = 2;
	Request->BindingExpiration = 43200;
	Request->N_Policy = 5; //minimum required client count

	memcpy(&Request->ActID, &SkuGuid, sizeof(GUID));
	memcpy(&Request->KMSID, &KmsGuid, sizeof(GUID));
	memcpy(&Request->AppID, &AppGuid, sizeof(GUID));

	//getUnixTimeAsFileTime(&Request->ClientTime);
	GetSystemTimeAsFileTime(&Request->ClientTime);
	CoCreateGuid(&Request->CMID);
	CoCreateGuid(&Request->CMID_prev);
	// Set reserved UUID bits
	Request->CMID.Data4[0] &= 0x3F;
	Request->CMID.Data4[0] |= 0x80;

	wcscpy(Request->WorkstationName, L"hohoho-pc");
}

int main()
{
	WSADATA wsd;
	SetConsoleOutputCP(65001);
	WSAStartup(0x202, &wsd);
	srand((uint32_t)time(0) * 1000 + GetTickCount());

	RPC_WSTR cpstr = 0;
	RpcStringBindingCompose(NULL, (RPC_WSTR)L"ncacn_ip_tcp", (RPC_WSTR)L"127.0.0.1" /*NULL*/, (RPC_WSTR)L"1689", NULL, &cpstr);
	RpcBindingFromStringBinding(cpstr, &kms_netHandle);
	
	REQUEST br;
	CreateRequestBase(&br);
	size_t sz = 0;
	BYTE * pb = CreateRequestV6(&sz, &br);

	unsigned char * r = 0;
	int rsz = 0;
	int vv = RequestActivation((int)sz, pb, &rsz, &r);
	dump_hex(0, r, rsz, stdout);
	printf("rv=%d\n", vv);
	
	RESPONSE_V6 response_v6;
	RESPONSE_RESULT result;
	hwid_t hwid;
	result = DecryptResponseV6(&response_v6, (int)rsz, r, pb, hwid);
	//Helper::dump_hex(0, &response_v6, sizeof(response_v6), stdout);
	dbg_dump_responce(response_v6);
	//memcpy(baseResponse, &response_v6.ResponseBase, sizeof(RESPONSE));


	midl_user_free(r);
	RpcStringFree(&cpstr);
	RpcBindingFree(&kms_netHandle);

	return 0;
}

void * midl_user_allocate(size_t len)
{
	return(malloc(len));
}

void midl_user_free(void __RPC_FAR *ptr)
{
	free(ptr);
}
