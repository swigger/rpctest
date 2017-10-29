#include "stdafx.h"
#include "kms_i.h"
#include "shared.h"
#include "kms_io.h"

extern "C"
int RequestActivation(int requestSize, unsigned char *request, int *responseSize, unsigned char **response)
{
	string rr;
	int rv = kms_io(request, requestSize, rr);
	if (rv == 0)
	{
		*response = (unsigned char*)memcpy(malloc(rr.size()), rr.data(), rr.size());
		*responseSize = (int)rr.size();
	}
	else
	{
		*responseSize = 0;
		*response = 0;
	}
	return rv;
}

void Shutdown(void)
{
	RpcMgmtStopServerListening(NULL);
	RpcServerUnregisterIf(NULL, NULL, FALSE);
}

int main()
{
	WSADATA wsd;
	SetConsoleOutputCP(65001);
	WSAStartup(0x202, &wsd);

	//RpcServerUseProtseqEp("ncacn_np", 20, "\\pipe\\unique.name", NULL);
	LONG a = RpcServerUseProtseqEp((RPC_WSTR)L"ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_WSTR)L"1688", NULL);
	if (a)
	{
		fprintf(stderr, "RpcServerUseProtseqEp error: %d %s\n", a, errmsg(a).c_str());
		return a;
	}

	a = RpcServerRegisterIfEx(KMSServer_v1_0_s_ifspec, NULL, NULL, RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH, RPC_C_LISTEN_MAX_CALLS_DEFAULT, NULL);
	if (a)
	{
		fprintf(stderr, "RpcServerRegisterIfEx error: %d %s\n", a, errmsg(a).c_str());
		return a;
	}

	return RpcServerListen(0, RPC_C_LISTEN_MAX_CALLS_DEFAULT, 0/*block*/);
}

void * midl_user_allocate(size_t len)
{
	return(malloc(len));
}

void midl_user_free(void __RPC_FAR *ptr)
{
	free(ptr);
}
