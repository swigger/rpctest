#include "stdafx.h"
#include "kms_i.h"
#include <string>
using std::string;


int main()
{
	WSADATA wsd;
	SetConsoleOutputCP(65001);
	WSAStartup(0x202, &wsd);

	RPC_WSTR cpstr = 0;
	RpcStringBindingCompose(NULL, (RPC_WSTR)L"ncacn_ip_tcp", (RPC_WSTR)L"127.0.0.1" /*NULL*/, (RPC_WSTR)L"1689", NULL, &cpstr);
	RpcBindingFromStringBinding(cpstr, &kms_netHandle);

	string req("hello");
	unsigned char * r = 0;
	int rsz = 0;
	int vv = RequestActivation((int)req.size(), (BYTE*) req.c_str(), &rsz, &r);
	printf("s=%s\nrv=%d\n", r, vv);
	
	midl_user_free(r);
	RpcStringFree(&cpstr);
	RpcBindingFree(&kms_netHandle);

	return 0;
}
