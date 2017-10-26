#include "stdafx.h"
#include "kms_i.h"


string errmsg(DWORD msgid)
{
	LPTSTR lpMsgBuf = 0;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, msgid, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf, 0, NULL);
	string sa;
	sa.resize(wcslen(lpMsgBuf) * 3 + 10);
	int n = WideCharToMultiByte(CP_UTF8, 0, lpMsgBuf, -1, &sa[0], (int)sa.length(), 0, 0);
	if (n <= 0) sa.clear();
	else sa.resize(n);
	LocalFree(lpMsgBuf);
	return sa;
}


void * midl_user_allocate(size_t len)
{
	return(malloc(len));
}

void midl_user_free(void __RPC_FAR *ptr)
{
	free(ptr);
}
