#include "stdafx.h"
#include "shared.h"
#include <time.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

void Sha256(BYTE *data, size_t len, BYTE *hash)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, len);
	SHA256_Final(hash, &ctx);
}

int8_t Sha256Hmac(BYTE* key, BYTE*  data, DWORD len, BYTE*  hmac)
{
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, 16, EVP_sha256(), NULL);
	HMAC_Update(&ctx, data, len);
	HMAC_Final(&ctx, hmac, NULL);
	HMAC_cleanup(&ctx);
	return TRUE;
}


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

uint32_t BE32(uint32_t v)
{
	return _byteswap_ulong(v);
}

uint64_t BE64(uint64_t v)
{
	return _byteswap_uint64(v);
}

void get_random_bytes(void * buf, size_t sz)
{
	std::generate((char*)buf, (char*)buf + sz, xrand);
}

void UUID2String(const GUID *const guid, char *const s)
{
	sprintf(s, "%08x-%04x-%04x-%02x%02x-%012llx",
		(unsigned int)guid->Data1,
		(unsigned int)guid->Data2,
		(unsigned int)guid->Data3,
		guid->Data4[0], guid->Data4[1],
		(unsigned long long)BE64(*(uint64_t*)(guid->Data4)) & 0xffffffffffffLL
	);
}

//Converts a String Guid to a host binary guid in host endianess
bool String2UUID(const char * input, GUID * guid)
{
	uint16_t tmp = 0;
	uint64_t tmp2 = 0;
	if (input[0] == '{') ++input;
	if (sscanf(input, "%lx-%hx-%hx-%hx-%llx", &guid->Data1, &guid->Data2, &guid->Data3, &tmp, &tmp2) == 5)
	{
		*(uint64_t*)guid->Data4 = BE64(tmp2);
		guid->Data4[0] = tmp >> 8;
		guid->Data4[1] = (BYTE)tmp;
		return TRUE;
	}
	return false;
}

void FILETIME2String(const FILETIME * ft, char * s)
{
	time_t t = *(uint64_t*)(ft) / 10000000LL - 11644473600LL;
	struct tm * tt = localtime(&t);
	sprintf(s, "%04d-%02d-%02d %02d:%02d:%02d",
		tt->tm_year + 1900, tt->tm_mon + 1, tt->tm_mday,
		tt->tm_hour, tt->tm_min, tt->tm_sec);
}

static inline void addch(string & os, int ch)
{
	os += (char)ch;
}

string utf16to8(const WCHAR * s, int n)
{
	string os;
	//get the string length.
	if (n < 0)
	{
		for (int x = 0;; ++x) if (s[x] == 0) { n = x; break; }
	}
	else
	{
		for (int x = 0; x<n; ++x) if (s[x] == 0) { n = x; break; }
	}
	os.reserve(n * 3 + 3);

	int err = 0;
	for (size_t i = 0; i<(size_t)n; ++i)
	{
		unsigned short ch = s[i];
		if (ch<0x80)
			addch(os, ch);
		else if (ch <= 0x3ff)
		{
			addch(os, 0xc0 | (ch >> 6));
			addch(os, 0x80 | (ch & 0x3f));
		}
		else if (ch<0xd800 || ch>0xdfff)
		{
			addch(os, 0xe0 | (ch >> 12));
			addch(os, 0x80 | ((ch >> 6) & 0x3f));
			addch(os, 0x80 | (ch & 0x3f));
		}
		else if (ch<0xdc00 && i+1 < (size_t)n)
		{
			unsigned short ch1 = s[i + 1];
			if (ch1 >= 0xdc00 && ch1 <= 0xdfff)
			{
				unsigned int k = 0x10000 + ((ch - 0xd800) << 10) + (ch1 - 0xdc00);
				addch(os, 0xf0 | (k >> 18));
				addch(os, 0x80 | ((k >> 12) & 0x3f));
				addch(os, 0x80 | ((k >> 6) & 0x3f));
				addch(os, 0x80 | (k & 0x3f));
				++i;
			}
			else
			{
				addch(os, '?');
				err++;
			}
		}
		else
		{
			addch(os, '?');
			err++;
		}
	}
	return os;
}

//glibc's implemention of rand, make it thread-unsafe.
//Ahhh? do you need thread-safe for a "random" function? unsafe means more random!
#define NELE 512
unsigned int xrand()
{
	static int r[NELE];
	static int i = 0, v = 0;
	int o;
	if (v == 0)
	{
		//r[0] = getpid() * 10000 + (unsigned int)time(0) * 1000;
		r[0] = (uint32_t)time(0) * GetCurrentThreadId() + GetTickCount();
		for (i = 1; i<31; i++) {
			r[i] = (16807LL * r[i - 1]) % 2147483647;
			if (r[i] < 0) {
				r[i] += 2147483647;
			}
		}
		for (i = 31; i<34; i++) {
			r[i] = r[i - 31];
		}
		for (i = 34; i<344; i++) {
			r[i] = r[i - 31] + r[i - 3];
		}
		v = 1;
	}
	o = r[i%NELE] = r[(i - 31) % NELE] + r[(i - 3) % NELE];
	++i;
	return ((unsigned int)o) >> 1;
}

size_t dump_hex(uintptr_t spos, const void * buf, size_t sz, FILE * fo)
{
	string s;
	dump_hex(spos, buf, sz, s);
	fwrite(s.data(), 1, s.length(), fo);
	return s.length();
}

const char * dump_hex(uintptr_t stpos, const void * buf, size_t sz, string & sa)
{
	size_t osz = sa.length();
	if (!buf)
	{
		sa += "(null)\r\n";
		return sa.c_str() + osz;
	}

	const char * hextbl = "0123456789abcdef";
	char cbuf[100];

	for (size_t i = 0; i<sz; i += 16)
	{
		const char * ptr = (const char *)buf + i;
		uintptr_t addr = stpos + i;
		size_t l = sz - i; if (l>16) l = 16;
		char * os = cbuf;

		for (int j = 0; j<8; ++j)
		{
			int o = 4 * (8 - j - 1);
			*os++ = hextbl[0xf & (addr >> o)];
		}
		*os++ = ':';
		*os++ = ' ';
		*os++ = ' ';

		for (uint32_t i = 0; i<16; ++i)
		{
			if (i<l)
			{
				*os++ = hextbl[0xf & (ptr[i] >> 4)];
				*os++ = hextbl[0xf & (ptr[i])];
				*os++ = (i == 7 && l>8) ? '-' : ' ';
			}
			else
			{
				*os++ = ' ';
				*os++ = ' ';
				*os++ = ' ';
			}
		}
		*os++ = ' ';
		*os++ = ' ';
		*os++ = ' ';

		for (uint32_t i = 0; i<l; ++i)
		{
			unsigned char ch = ptr[i];
			*os++ = isprint(ch) ? ch : '.';
		}
		*os++ = '\r';
		*os++ = '\n';
		*os++ = 0;
		sa += cbuf;
	}
	return sa.c_str() + osz;
}

void def_log(int level, const char * msg, ...)
{
	va_list vl, vl1;
	va_start(vl, msg);
	va_copy(vl1, vl);

	if (level < -2) level = -2;
	if (level > 2) level = 2;
	const char * slvls[] = {
		"FATAL", "ERROR", "WARNING", "INFO", "DEBUG"
	};
	time_t t = time(0);

	struct tm * tt = localtime(&t);
	char prefix[100];
	char dt[10];
	char * pd = 0;
	sprintf(prefix, "%d-%02d-%02d %02d:%02d:%02d [%s] ",
		tt->tm_year + 1900, tt->tm_mon + 1, tt->tm_mday,
		tt->tm_hour, tt->tm_min, tt->tm_sec,
		slvls[level + 2]);
	int n = _vsnprintf(dt, sizeof(dt), msg, vl);
	if (n >= sizeof(dt) - 1)
	{
		pd = (char*)malloc(n + 10);
		_vsnprintf(pd, n + 10, msg, vl1);
	}
	else
		pd = dt;

	fprintf(stderr, "%s%s\n", prefix, pd);
	va_end(vl);
	va_end(vl1);
	if (pd != dt) free(pd);
}

void(*logfunc)(int level, const char * msg, ...) = def_log;
