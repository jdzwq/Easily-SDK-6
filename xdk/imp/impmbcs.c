/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc mbcs document

	@module	impmbcs.c | implement file

	@devnote 张文权 2021.01 - 2021.12	v6.0
***********************************************************************/

/**********************************************************************
This program is free software : you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
LICENSE.GPL3 for more details.
***********************************************************************/

#include "impmbcs.h"

#include "../xdkstd.h"
#include "../xdkimp.h"

#ifdef XDK_SUPPORT_MBCS

int sys_gbk_code_sequence(byte_t b)
{
	if ((b & ~0x7F) == 0)
		return 1;

	if (0xa1 <= b && b <= 0xf7)
		return 2;

	return 2;
}

int sys_gbk_byte_to_ucs(const byte_t* src, wchar_t* dest)
{
	if_mbcs_t* pif;
	int cs;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	cs = sys_gbk_code_sequence(*src);

	return (*pif->pf_gbk_to_ucs)((schar_t*)src, cs, dest, 1);
}

int sys_gbk_to_ucs(const byte_t* src, dword_t slen, wchar_t* dest, int dlen)
{
	if_mbcs_t* pif;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_gbk_to_ucs)((schar_t*)src, slen, dest, dlen);
}

int sys_ucs_byte_to_gbk(wchar_t ch, byte_t* buf)
{
	if_mbcs_t* pif;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_ucs_to_gbk)(&ch, 1, buf, 2);
}

int sys_ucs_to_gbk(const wchar_t* src, int slen, byte_t* dest, dword_t dlen)
{
	if_mbcs_t* pif;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	if (src && slen < 0)
	{
		slen = 0;
		while (*(src + slen))
			slen++;
	}

	return (*pif->pf_ucs_to_gbk)(src, slen, dest, dlen);
}

int sys_utf_code_sequence(byte_t b)
{
	if (b == 0xFF) //_UTF16_LIT
		return 2;
	else if (b == 0xFE) //_UTF16_BIG
		return 2;

	if ((b & ~0x7F) == 0) {
		return 1;
	}
	//if ((b & 0xC0) != 0xC0) {
	//return 0;
	//}
	if ((b & 0xE0) == 0xC0) {
		return 2;
	}
	if ((b & 0xF0) == 0xE0) {
		return 3;
	}
	if ((b & 0xF8) == 0xF0) {
		return 4;
	}

	return 1;
}

int sys_utf_byte_to_ucs(const byte_t* src, wchar_t* dest)
{
	if_mbcs_t* pif;
	int cs;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	cs = sys_utf_code_sequence(*src);

	return (*pif->pf_utf_to_ucs)((schar_t*)src, cs, dest, 1);
}

int sys_utf_to_ucs(const byte_t* src, dword_t slen, wchar_t* dest, int dlen)
{
	if_mbcs_t* pif;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_utf_to_ucs)((schar_t*)src, slen, dest, dlen);
}

int sys_ucs_byte_to_utf(wchar_t ch, byte_t* buf)
{
	if_mbcs_t* pif;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_ucs_to_utf)(&ch, 1, buf, 3);
}

int sys_ucs_to_utf(const wchar_t* src, int slen, byte_t* dest, dword_t dlen)
{
	if_mbcs_t* pif;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	if (src && slen < 0)
	{
		slen = 0;
		while (*(src + slen))
			slen++;
	}

	return (*pif->pf_ucs_to_utf)(src, slen, dest, dlen);
}

#if defined (DEBUG) || defined (_DEBUG)
void mbcs_self_test()
{
	printf("test mbcs converting...\n");

	char chs[4];
	wchar_t wc = L'中';
	int s;

#if DEF_MBS == _GB2312
	s = sys_ucs_byte_to_gbk(wc, (byte_t*)chs);
	printf("gb2312 characterset: %s, %dbytes\n", chs, s);
#else
	s = sys_ucs_byte_to_utf(wc, (byte_t*)chs);
	printf("utf8 characterset: %s, %dbytes\n", chs, s);
#endif

	schar_t* mbs_token = "A多BC字节中文";
	wchar_t* ucs_token = L"A宽字B节C中文";

	byte_t utf_buf[100] = {0};
	schar_t mbs_buf[100] = {0};
	wchar_t ucs_buf[100] = {0};

#if DEF_MBS == _GB2312
	s = sys_ucs_to_gbk(ucs_token, -1, utf_buf, 100);
	printf("unicode to utf8: %s, %dbytes\n", utf_buf, s);
#else
	s = sys_ucs_to_utf(ucs_token, -1, utf_buf, 100);
	printf("unicode to utf8: %s, %dbytes\n", utf_buf, s);
#endif

#if DEF_MBS == _GB2312
	s = a_xslen(mbs_token);
	s = sys_gbk_to_ucs(mbs_token, s, ucs_buf, 100);
	wprintf(L"gb2312 to unicode: %s, %dbytes\n", ucs_buf, s);
#else
	s = a_xslen(mbs_token);
	s = sys_utf_to_ucs(mbs_token, s, ucs_buf, 100);
	wprintf(L"utf8 to unicode: %S, %dbytes\n", ucs_buf, s);
#endif
}
#endif

#endif /*XDK_SUPPORT_MBCS*/
