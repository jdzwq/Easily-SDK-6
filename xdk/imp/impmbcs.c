﻿/***********************************************************************
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

#include "../xdkimp.h"
#include "../xdkstd.h"

#ifdef XDK_SUPPORT_MBCS

int gbk_code_sequence(byte_t b)
{
	if ((b & ~0x7F) == 0)
		return 1;

	if (0xa1 <= b && b <= 0xf7)
		return 2;

	return 2;
}

int gbk_byte_to_ucs(const byte_t* src, wchar_t* dest)
{
	if_mbcs_t* pif;
	int cs;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	cs = gbk_code_sequence(*src);

	return (*pif->pf_gbk_to_ucs)((schar_t*)src, cs, dest, 1);
}

int gbk_to_ucs(const byte_t* src, dword_t slen, wchar_t* dest, int dlen)
{
	if_mbcs_t* pif;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_gbk_to_ucs)((schar_t*)src, slen, dest, dlen);
}

int ucs_byte_to_gbk(wchar_t ch, byte_t* buf)
{
	if_mbcs_t* pif;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_ucs_to_gbk)(&ch, 1, buf, 2);
}

int ucs_to_gbk(const wchar_t* src, int slen, byte_t* dest, dword_t dlen)
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

int utf_code_sequence(byte_t b)
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

int utf_byte_to_ucs(const byte_t* src, wchar_t* dest)
{
	if_mbcs_t* pif;
	int cs;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	cs = utf_code_sequence(*src);

	return (*pif->pf_utf_to_ucs)((schar_t*)src, cs, dest, 1);
}

int utf_to_ucs(const byte_t* src, dword_t slen, wchar_t* dest, int dlen)
{
	if_mbcs_t* pif;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_utf_to_ucs)((schar_t*)src, slen, dest, dlen);
}

int ucs_byte_to_utf(wchar_t ch, byte_t* buf)
{
	if_mbcs_t* pif;

	pif = PROCESS_MBCS_INTERFACE;

	XDK_ASSERT(pif != NULL);

	return (*pif->pf_ucs_to_utf)(&ch, 1, buf, 3);
}

int ucs_to_utf(const wchar_t* src, int slen, byte_t* dest, dword_t dlen)
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

#endif //XDK_SUPPORT_MBCS
