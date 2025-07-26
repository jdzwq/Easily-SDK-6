/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc code page document

	@module	acp_unnicode.c | implement file

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

#include "acp.h"

#include "../xdkstd.h"

int acp_unicode_byte_to_gb2312(wchar_t ch, byte_t* buf)
{
#ifdef XDK_SUPPORT_ACP_TABLE
	return table_unicode_seek_gb2312((unsigned short)ch, (unsigned char*)buf);
#else
	return share_unicode_seek_gb2312((unsigned short)ch, (unsigned char*)buf);
#endif
}

int acp_unicode_to_gb2312(const wchar_t* src, int slen, byte_t* dest, dword_t dlen)
{
	int len = 0, total = 0;

	while (total < slen && len < dlen)
	{
#ifdef XDK_SUPPORT_ACP_TABLE
		len += table_unicode_seek_gb2312((unsigned short)(src[total]), ((dest) ? (unsigned char*)(dest + len) : NULL));
#else
		len += share_unicode_seek_gb2312((unsigned short)(src[total]), ((dest) ? (unsigned char*)(dest + len) : NULL));
#endif
		total++;
	}

	return len;
}

int acp_unicode_code_count(void)
{
	return (MAX_CHS_UNICODE - MIN_CHS_UNICODE + 1);
}

bool_t acp_next_unicode_char(byte_t* pch)
{
	byte_t h, l;

	h = pch[0];
	l = pch[1];

	if (!h && !l)
	{
		pch[0] = 0x4E;
		pch[1] = 0x00;
		return bool_true;
	}
	
	if (h == 0x9F && l == 0xA5)
	{
		pch[0] = 0x00;
		pch[1] = 0x00;
		return bool_false;
	}

	if (l == 0xFF)
	{
		h++;
		pch[0] = h;
		pch[1] = 0x00;
	}
	else
	{
		l++;
		pch[1] = l;
	}

	return bool_true;
}