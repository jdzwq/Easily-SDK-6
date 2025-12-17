/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc code page document

	@module	acp_gbk.c | implement file

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

int acp_gb2312_code_sequence(unsigned char b)
{
	if ((b & ~0x7F) == 0)
		return 1;

	//head
	if (0xa1 <= b && b <= 0xf7)
		return 2;

	//tail
	//if(0xa1 <= b && b <= 0xfe)
	//return 1;

	return 2;
}

int acp_gb2312_byte_to_unicode(const byte_t* src, wchar_t* dst)
{
	int len;
	unsigned short sch, uch;
	bool_t b;

	len = acp_gb2312_code_sequence(*src);

	if (len == 1)
	{
		if (dst)
		{
			*dst = (wchar_t)MAKESHORT(src[0], 0);
		}
		return 1;
	}

	sch = MAKESHORT(src[0], src[1]);

	b = share_gb2312_seek_unicode(sch, (unsigned short*)&uch);
	if(dst)
	{
		*dst = (b)? (wchar_t)uch : (wchar_t)ALT_CHAR;
	}

	return 1;
}

int acp_gb2312_to_unicode(const byte_t* src, dword_t slen, wchar_t* dest, int dlen)
{
	int len = 0;
	dword_t total = 0;

	while (total < slen && len < dlen)
	{
		len += acp_gb2312_byte_to_unicode(((unsigned char*)src + total), ((dest) ? (wchar_t*)(dest + len) : NULL));

		total += acp_gb2312_code_sequence((unsigned char)(src[total]));
	}

	return len;
}

int acp_gb2312_code_count(void)
{
	return (0xFE - 0xA1 + 1) * (0xFE - 0xA1 + 1);
}

bool_t acp_next_gb2312_char(byte_t* pch)
{
	byte_t h, l;

	h = pch[0];
	l = pch[1];

	if (!h && !l)
	{
		pch[0] = 0xA1;
		pch[1] = 0xA1;
		return bool_true;
	}
	
	if (h == 0xFE && l == 0xFE)
	{
		pch[0] = 0x00;
		pch[1] = 0x00;
		return bool_false;
	}

	if (l == 0xFE)
	{
		h++;
		pch[0] = h;
		pch[1] = 0xA1;
	}
	else
	{
		l++;
		pch[1] = l;
	}

	return bool_true;
}

