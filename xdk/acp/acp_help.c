/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc code page document

	@module	acp.c | implement file

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

/*******************************************************************************************/

int w_acp_help_code(const wchar_t* src, int len, wchar_t* buf, int max)
{
	int count = 0;
	int i = 0;
	unsigned short sch, uch;
	bool_t b;

	if (len < 0)
	{
		len = 0;
		while (src && *(src + len))
			len++;
	}

	while (i < len && count < max)
	{
		sch = src[i++];
		if (sch >= 0x0000 && sch <= 0x007F)
		{
			if (sch >= L'A' && sch <= L'Z')
			{
				if(buf)
				{
					buf[count] = (wchar_t)sch;
				}
				count ++;
			}
			else if (src[i] >= L'a' && src[i] <= L'z')
			{
				sch -= 32;
				if(buf)
				{
					buf[count] = (wchar_t)sch;
				}
				count ++;
			}
		}else
		{
			b = share_unicode_seek_help(sch, &uch);
			if(b)
			{
				if(buf)
				{
					buf[count] = (wchar_t)uch;
				}
				count ++;
			}
		}
	}

	if (buf) buf[count] = L'\0';

	return count;
}

static int _gb2312_acp_help_code(const schar_t* src, int len, schar_t* buf, int max)
{
	int seq, count = 0;
	int i = 0;
	unsigned short sch, uch;
	bool_t b;

	if (len < 0)
	{
		len = 0;
		while (src && *(src + len))
			len++;
	}

	while (i < len && count < max)
	{
		seq = acp_gb2312_code_sequence((byte_t)(src[i]));
		if (!seq)
			break;

		if (seq == 1)
		{
			sch = src[i];
			if (sch >= 0x00 && sch <= 0x7F)
			{
				if (sch >= 'A' && sch <= 'Z')
				{
					if(buf)
					{
						buf[count] = (schar_t)sch;
					}
					count ++;
				}
				else if (sch >= 'a' && sch <= 'z')
				{
					sch -= 32;
					if(buf)
					{
						buf[count] = (schar_t)sch;
					}
					count ++;
				}
			}
		}else
		{
			sch = MAKESHORT(src[0], src[1]);
			b = share_gb2312_seek_help(sch, &uch);
			if(b)
			{
				if(buf)
				{
					buf[count] = (schar_t)uch;
				}
				count ++;
			}
		}

		i += seq;
	}

	if (buf) buf[count] = '\0';

	return count;
}

static int _utf8_acp_help_code(const schar_t* src, int len, schar_t* buf, int max)
{
	int seq, count = 0;
	int i = 0;
	wchar_t wc, hlp;

	if (len < 0)
	{
		len = 0;
		while (src && *(src + len))
			len++;
	}

	while (i < len && count < max)
	{
		seq = acp_utf8_code_sequence(*(byte_t*)(src + i));
		if (!seq)
			break;

		utf8_byte_to_ucs((byte_t*)(src + i), &wc);

		if(w_acp_help_code(&wc, 1, &hlp, 1) > 0)
		{
			if(buf)
			{
				buf[count] = (schar_t)hlp;
			}
			count ++;
		}

		i += seq;
	}

	if (buf) buf[count] = '\0';

	return count;
}

int a_acp_help_code(const schar_t* src, int len, schar_t* buf, int max)
{
#if DEF_MBS == _GB2312
	return _gb2312_acp_help_code(src, len, buf, max);
#else
	return _utf8_acp_help_code(src, len, buf, max);
#endif
}