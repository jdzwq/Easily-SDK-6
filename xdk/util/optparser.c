/***********************************************************************
	Easily SDK 6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc options parser document

	@module	optparser.c | implement file

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

#include "optparser.h"

#include "../xdkstd.h"

int parse_options(const tchar_t* str, int len, tchar_t itemfeed, tchar_t linefeed, void* param, PF_OPTIONS_PARSE pf_parse)
{
	const tchar_t* token;
	int total = 0;
	int count = 0;

	const tchar_t *key, *val;
	int klen, vlen;

	if (xsisnil(str) || !len)
		return 0;

	if (len < 0)
		len = xslen(str);

	token = str;

	while (total < len)
	{
		key = val = NULL;
		klen = vlen = 0;

		//skip blank
		while ((*token == _T(' ') || *token == _T('\t')) && total < len)
		{
			token++;
			total++;
		}

		key = (tchar_t*)token;
		while (*token != itemfeed && *token != _T('\0') && total < len)
		{
			token++;
			total++;
		}
		klen = (int)(token - key);

		if (total >= len)
			break;

		//skip item feed
		if (*token == itemfeed)
		{
			token++; 
			total++;
		}

		//skip blank
		while ((*token == _T(' ') || *token == _T('\t')) && total < len)
		{
			token++;
			total++;
		}

		if (total >= len)
			break;

		val = (tchar_t*)token;
		while (*token != linefeed && *token != _T('\0') && total < len)
		{
			token++;
			total++;
		}
		vlen = (int)(token - val);

		if (pf_parse)
		{
			if (!(*pf_parse)(param, key, klen, val, vlen))
				break;
		}

		count++;

		while (*token == linefeed)
		{
			token++;
			total++;
		}

		if (*token == _T('\0'))
			break;
	}

	return count;
}

int format_options(tchar_t* buf, int max, tchar_t itemfeed, tchar_t linefeed, void* param, PF_OPTIONS_FORMAT pf_format)
{
	int total = 0;
	const tchar_t *key, *val;
	int klen, vlen;

	key = val = NULL;
	klen = vlen = 0;

	while ((*pf_format)(param, &key, &klen, &val, &vlen))
	{
		if (total + klen + vlen + 2 > max)
			break;

		if (buf)
		{
			xsncpy(buf + total, key, klen);
			buf[total + klen] = itemfeed;
			xsncpy(buf + total + klen + 1, val, vlen);
			buf[total + klen + 1 + vlen] = linefeed;
		}

		total += (klen + vlen + 2);

		key = val = NULL;
		klen = vlen = 0;
	}

	return total;
}