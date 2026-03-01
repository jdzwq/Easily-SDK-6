/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc attributes bag document

	@module	attrbag.c | implement file

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

#include "attrbag.h"

#include "../xdldoc.h"

int split_attributes_title(const tchar_t* str, int len, tchar_t* buf, int max)
{
	const tchar_t* tk;
	int n;

	if(len < 0) len = xslen(str);
	if(!str || !len) return 0;

	tk = str;
	n = 0;
	while(len && *str != _T('{') && *str != _T('\0'))
	{
		str++;len--;
		n++;
	}

	if(buf)
	{
		n = (n < max)? n : max;
		xsncpy(buf, tk, n);
	}

	return n;
}

bool_t dom_node_parse_attributes(link_t_ptr nlk, const tchar_t* str, int len)
{
	const tchar_t* tk;
	int n;

	if(len < 0) len = xslen(str);
	if(!str || !len) return bool_false;

	tk = str;
	n = 0;
	while(len && *str != _T('{') && *str != _T('\0'))
	{
		str++;len--;
		n++;
	}

	if(!n) return bool_false;

	set_dom_node_name(nlk, tk, n);

	if(*str == _T('{'))
	{
		str ++;len--;
	}

	tk = str;
	n = 0;
	while(len && *str != _T('}') && *str != _T('\0'))
	{
		str++;len--;
		n++;
	}

	hash_table_parse_attrset(get_dom_node_attr_table(nlk), tk, n);

	return bool_true;
}

int dom_node_format_attributes(link_t_ptr nlk, tchar_t* buf, int max)
{
	const tchar_t* tk;
	int len, total = 0;

	tk = get_dom_node_name_ptr(nlk);
	len = xslen(tk);
	if(total + len > max) return 0;
	if(buf)
	{
		xsncat((buf + total), tk, len);
	}
	total += len;

	if(total + 1 > max) return 0;
	if(buf)
	{
		xsncat((buf + total), _T("{"), 1);
	}
	total += 1;

	len = hash_table_format_attrset(get_dom_node_attr_table(nlk), ((buf)? (buf + total) : NULL), max - total);
	if(total + len > max) return 0;
	total += len;

	if(total + 1 > max) return 0;
	if(buf)
	{
		xsncat((buf + total), _T("}"), 1);
	}
	total += 1;

	return total;
}
