/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc code page document

	@module	acp_ascii.c | implement file

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

int acp_ascii_code_count(void)
{
	return (0xFE - 0x20 + 1);
}

bool_t acp_next_ascii_char(byte_t* pch)
{
	byte_t h, l;

	h = pch[0];
	l = pch[1];

	if (!h && !l)
	{
		pch[0] = 0x00;
		pch[1] = 0x20;
		return bool_true;
	}
	
	if (h == 0x00 && l == 0xFE)
	{
		pch[0] = 0x00;
		pch[1] = 0x00;
		return bool_false;
	}

	l++;
	pch[1] = l;

	return bool_true;
}
