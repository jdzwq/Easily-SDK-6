/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc glyph finder document

	@module	gly_finder.c | implement file

	@devnote 张文权 2021.01 - 2021.12 v6.0
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

#include "gly.h"

#include "../xgcobj.h"


const glyph_info_t* find_glyph_info(const tchar_t* charset, const xfont_t* pxf)
{
	int n, i;

	if (xsicmp(charset, CHARSET_ASCII) == 0)
	{
		n = sizeof(a_glyph_list) / sizeof(glyph_info_t);

		for (i = 0; i < n; i++)
		{
			if (xstof(pxf->size) <= xstof(a_glyph_list[i].size))
				return &(a_glyph_list[i]);
		}
	}
	else
	{
		n = sizeof(c_glyph_list) / sizeof(glyph_info_t);

		for (i = 0; i < n; i++)
		{
			if (xstof(pxf->size) <= xstof(c_glyph_list[i].size))
				return &(c_glyph_list[i]);
		}
	}

	return NULL;
}

static void big_bytes(const tchar_t* str, byte_t* pch)
{
	wchar_t wc;

	if(is_ascii(str[0]))
	{
		pch[0] = 0x00;
		pch[1] = (byte_t)str[0];
		return;
	}
#if defined(_UNICODE) || defined(UNICODE)
	pch[0] = GETHBYTE((sword_t)(*str));
	pch[1] = GETLBYTE((sword_t)(*str));
#else
#ifdef XGC_USE_GB2312_GLYPH
	mbs_byte_to_gb2312(str, pch);
#else
	mbs_byte_to_ucs(str, &wc);
	pch[0] = GETHBYTE((sword_t)wc);
	pch[1] = GETLBYTE((sword_t)wc);
#endif
#endif
}

bool_t get_glyph_metrix(const glyph_info_t* pgi, const tchar_t *str, glyph_metrix_t* pmetr)
{
	int ind;
	byte_t pch[2];
	dword_t m;
	byte_t* pb;

	if (pmetr) pmetr->width = pgi->width;
	if (pmetr) pmetr->height = pgi->height;
	if (pmetr) pmetr->ascent = pgi->ascent;

	if (is_null(str)) return bool_true;

	big_bytes(str, pch);

	m = 2 + pgi->bytesperline * pgi->height;

	ind = (pgi->pf_index)? ((*pgi->pf_index)(pch)) : 0;
	if(ind < 0) ind = 0;

	pb = (pgi->glyph)? (byte_t*)xshare_lock(pgi->glyph, ind * m, m) : NULL;
	if (pb)
	{
		if (pmetr) pmetr->width = GET_SWORD_LOC(pb, 0);
		xshare_unlock(pgi->glyph, ind * m, m, pb);
	}
	
	return bool_true;
}

int get_glyph_pixmap(const glyph_info_t* pgi, const tchar_t* str, byte_t* pdata)
{
	int w, ind;
	byte_t pch[2];
	dword_t m;
	byte_t* pb;

	big_bytes(str, pch);

	m = 2 + pgi->bytesperline * pgi->height;

	ind = (pgi->pf_index)? ((*pgi->pf_index)(pch)) : 0;
	if(ind < 0) ind = 0;

	pb = (pgi->glyph)? (byte_t*)xshare_lock(pgi->glyph, ind * m, m) : NULL;
	if (pb)
	{
		w = GET_SWORD_LOC(pb, 0);
		if (pdata)
		{
			xmem_copy((void *)(pdata), (void *)(pb + 2), (m - 2));
		}
		xshare_unlock(pgi->glyph, ind * m, m, pb);
	}
	else
	{
		w = pgi->width;
	}

	return w;
}