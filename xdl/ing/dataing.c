﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc shape document

	@module	shaping.c | implement file

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

#include "dataing.h"

#include "../xdlgdi.h"
#include "../xdlutil.h"



void draw_pass(const drawing_interface* pif, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, const tchar_t* txt, int len)
{
	tchar_t sz_pass[INT_LEN + 1] = { 0 };

	len = format_password(txt, sz_pass, INT_LEN);

	(*pif->pf_draw_text)(pif->ctx, pxf, pxa, pxr, sz_pass, len);
}

void draw_data(const drawing_interface* pif, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, const tchar_t* data, int len, int dig, const tchar_t* type, const tchar_t* fmt, bool_t zeronull, bool_t autowrap)
{
	tchar_t sz_format[RES_LEN + 1] = { 0 };
	xdate_t dt = { 0 };
	int lt;
	double db;

	xsize_t xs;
	xface_t xa;

	if (len < 0)
		len = xslen(data);

	xmem_copy((void*)&xa, (void*)pxa, sizeof(xface_t));

	if (compare_text(type, -1, ATTR_DATA_TYPE_INTEGER, -1, 0) == 0)
	{
		lt = xsntol(data, len);

		if (zeronull && !lt)
		{
			xscpy(sz_format, _T(""));
		}
		else if (!is_null(fmt))
		{
			format_integer_ex(lt, fmt, sz_format, RES_LEN);
		}
		else
		{
			xsncpy(sz_format, data, len);
		}

		if (autowrap && pxa && is_null(xa.text_wrap))
		{
			(*pif->pf_text_size)(pif->ctx, pxf, sz_format, -1, &xs);
			if (xs.fw > pxr->fw)
			{
				xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);
			}
		}

		(*pif->pf_draw_text)(pif->ctx, pxf, &xa, pxr, sz_format, -1);
	}
	else if (compare_text(type, -1, ATTR_DATA_TYPE_NUMERIC, -1, 0) == 0)
	{
		db = xsntonum(data, len);

		if (zeronull && is_zero_numeric(db, dig))
		{
			xscpy(sz_format, _T(""));
		}
		else if (!is_null(fmt))
		{
			format_numeric(db, fmt, sz_format, RES_LEN);
		}
		else
		{
			xsncpy(sz_format, data, len);
		}

		if (autowrap && is_null(xa.text_wrap))
		{
			(*pif->pf_text_size)(pif->ctx, pxf, sz_format, -1, &xs);
			if (xs.fw > pxr->fw)
			{
				xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);
			}
		}

		(*pif->pf_draw_text)(pif->ctx, pxf, &xa, pxr, sz_format, -1);
	}
	else if (compare_text(type, -1, ATTR_DATA_TYPE_DATETIME, -1, 0) == 0)
	{
		if (!is_null(fmt) && !is_null(data))
		{
			parse_datetime(&dt, data);
			format_datetime_ex(&dt, fmt, sz_format, RES_LEN);
		}
		else
		{
			xsncpy(sz_format, data, len);
		}

		if (autowrap && is_null(xa.text_wrap))
		{
			(*pif->pf_text_size)(pif->ctx, pxf, sz_format, -1, &xs);
			if (xs.fw > pxr->fw)
			{
				xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);
			}
		}

		(*pif->pf_draw_text)(pif->ctx, pxf, &xa, pxr, sz_format, -1);
	}
	else if (compare_text(type, -1, ATTR_DATA_TYPE_DATE, -1, 0) == 0)
	{
		if (!is_null(fmt) && !is_null(data))
		{
			parse_date(&dt, data);
			format_datetime_ex(&dt, fmt, sz_format, RES_LEN);
		}
		else
		{
			xsncpy(sz_format, data, len);
		}

		if (autowrap && is_null(xa.text_wrap))
		{
			(*pif->pf_text_size)(pif->ctx, pxf, sz_format, -1, &xs);
			if (xs.fw > pxr->fw)
			{
				xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);
			}
		}

		(*pif->pf_draw_text)(pif->ctx, pxf, &xa, pxr, sz_format, -1);
	}
	else
	{
		if (autowrap && is_null(xa.text_wrap))
		{
			(*pif->pf_text_size)(pif->ctx, pxf, data, len, &xs);
			if (xs.fw > pxr->fw)
			{
				xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);
			}
		}

		(*pif->pf_draw_text)(pif->ctx, pxf, &xa, pxr, data, len);
	}
}


