/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc utility document

	@module	xdgutil.c | implement file

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

#include "xdgutil.h"


#define IS_LETTER(ch)	((ch >= _T('A') && ch <= _T('Z')) || (ch >= _T('a') && ch <= _T('z')))
#define IS_NUMERIC(ch)	((ch >= _T('1') && ch <= _T('9')) || (ch == _T(' ') || ch == _T(',')))

tchar_t* next_draw_path(const tchar_t* script, int len, tchar_t* pname, xpoint_t* ppt, int* pn)
{
	tchar_t* token = (tchar_t*)script;
	int total = 0;
	tchar_t ch;

	if (xsisnil(script))
		return NULL;

	if (len < 0)
		len = xslen(script);

	while (!IS_LETTER(*token) && *token && total < len)
	{
		token++;
		total++;
	}

	if (*token == _T('\0') || total == len)
		return NULL;

	ch = *token;

	token++;
	total++;

	switch (ch)
	{
	case _T('M'):
	case _T('m'):
		xsscanf(token, _T("%d %d"), &(ppt[0].x), &(ppt[0].y));

		*pname = ch;
		*pn = 1;
		break;
	case _T('L'):
	case _T('l'):
		xsscanf(token, _T("%d %d"), &(ppt[0].x), &(ppt[0].y));

		*pname = ch;
		*pn = 1;
		break;
	case _T('H'):
	case _T('h'):
		xsscanf(token, _T("%d"), &(ppt[0].x));
		ppt[0].y = 0;

		*pname = ch;
		*pn = 1;
		break;
	case _T('V'):
	case _T('v'):
		ppt[0].x = 0;
		xsscanf(token, _T("%d"), &(ppt[0].y));

		*pname = ch;
		*pn = 1;
		break;
	case _T('Q'):
	case _T('q'):
		xsscanf(token, _T("%d %d, %d %d"), &(ppt[0].x), &(ppt[0].y), &(ppt[1].x), &(ppt[1].y));

		*pname = ch;
		*pn = 2;
		break;
	case _T('T'):
	case _T('t'):
		xsscanf(token, _T("%d %d"), &(ppt[0].x), &(ppt[0].y));

		*pname = ch;
		*pn = 1;
		break;
	case _T('C'):
	case _T('c'):
		xsscanf(token, _T("%d %d, %d %d, %d %d"), &(ppt[0].x), &(ppt[0].y), &(ppt[1].x), &(ppt[1].y), &(ppt[2].x), &(ppt[2].y));

		*pname = ch;
		*pn = 3;
		break;
	case _T('S'):
	case _T('s'):
		xsscanf(token, _T("%d %d, %d %d"), &(ppt[0].x), &(ppt[0].y), &(ppt[1].x), &(ppt[1].y));

		*pname = ch;
		*pn = 2;
		break;
	case _T('Z'):
	case _T('z'):
		*pname = ch;
		*pn = 0;
		break;
	}

	while (IS_NUMERIC(*token) && total < len)
	{
		token++;
		total++;
	}

	return token;
}

dword_t load_image_file(const tchar_t* fname, tchar_t* itype, byte_t* buf, dword_t max)
{
	dword_t size;
	xhand_t fh;
	int len;

	tchar_t fsize[NUM_LEN + 1] = { 0 };

	len = xslen(fname);
	if (len < 4)
		return 0;

	if (compare_text(fname + xslen(fname) - 4, -1, _T(".jpg"), -1, 1) == 0)
	{
		if (itype)
			xscpy(itype, GDI_ATTR_IMAGE_TYPE_JPG);
	}
	else if (compare_text(fname + xslen(fname) - 4, -1, _T(".png"), -1, 1) == 0)
	{
		if (itype)
			xscpy(itype, GDI_ATTR_IMAGE_TYPE_PNG);
	}
	else if (compare_text(fname + xslen(fname) - 4, -1, _T(".bmp"), -1, 1) == 0)
	{
		if (itype)
			xscpy(itype, GDI_ATTR_IMAGE_TYPE_BMP);
	}
	else
		return 0;

	if (!xuncf_file_info(NULL, fname, NULL, fsize, NULL, NULL))
	{
		return 0;
	}

	size = xstol(fsize);
	size = (size < max) ? size : max;

	if (buf && max >= (int)size)
	{
		fh = xuncf_open_file(NULL, fname, FILE_OPEN_READ);
		if (!fh)
			return 0;

		xuncf_read_file(fh, buf, &size);
		xuncf_close_file(fh);
	}

	return size;
}