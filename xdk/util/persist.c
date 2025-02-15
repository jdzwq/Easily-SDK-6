/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc utility document

	@module	others.c | implement file

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

#include "others.h"

#include "../xdkimp.h"
#include "../xdkstd.h"
#include "../xdkutil.h"

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