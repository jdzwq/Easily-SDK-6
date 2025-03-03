﻿/***********************************************************************
	Easily xdl v5.5

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc printer context document

	@module	impbitmap.c | implement file

	@devnote 张文权 2021.01 - 2021.12	v6.0
***********************************************************************/

/**********************************************************************
This program is xmem_free software : you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
LICENSE.GPL3 for more details.
***********************************************************************/

#include "impbitmap.h"

#include "../xdcimp.h"
#include "../xdcinit.h"

#ifdef XDU_SUPPORT_CONTEXT_BITMAP

void destroy_bitmap(bitmap_t bmp)
{
	if_context_t* pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(pif->pf_destroy_bitmap)(bmp);
}

void get_bitmap_size(bitmap_t rdc, int* pw, int* ph)
{
	if_context_t* pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(pif->pf_get_bitmap_size)(rdc, pw, ph);
}

bitmap_t create_context_bitmap(visual_t rdc)
{
	if_context_t* pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	return (pif->pf_create_context_bitmap)(rdc);
}

bitmap_t create_color_bitmap(visual_t rdc, const xcolor_t* pxc, int w, int h)
{
	if_context_t* pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	return (pif->pf_create_color_bitmap)(rdc, pxc, w, h);
}

bitmap_t create_pattern_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h)
{
	if_context_t* pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	return (pif->pf_create_pattern_bitmap)(rdc, pxc_front, pxc_back, w, h);
}

bitmap_t create_gradient_bitmap(visual_t rdc, const xcolor_t* pxc_near, const xcolor_t* pxc_center, int w, int h, const tchar_t* lay)
{
	if_context_t* pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	return (pif->pf_create_gradient_bitmap)(rdc, pxc_near, pxc_center, w, h, lay);
}

bitmap_t create_code128_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const tchar_t* text)
{
	if_context_t* pif;

	byte_t* buf;
	int len;

	byte_t* bar_buf;
	dword_t bar_len;
	bitmap_t bmp;

	pif = PROCESS_CONTEXT_INTERFACE;

#ifdef _UNICODE
	len = ucs_to_utf8(text, -1, NULL, MAX_LONG);
#else
	len = mbs_to_utf8(text, -1, NULL, MAX_LONG);
#endif

	if (!len)
		return NULL;

	buf = (byte_t*)xmem_alloc(len + 1);
#ifdef _UNICODE
	ucs_to_utf8(text, -1, buf, len);
#else
	mbs_to_utf8(text, -1, buf, len);
#endif

	bar_len = code128_encode(buf, len, NULL, MAX_LONG);
	if (bar_len <= 0)
	{
		xmem_free(buf);
		return NULL;
	}

	bar_buf = (byte_t*)xmem_alloc(bar_len + 1);
	bar_len = code128_encode(buf, len, bar_buf, bar_len);

	xmem_free(buf);

	bmp = (pif->pf_create_code128_bitmap)(rdc, pxc_front, pxc_back, bar_buf, bar_len);

	xmem_free(bar_buf);

	return bmp;
}

bitmap_t create_pdf417_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const tchar_t* text)
{
	if_context_t* pif;

	byte_t* buf;
	int len;

	byte_t* bar_buf;
	int cols, rows;
	dword_t bar_len;
	bitmap_t bmp;

	pif = PROCESS_CONTEXT_INTERFACE;

#ifdef _UNICODE
	len = ucs_to_utf8(text, -1, NULL, MAX_LONG);
#else
	len = mbs_to_utf8(text, -1, NULL, MAX_LONG);
#endif

	if (!len)
		return NULL;

	buf = (byte_t*)xmem_alloc(len + 1);
#ifdef _UNICODE
	ucs_to_utf8(text, -1, buf, len);
#else
	mbs_to_utf8(text, -1, buf, len);
#endif

	bar_len = pdf417_encode(buf, len, NULL, MAX_LONG, NULL, NULL);
	if (bar_len <= 0)
	{
		xmem_free(buf);
		return NULL;
	}

	bar_buf = (byte_t*)xmem_alloc(bar_len + 1);
	bar_len = pdf417_encode(buf, len, bar_buf, bar_len, &rows, &cols);

	xmem_free(buf);

	bmp = (pif->pf_create_pdf417_bitmap)(rdc, pxc_front, pxc_back, bar_buf, rows, cols);

	xmem_free(bar_buf);

	return bmp;
}

bitmap_t create_qrcode_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const tchar_t* text)
{
	if_context_t* pif;

	byte_t* buf;
	int len;

	byte_t* bar_buf;
	int cols, rows;
	dword_t bar_len;
	bitmap_t bmp;

	pif = PROCESS_CONTEXT_INTERFACE;

#ifdef _UNICODE
	len = ucs_to_utf8(text, -1, NULL, MAX_LONG);
#else
	len = mbs_to_utf8(text, -1, NULL, MAX_LONG);
#endif

	if (!len)
		return NULL;

	buf = (byte_t*)xmem_alloc(len + 1);
#ifdef _UNICODE
	ucs_to_utf8(text, -1, buf, len);
#else
	mbs_to_utf8(text, -1, buf, len);
#endif

	bar_len = qr_encode(buf, len, NULL, MAX_LONG, NULL, NULL);
	if (bar_len <= 0)
	{
		xmem_free(buf);
		return NULL;
	}

	bar_buf = (byte_t*)xmem_alloc(bar_len + 1);
	bar_len = qr_encode(buf, len, bar_buf, bar_len, &rows, &cols);

	xmem_free(buf);

	bmp = (pif->pf_create_qrcode_bitmap)(rdc, pxc_front, pxc_back, bar_buf, rows, cols);

	xmem_free(bar_buf);

	return bmp;
}

bitmap_t load_bitmap_from_bytes(visual_t rdc, const byte_t* pb, dword_t len)
{
	if_context_t* pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	return (pif->pf_load_bitmap_from_bytes)(rdc, pb, len);
}

dword_t	save_bitmap_to_bytes(visual_t rdc, bitmap_t rb, byte_t* pb, dword_t max)
{
	if_context_t* pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	return (dword_t)(pif->pf_save_bitmap_to_bytes)(rdc, rb, pb, max);
}

dword_t	get_bitmap_bytes(bitmap_t rdc)
{
	if_context_t* pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	return (dword_t)(pif->pf_get_bitmap_bytes)(rdc);
}

#ifdef XDU_SUPPORT_SHELL

bitmap_t load_bitmap_from_thumb(visual_t rdc, const tchar_t* fname)
{
	if_context_t* pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	return (pif->pf_load_bitmap_from_thumb)(rdc, fname);
}

bitmap_t load_bitmap_from_icon(visual_t rdc, const tchar_t* iname)
{
	if_context_t* pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	return (pif->pf_load_bitmap_from_icon)(rdc, iname);
}

#endif /*XDU_SUPPORT_SHELL*/

/***********************************************************************************************/

bool_t save_bitmap_to_ximage(visual_t rdc, bitmap_t bmp, ximage_t* pmi)
{
	byte_t* bmp_buf = NULL;
	dword_t bmp_len = 0;

	int base_len = 0;

	bmp_len = save_bitmap_to_bytes(rdc, bmp, NULL, MAX_LONG);
	if (!bmp_len)
		return 0;

	bmp_buf = (byte_t*)xmem_alloc(bmp_len);
	save_bitmap_to_bytes(rdc, bmp, bmp_buf, bmp_len);

	base_len = xbas_encode(bmp_buf, bmp_len, NULL, MAX_LONG);
	if (!base_len)
	{
		xmem_free(bmp_buf);
		return 0;
	}

	xscpy(pmi->type, GDI_ATTR_IMAGE_TYPE_BMP);

	pmi->source = xsalloc(base_len + 1);
	xbas_encode(bmp_buf, bmp_len, (tchar_t*)pmi->source, base_len);

	xmem_free(bmp_buf);

	return 1;
}

bitmap_t load_bitmap_from_ximage(visual_t rdc, const ximage_t* pmi, int cx, int cy)
{
	bitmap_t ih = NULL;
	int len, len_bmp, len_zip;
	byte_t *buf_bmp, *buf_zip;
	xcolor_t xc;

	parse_xcolor(&xc, pmi->color);

#ifdef GPL_SUPPORT_JPG
	if (xsicmp(pmi->type, GDI_ATTR_IMAGE_TYPE_JPG) == 0)
	{
		len = xslen(pmi->source);
		len_zip = xbas_decode(pmi->source, len, NULL, MAX_LONG);
		buf_zip = (byte_t*)xmem_alloc(len_zip);
		xbas_decode(pmi->source, len, buf_zip, len_zip);

		len_bmp = xjpg_decompress(buf_zip, len_zip, NULL, MAX_LONG);
		buf_bmp = (byte_t*)xmem_alloc(len_bmp);
		xjpg_decompress(buf_zip, len_zip, buf_bmp, len_bmp);

		xmem_free(buf_zip);

		if (RGB_GRAY(xc.r, xc.g, xc.b) < 248)
		{
			buf_zip = buf_bmp;
			len_zip = len_bmp;

			len_bmp = xbmp_convgray(buf_zip, len_zip, NULL, MAX_LONG);
			buf_bmp = (byte_t*)xmem_alloc(len_bmp);
			xbmp_convgray(buf_zip, len_zip, buf_bmp, len_bmp);

			xmem_free(buf_zip);
		}

		ih = load_bitmap_from_bytes(rdc, buf_bmp, len_bmp);

		xmem_free(buf_bmp);
	}
#endif
#ifdef GPL_SUPPORT_PNG
	if (xsicmp(pmi->type, GDI_ATTR_IMAGE_TYPE_PNG) == 0)
	{
		len = xslen(pmi->source);
		len_zip = xbas_decode(pmi->source, len, NULL, MAX_LONG);
		buf_zip = (byte_t*)xmem_alloc(len_zip);
		xbas_decode(pmi->source, len, buf_zip, len_zip);

		len_bmp = xpng_decompress(buf_zip, len_zip, NULL, MAX_LONG);
		buf_bmp = (byte_t*)xmem_alloc(len_bmp);
		xpng_decompress(buf_zip, len_zip, buf_bmp, len_bmp);

		xmem_free(buf_zip);

		if (RGB_GRAY(xc.r, xc.g, xc.b) < 248)
		{
			buf_zip = buf_bmp;
			len_zip = len_bmp;

			len_bmp = xbmp_convgray(buf_zip, len_zip, NULL, MAX_LONG);
			buf_bmp = (byte_t*)xmem_alloc(len_bmp);
			xbmp_convgray(buf_zip, len_zip, buf_bmp, len_bmp);

			xmem_free(buf_zip);
		}

		ih = load_bitmap_from_bytes(rdc, buf_bmp, len_bmp);

		xmem_free(buf_bmp);
	}
#endif
	if (xsicmp(pmi->type, GDI_ATTR_IMAGE_TYPE_BMP) == 0)
	{
		len = xslen(pmi->source);
		len_bmp = xbas_decode(pmi->source, len, NULL, MAX_LONG);
		buf_bmp = (byte_t*)xmem_alloc(len_bmp);
		xbas_decode(pmi->source, len, buf_bmp, len_bmp);

		if (RGB_GRAY(xc.r, xc.g, xc.b) < 248)
		{
			buf_zip = buf_bmp;
			len_zip = len_bmp;

			len_bmp = xbmp_convgray(buf_zip, len_zip, NULL, MAX_LONG);
			buf_bmp = (byte_t*)xmem_alloc(len_bmp);
			xbmp_convgray(buf_zip, len_zip, buf_bmp, len_bmp);

			xmem_free(buf_zip);
		}

		ih = load_bitmap_from_bytes(rdc, buf_bmp, len_bmp);

		xmem_free(buf_bmp);
	}
#if defined(XDU_SUPPORT_FILE)
	else
	{
		ih = load_bitmap_from_file(rdc, pmi->source);
	}
#endif

	return ih;
}

bitmap_t load_bitmap_from_file(visual_t rdc, const tchar_t* fname)
{
	tchar_t type[RES_LEN + 1] = { 0 };

	byte_t* file_buf = NULL;
	dword_t file_len;

	byte_t* bmp_buf = NULL;
	dword_t bmp_len;

	bitmap_t bmp;

	file_len = load_image_bytes_from_file(NULL, fname, type, NULL, MAX_LONG);
	if (!file_len)
		return NULL;

	file_buf = (byte_t*)xmem_alloc(file_len);
	load_image_bytes_from_file(NULL, fname, type, file_buf, file_len);

	if (compare_text(type, -1, GDI_ATTR_IMAGE_TYPE_JPG, -1, 1) == 0)
	{
#ifdef GPL_SUPPORT_JPG
		bmp_len = xjpg_decompress(file_buf, file_len, NULL, MAX_LONG);
		if (!bmp_len)
		{
			xmem_free(file_buf);
			return NULL;
		}

		bmp_buf = (byte_t*)xmem_alloc(bmp_len);

		xjpg_decompress(file_buf, file_len, bmp_buf, bmp_len);

		xmem_free(file_buf);
#else
		xmem_free(file_buf);
		return NULL;
#endif //GPL_SUPPORT_JPG
	}
	else if (compare_text(type, -1, GDI_ATTR_IMAGE_TYPE_PNG, -1, 1) == 0)
	{
#ifdef GPL_SUPPORT_PNG
		bmp_len = xpng_decompress(file_buf, file_len, NULL, MAX_LONG);
		if (!bmp_len)
		{
			xmem_free(file_buf);
			return NULL;
		}

		bmp_buf = (byte_t*)xmem_alloc(bmp_len);

		xpng_decompress(file_buf, file_len, bmp_buf, bmp_len);

		xmem_free(file_buf);
#else
		xmem_free(file_buf);
		return NULL;
#endif //GPL_SUPPORT_PNG
	}
	else if (compare_text(type, -1, GDI_ATTR_IMAGE_TYPE_BMP, -1, 1) == 0)
	{
		bmp_buf = file_buf;
		bmp_len = file_len;
	}

	if (!bmp_buf)
		return NULL;

	bmp = load_bitmap_from_bytes(rdc, bmp_buf, bmp_len);

	xmem_free(bmp_buf);

	return bmp;
}

bool_t save_bitmap_to_file(visual_t rdc, bitmap_t rb, const tchar_t* type, const tchar_t* fname)
{
	byte_t* bmp_buf = NULL;
	dword_t bmp_len = 0;

	byte_t* file_buf = NULL;
	dword_t file_len = 0;

	bool_t rt;

	bmp_len = save_bitmap_to_bytes(rdc, rb, NULL, MAX_LONG);
	if (!bmp_len)
		return 0;

	bmp_buf = (byte_t*)xmem_alloc(bmp_len);
	save_bitmap_to_bytes(rdc, rb, bmp_buf, bmp_len);

	if (compare_text(type, -1, GDI_ATTR_IMAGE_TYPE_JPG, -1, 1) == 0)
	{
#ifdef GPL_SUPPORT_JPG
		file_len = bmp_len;
		file_buf = (byte_t*)xmem_alloc(file_len);
		file_len = xjpg_compress(bmp_buf, bmp_len, file_buf, file_len);

		xmem_free(bmp_buf);
#else
		xmem_free(bmp_buf);
		return 0;
#endif
	}
	else if (compare_text(type, -1, GDI_ATTR_IMAGE_TYPE_PNG, -1, 1) == 0)
	{
#ifdef GPL_SUPPORT_PNG
		file_len = bmp_len;
		file_buf = (byte_t*)xmem_alloc(file_len);
		file_len = xpng_compress(bmp_buf, bmp_len, file_buf, file_len);

		xmem_free(bmp_buf);
#else
		xmem_free(bmp_buf);
		return 0;
#endif
	}
	else
	{
		file_buf = bmp_buf;
		file_len = bmp_len;
	}

	if (file_len <= 0)
	{
		xmem_free(file_buf);
		return 0;
	}

	rt = save_image_bytes_to_file(NULL, fname, file_buf, file_len);

	xmem_free(file_buf);

	return rt;
}

#endif /*XDU_SUPPORT_CONTEXT_BITMAP*/

