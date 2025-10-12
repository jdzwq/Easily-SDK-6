/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc bitmap document

	@module	if_bitmap_win.c | windows implement file

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

#include "../xduloc.h"

#ifdef XDU_SUPPORT_CONTEXT_BITMAP

#ifndef WINCE
#pragma comment(lib, "Msimg32.lib")
#endif

#ifdef WINCE
static int MulDiv(int a, int b, int c)
{
	return (int)((float)a * (float)b / (float)c);
}
#endif

static void _CenterRect(RECT* pRect, int src_width, int src_height)
{
	if (pRect->right - pRect->left > src_width)
	{
		pRect->left = pRect->left + (pRect->right - pRect->left - src_width) / 2;
		pRect->right = pRect->left + src_width;
	}
	if (pRect->bottom - pRect->top > src_height)
	{
		pRect->top = pRect->top + (pRect->bottom - pRect->top - src_height) / 2;
		pRect->bottom = pRect->top + src_height;
	}
}

void _destroy_bitmap(bitmap_t bmp)
{
	win32_bitmap_t* pwb = (win32_bitmap_t*)bmp;

	XDK_ASSERT(bmp->tag == _HANDLE_BITMAP);

	DeleteObject(pwb->bitmap);

	xmem_free(pwb);
}

void _get_bitmap_size(bitmap_t rb, int* pw, int* ph)
{
	win32_bitmap_t* pwb = (win32_bitmap_t*)rb;

	BITMAP bmp;

	GetObject(pwb->bitmap, sizeof(bmp), (void*)&bmp);

	*pw = bmp.bmWidth;
	*ph = bmp.bmHeight;
}

bitmap_t _create_context_bitmap(visual_t rdc)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	win32_bitmap_t* pwb;

	HDC hDC = (HDC)(ctx->context);
	HBITMAP hbmp;

	if (ctx->type != CONTEXT_MEMORY)
		return NULL;

	hbmp = (HBITMAP)GetCurrentObject(hDC, OBJ_BITMAP);
	if (!hbmp)
		return NULL;

	pwb = (win32_bitmap_t*)xmem_alloc(sizeof(win32_bitmap_t));
	pwb->head.tag = _HANDLE_BITMAP;

	pwb->bitmap = (HBITMAP)CopyImage(hbmp, IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION | LR_COPYRETURNORG);

	return (bitmap_t)&pwb->head;
}

bitmap_t _create_color_bitmap(visual_t rdc, const xcolor_t* pxc, int w, int h)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb;
	HBITMAP dibBmp;

	BITMAPINFO* pbi = NULL;
	BITMAPINFOHEADER* pbh = NULL;
	RGBQUAD* pbq = NULL;

	bitmap_info_head_t bih = { 0 };
	bitmap_quad_t* pquad = NULL;
	byte_t* pbb = NULL;
	int deep = 1;

	if (deep > 8)
		pbi = (BITMAPINFO*)xmem_alloc(sizeof(BITMAPINFO));
	else
		pbi = (BITMAPINFO*)xmem_alloc(sizeof(BITMAPINFO) + sizeof(RGBQUAD) * (1<<deep));

	pbh = (BITMAPINFOHEADER*)pbi;
	pbq = pbi->bmiColors;

	pbh->biSize = sizeof(BITMAPINFOHEADER);
	pbh->biWidth = w;
	pbh->biHeight = h;
	pbh->biPlanes = 1;
	pbh->biBitCount = deep;
	pbh->biCompression = BI_RGB;
	pbh->biSizeImage = 0;
	pbh->biXPelsPerMeter = 0;
	pbh->biYPelsPerMeter = 0;
	pbh->biClrUsed = 0;
	pbh->biClrImportant = 0;

	if (pbh->biBitCount == 1)
	{
		pbq[0].rgbBlue = 0;
		pbq[0].rgbGreen = 0;
		pbq[0].rgbRed = 0;
		pbq[1].rgbBlue = pxc->b;
		pbq[1].rgbGreen = pxc->g;
		pbq[1].rgbRed = pxc->r;
	}
	else if (pbh->biBitCount == 4)
	{
		xbmp_fill_quad(4, 16, (unsigned char*)pbq, 16);
	}
	else if (pbh->biBitCount == 8)
	{
		xbmp_fill_quad(8, 216, (unsigned char*)pbq, 256);
	}

	dibBmp = CreateDIBSection(hDC, pbi, DIB_RGB_COLORS, (void**)&pbb, NULL, 0);
	xmem_free(pbi);

	if (!dibBmp)
	{
		return NULL;
	}

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = deep;
	bih.compress = 0;
	bih.bytes = BMP_LINE_BYTES(w, bih.clrbits) * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	if (bih.clrbits <= 8)
	{
		pquad = (bitmap_quad_t*)xmem_alloc(sizeof(bitmap_quad_t) * (1 << bih.clrbits));
	}

	if (bih.clrbits == 1)
	{
		pquad[0].blue = pquad[0].green = pquad[0].red = 0;
		pquad[1].blue = pxc->b;
		pquad[1].green = pxc->g;
		pquad[1].red = pxc->r;
	}
	else if (bih.clrbits == 4)
	{
		xbmp_fill_quad(4, 16, (unsigned char*)pquad, 16);
	}
	else if (bih.clrbits == 8)
	{
		xbmp_fill_quad(8, 216, (unsigned char*)pquad, 256);
	}

	fill_color_dibbits(pxc, &bih, pquad, pbb, bih.bytes);
	xmem_free(pquad);

	pwb = (win32_bitmap_t*)xmem_alloc(sizeof(win32_bitmap_t));
	pwb->head.tag = _HANDLE_BITMAP;

	pwb->bitmap = dibBmp;

	return (bitmap_t)&pwb->head;
}

bitmap_t _create_pattern_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb;
	HBITMAP dibBmp;

	BITMAPINFO* pbi = NULL;
	BITMAPINFOHEADER* pbh = NULL;
	RGBQUAD* pbq = NULL;

	bitmap_info_head_t bih = { 0 };
	bitmap_quad_t* pquad = NULL;
	byte_t* pbb = NULL;
	int deep = 1;

	if (deep > 8)
		pbi = (BITMAPINFO*)xmem_alloc(sizeof(BITMAPINFO));
	else
		pbi = (BITMAPINFO*)xmem_alloc(sizeof(BITMAPINFO) + sizeof(RGBQUAD) * (1 << deep));

	pbh = (BITMAPINFOHEADER*)pbi;
	pbq = pbi->bmiColors;

	pbh->biSize = sizeof(BITMAPINFOHEADER);
	pbh->biWidth = w;
	pbh->biHeight = h;
	pbh->biPlanes = 1;
	pbh->biBitCount = deep;
	pbh->biCompression = BI_RGB;
	pbh->biSizeImage = 0;
	pbh->biXPelsPerMeter = 0;
	pbh->biYPelsPerMeter = 0;
	pbh->biClrUsed = 0;
	pbh->biClrImportant = 0;

	if (pbh->biBitCount == 1)
	{
		pbq[0].rgbBlue = pxc_back->b;
		pbq[0].rgbGreen = pxc_back->g;
		pbq[0].rgbRed = pxc_back->r;
		pbq[1].rgbBlue = pxc_front->b;
		pbq[1].rgbGreen = pxc_front->g;
		pbq[1].rgbRed = pxc_front->r;
	}
	else if (pbh->biBitCount == 4)
	{
		xbmp_fill_quad(4, 16, (unsigned char*)pbq, 16);
	}
	else if (pbh->biBitCount == 8)
	{
		xbmp_fill_quad(8, 216, (unsigned char*)pbq, 256);
	}

	dibBmp = CreateDIBSection(hDC, pbi, DIB_RGB_COLORS, (void**)&pbb, NULL, 0);
	xmem_free(pbi);

	if (!dibBmp)
	{
		return NULL;
	}

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = deep;
	bih.compress = 0;
	bih.bytes = BMP_LINE_BYTES(w, bih.clrbits) * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	if (bih.clrbits <= 8)
	{
		pquad = (bitmap_quad_t*)xmem_alloc(sizeof(bitmap_quad_t) * (1 << bih.clrbits));
	}

	if (bih.clrbits == 1)
	{
		pquad[0].blue = pxc_back->b;
		pquad[0].green = pxc_back->g;
		pquad[0].red = pxc_back->r;
		pquad[1].blue = pxc_front->b;
		pquad[1].green = pxc_front->g;
		pquad[1].red = pxc_front->r;
	}
	else if (bih.clrbits == 4)
	{
		xbmp_fill_quad(4, 16, (unsigned char*)pquad, 16);
	}
	else if (bih.clrbits == 8)
	{
		xbmp_fill_quad(8, 216, (unsigned char*)pquad, 256);
	}

	fill_pattern_dibbits(pxc_front, pxc_back, &bih, pquad, pbb, bih.bytes);
	xmem_free(pquad);

	pwb = (win32_bitmap_t*)xmem_alloc(sizeof(win32_bitmap_t));
	pwb->head.tag = _HANDLE_BITMAP;

	pwb->bitmap = dibBmp;

	return (bitmap_t)&pwb->head;
}

bitmap_t _create_gradient_bitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb;
	HBITMAP dibBmp;

	BITMAPINFO* pbi = NULL;
	BITMAPINFOHEADER* pbh = NULL;

	bitmap_info_head_t bih = { 0 };
	byte_t* pbb = NULL;
	int deep = 24;

	pbi = (BITMAPINFO*)xmem_alloc(sizeof(BITMAPINFO));

	pbh = (BITMAPINFOHEADER*)pbi;

	pbh->biSize = sizeof(BITMAPINFOHEADER);
	pbh->biWidth = w;
	pbh->biHeight = h;
	pbh->biPlanes = 1;
	pbh->biBitCount = deep;
	pbh->biCompression = BI_RGB;
	pbh->biSizeImage = 0;
	pbh->biXPelsPerMeter = 0;
	pbh->biYPelsPerMeter = 0;
	pbh->biClrUsed = 0;
	pbh->biClrImportant = 0;

	dibBmp = CreateDIBSection(hDC, pbi, DIB_RGB_COLORS, (void**)&pbb, NULL, 0);
	xmem_free(pbi);

	if (!dibBmp)
	{
		return NULL;
	}

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = deep;
	bih.compress = 0;
	bih.bytes = BMP_LINE_BYTES(w, bih.clrbits) * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	fill_gradient_dibbits(pxc_brim, pxc_core, type, &bih, pbb, bih.bytes);

	pwb = (win32_bitmap_t*)xmem_alloc(sizeof(win32_bitmap_t));
	pwb->head.tag = _HANDLE_BITMAP;

	pwb->bitmap = dibBmp;

	return (bitmap_t)&pwb->head;
}

bitmap_t _create_code128_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC winDC, hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb;
	HBITMAP dibBmp;
	int w, h, unit;

	BITMAPINFO* pbi = NULL;
	BITMAPINFOHEADER* pbh = NULL;
	RGBQUAD* pbq = NULL;

	bitmap_info_head_t bih = { 0 };
	bitmap_quad_t* pquad = NULL;
	byte_t* pbb = NULL;
	int deep = 8;

	winDC = GetDC(NULL);
	unit = GetDeviceCaps(hDC, LOGPIXELSX) / GetDeviceCaps(winDC, LOGPIXELSX);
	ReleaseDC(NULL, winDC);
	if (unit < 2) unit = 2;

	if (deep > 8)
		pbi = (BITMAPINFO*)xmem_alloc(sizeof(BITMAPINFO));
	else
		pbi = (BITMAPINFO*)xmem_alloc(sizeof(BITMAPINFO) + sizeof(RGBQUAD) * (1 << deep));

	w = code128_units(bar_buf, bar_cols) * unit;
	h = 10 * unit;

	pbh = (BITMAPINFOHEADER*)pbi;
	pbq = pbi->bmiColors;

	pbh->biSize = sizeof(BITMAPINFOHEADER);
	pbh->biWidth = w;
	pbh->biHeight = h;
	pbh->biPlanes = 1;
	pbh->biBitCount = deep;
	pbh->biCompression = BI_RGB;
	pbh->biSizeImage = 0;
	pbh->biXPelsPerMeter = 0;
	pbh->biYPelsPerMeter = 0;
	pbh->biClrUsed = 0;
	pbh->biClrImportant = 0;

	if (pbh->biBitCount == 1)
	{
		pbq[0].rgbBlue = pxc_back->b;
		pbq[0].rgbGreen = pxc_back->g;
		pbq[0].rgbRed = pxc_back->r;
		pbq[1].rgbBlue = pxc_front->b;
		pbq[1].rgbGreen = pxc_front->g;
		pbq[1].rgbRed = pxc_front->r;
	}
	else if (pbh->biBitCount == 4)
	{
		xbmp_fill_quad(4, 16, (unsigned char*)pbq, 16);
	}
	else if (pbh->biBitCount == 8)
	{
		xbmp_fill_quad(8, 216, (unsigned char*)pbq, 256);
	}

	dibBmp = CreateDIBSection(hDC, pbi, DIB_RGB_COLORS, (void**)&pbb, NULL, 0);
	xmem_free(pbi);

	if (!dibBmp)
	{
		return NULL;
	}

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = deep;
	bih.compress = 0;
	bih.bytes = BMP_LINE_BYTES(w, bih.clrbits) * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	if (bih.clrbits <= 8)
	{
		pquad = (bitmap_quad_t*)xmem_alloc(sizeof(bitmap_quad_t) * (1 << bih.clrbits));
	}

	if (bih.clrbits == 1)
	{
		pquad[0].blue = pxc_back->b;
		pquad[0].green = pxc_back->g;
		pquad[0].red = pxc_back->r;
		pquad[1].blue = pxc_front->b;
		pquad[1].green = pxc_front->g;
		pquad[1].red = pxc_front->r;
	}
	else if (bih.clrbits == 4)
	{
		xbmp_fill_quad(4, 16, (unsigned char*)pquad, 16);
	}
	else if (bih.clrbits == 8)
	{
		xbmp_fill_quad(8, 216, (unsigned char*)pquad, 256);
	}

	fill_code128_dibbits(pxc_front, pxc_back, bar_buf, bar_cols, unit, &bih, pquad, pbb, bih.bytes);
	xmem_free(pquad);

	pwb = (win32_bitmap_t*)xmem_alloc(sizeof(win32_bitmap_t));
	pwb->head.tag = _HANDLE_BITMAP;

	pwb->bitmap = dibBmp;

	return (bitmap_t)&pwb->head;
}

bitmap_t _create_pdf417_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC winDC, hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb;
	HBITMAP dibBmp;
	int w, h, unit;

	BITMAPINFO* pbi = NULL;
	BITMAPINFOHEADER* pbh = NULL;
	RGBQUAD* pbq = NULL;

	bitmap_info_head_t bih = { 0 };
	bitmap_quad_t* pquad = NULL;
	byte_t* pbb = NULL;
	int deep = 8;

	winDC = GetDC(NULL);
	unit = GetDeviceCaps(hDC, LOGPIXELSX) / GetDeviceCaps(winDC, LOGPIXELSX);
	ReleaseDC(NULL, winDC);
	if (unit < 2) unit = 2;

	w = (pdf417_units(bar_buf, bar_rows, bar_cols) / bar_rows) * unit;
	h = bar_rows * unit;

	if (deep > 8)
		pbi = (BITMAPINFO*)xmem_alloc(sizeof(BITMAPINFO));
	else
		pbi = (BITMAPINFO*)xmem_alloc(sizeof(BITMAPINFO) + sizeof(RGBQUAD) * (1 << deep));

	pbh = (BITMAPINFOHEADER*)pbi;
	pbq = pbi->bmiColors;

	pbh->biSize = sizeof(BITMAPINFOHEADER);
	pbh->biWidth = w;
	pbh->biHeight = h;
	pbh->biPlanes = 1;
	pbh->biBitCount = deep;
	pbh->biCompression = BI_RGB;
	pbh->biSizeImage = 0;
	pbh->biXPelsPerMeter = 0;
	pbh->biYPelsPerMeter = 0;
	pbh->biClrUsed = 0;
	pbh->biClrImportant = 0;

	if (pbh->biBitCount == 1)
	{
		pbq[0].rgbBlue = pxc_back->b;
		pbq[0].rgbGreen = pxc_back->g;
		pbq[0].rgbRed = pxc_back->r;
		pbq[1].rgbBlue = pxc_front->b;
		pbq[1].rgbGreen = pxc_front->g;
		pbq[1].rgbRed = pxc_front->r;
	}
	else if (pbh->biBitCount == 4)
	{
		xbmp_fill_quad(4, 16, (unsigned char*)pbq, 16);
	}
	else if (pbh->biBitCount == 8)
	{
		xbmp_fill_quad(8, 216, (unsigned char*)pbq, 256);
	}

	dibBmp = CreateDIBSection(hDC, pbi, DIB_RGB_COLORS, (void**)&pbb, NULL, 0);
	xmem_free(pbi);

	if (!dibBmp)
	{
		return NULL;
	}

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = deep;
	bih.compress = 0;
	bih.bytes = BMP_LINE_BYTES(w, bih.clrbits) * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	if (bih.clrbits <= 8)
	{
		pquad = (bitmap_quad_t*)xmem_alloc(sizeof(bitmap_quad_t) * (1 << bih.clrbits));
	}

	if (bih.clrbits == 1)
	{
		pquad[0].blue = pxc_back->b;
		pquad[0].green = pxc_back->g;
		pquad[0].red = pxc_back->r;
		pquad[1].blue = pxc_front->b;
		pquad[1].green = pxc_front->g;
		pquad[1].red = pxc_front->r;
	}
	else if (bih.clrbits == 4)
	{
		xbmp_fill_quad(4, 16, (unsigned char*)pquad, 16);
	}
	else if (bih.clrbits == 8)
	{
		xbmp_fill_quad(8, 216, (unsigned char*)pquad, 256);
	}

	fill_pdf417_dibbits(pxc_front, pxc_back, bar_buf, bar_rows, bar_cols, unit, &bih, pquad, pbb, bih.bytes);
	xmem_free(pquad);

	pwb = (win32_bitmap_t*)xmem_alloc(sizeof(win32_bitmap_t));
	pwb->head.tag = _HANDLE_BITMAP;

	pwb->bitmap = dibBmp;

	return (bitmap_t)&pwb->head;
}

bitmap_t _create_qrcode_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC winDC, hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb;
	HBITMAP dibBmp;
	int w, h, unit;

	BITMAPINFO* pbi = NULL;
	BITMAPINFOHEADER* pbh = NULL;
	RGBQUAD* pbq = NULL;

	bitmap_info_head_t bih = { 0 };
	bitmap_quad_t* pquad = NULL;
	byte_t* pbb = NULL;
	int deep = 8;

	winDC = GetDC(NULL);
	unit = GetDeviceCaps(hDC, LOGPIXELSX) / GetDeviceCaps(winDC, LOGPIXELSX);
	ReleaseDC(NULL, winDC);
	if (unit < 2) unit = 2;

	w = (qr_units(bar_buf, bar_rows, bar_cols) / bar_rows) * unit;
	h = bar_rows * unit;

	if (deep > 8)
		pbi = (BITMAPINFO*)xmem_alloc(sizeof(BITMAPINFO));
	else
		pbi = (BITMAPINFO*)xmem_alloc(sizeof(BITMAPINFO) + sizeof(RGBQUAD) * (1 << deep));

	pbh = (BITMAPINFOHEADER*)pbi;
	pbq = pbi->bmiColors;

	pbh->biSize = sizeof(BITMAPINFOHEADER);
	pbh->biWidth = w;
	pbh->biHeight = h;
	pbh->biPlanes = 1;
	pbh->biBitCount = deep;
	pbh->biCompression = BI_RGB;
	pbh->biSizeImage = 0;
	pbh->biXPelsPerMeter = 0;
	pbh->biYPelsPerMeter = 0;
	pbh->biClrUsed = 0;
	pbh->biClrImportant = 0;

	if (pbh->biBitCount == 1)
	{
		pbq[0].rgbBlue = pxc_back->b;
		pbq[0].rgbGreen = pxc_back->g;
		pbq[0].rgbRed = pxc_back->r;
		pbq[1].rgbBlue = pxc_front->b;
		pbq[1].rgbGreen = pxc_front->g;
		pbq[1].rgbRed = pxc_front->r;
	}
	else if (pbh->biBitCount == 4)
	{
		xbmp_fill_quad(4, 16, (unsigned char*)pbq, 16);
	}
	else if (pbh->biBitCount == 8)
	{
		xbmp_fill_quad(8, 216, (unsigned char*)pbq, 256);
	}

	dibBmp = CreateDIBSection(hDC, pbi, DIB_RGB_COLORS, (void**)&pbb, NULL, 0);
	xmem_free(pbi);

	if (!dibBmp)
	{
		return NULL;
	}

	bih.isize = BITMAPINFOHEAD_FIXED_SIZE;
	bih.width = w;
	bih.height = h;
	bih.planes = 1;
	bih.clrbits = deep;
	bih.compress = 0;
	bih.bytes = BMP_LINE_BYTES(w, bih.clrbits) * h;
	bih.xpelsperm = 0;
	bih.ypelsperm = 0;
	bih.clrused = 0;
	bih.clrimport = 0;

	if (bih.clrbits <= 8)
	{
		pquad = (bitmap_quad_t*)xmem_alloc(sizeof(bitmap_quad_t) * (1 << bih.clrbits));
	}

	if (bih.clrbits == 1)
	{
		pquad[0].blue = pxc_back->b;
		pquad[0].green = pxc_back->g;
		pquad[0].red = pxc_back->r;
		pquad[1].blue = pxc_front->b;
		pquad[1].green = pxc_front->g;
		pquad[1].red = pxc_front->r;
	}
	else if (bih.clrbits == 4)
	{
		xbmp_fill_quad(4, 16, (unsigned char*)pquad, 16);
	}
	else if (bih.clrbits == 8)
	{
		xbmp_fill_quad(8, 216, (unsigned char*)pquad, 256);
	}

	fill_qrcode_dibbits(pxc_front, pxc_back, bar_buf, bar_rows, bar_cols, unit, &bih, pquad, pbb, bih.bytes);
	xmem_free(pquad);

	pwb = (win32_bitmap_t*)xmem_alloc(sizeof(win32_bitmap_t));
	pwb->head.tag = _HANDLE_BITMAP;

	pwb->bitmap = dibBmp;

	return (bitmap_t)&pwb->head;
}

bitmap_t _create_storage_bitmap(visual_t rdc, const tchar_t* filename)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb;

	HANDLE handle;
	IPicture* p = NULL;
	IStream* s = NULL;
	HGLOBAL hb = NULL;
	dword_t size = 0;
	void* buf = NULL;

	WIN32_FILE_ATTRIBUTE_DATA ad = { 0 };
	HANDLE hFile;
	DWORD dw = 0;
	
	if (is_null(filename))
		return 0;

	if (!GetFileAttributesEx(filename, GetFileExInfoStandard, &ad))
		return 0;

	if (!ad.nFileSizeLow || ad.nFileSizeHigh)
		return 0;

	hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if ((HANDLE)hFile == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	
	size = ad.nFileSizeLow;
	hb = GlobalAlloc(GHND, size);

	if (!hb)
		return 0;

	buf = GlobalLock(hb);

	if (!ReadFile(hFile, buf, (DWORD)size, &dw, NULL))
	{
		GlobalUnlock(hb);
		GlobalFree(hb);
		return 0;
	}

	CloseHandle(hFile);

	CreateStreamOnHGlobal(hb, FALSE, &s);
	if (s == NULL)
	{
		GlobalUnlock(hb);
		GlobalFree(hb);
		return 0;
	}

	OleLoadPicture(s, 0, FALSE, IID_IPicture, (void**)&p);
	s->Release();
	GlobalUnlock(hb);
	GlobalFree(hb);

	if (p == NULL)
		return NULL;

	p->get_Handle((OLE_HANDLE *)&handle);

	handle = (HANDLE)CopyImage(handle, IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION | LR_COPYRETURNORG);

	p->Release();

	pwb = (win32_bitmap_t*)xmem_alloc(sizeof(win32_bitmap_t));
	pwb->head.tag = _HANDLE_BITMAP;

	pwb->bitmap = (HBITMAP)handle;

	return (bitmap_t)&pwb->head;
}
/*******************************************************************************/

dword_t _get_bitmap_bytes(bitmap_t rb)
{
	win32_bitmap_t* pwb = (win32_bitmap_t*)rb;
	BITMAP bmp;
	WORD cClrBits;
	DWORD dwClrUsed;
	DWORD dwSizeImage;
	DWORD dwTotal;

	XDK_ASSERT(rb && rb->tag == _HANDLE_BITMAP);

	if (!GetObject(pwb->bitmap, sizeof(BITMAP), (LPSTR)&bmp))
		return 0;

	cClrBits = (WORD)(bmp.bmPlanes * bmp.bmBitsPixel);

	if (cClrBits == 1)
		cClrBits = 1;
	else if (cClrBits <= 4)
		cClrBits = 4;
	else if (cClrBits <= 8)
		cClrBits = 8;
	else if (cClrBits <= 16)
		cClrBits = 16;
	else if (cClrBits <= 24)
		cClrBits = 24;
	else
		cClrBits = 32;

	if (cClrBits < 24)
		dwClrUsed = (1 << cClrBits);
	else
		dwClrUsed = 0;

	dwSizeImage = ((bmp.bmWidth * cClrBits + 31) & ~31) / 8 * bmp.bmHeight;

	dwTotal = (DWORD)(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwClrUsed * sizeof(RGBQUAD) + dwSizeImage);

	return dwTotal;
}

bitmap_t _load_bitmap_from_bytes(visual_t rdc, const unsigned char* pb, dword_t bytes)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb;

	PBITMAPINFO pbmi;
	BITMAPFILEHEADER bfh;
	LPBYTE lpBits;

	if (!pb)
		return NULL;

	if ((DWORD)bytes < sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER))
		return NULL;

	CopyMemory((void*)&bfh, (void*)pb, sizeof(BITMAPFILEHEADER));

	if (bfh.bfType != 0x4d42)
		return NULL;

	if ((DWORD)bytes < bfh.bfSize)
		return NULL;

	pbmi = (PBITMAPINFO)(pb + sizeof(BITMAPFILEHEADER));
	lpBits = (LPBYTE)(pb + bfh.bfOffBits);

	pwb = (win32_bitmap_t*)xmem_alloc(sizeof(win32_bitmap_t));
	pwb->head.tag = _HANDLE_BITMAP;

#ifdef WINCE
	pwb->bitmap = CreateDIBSection(hDC, pbmi, DIB_RGB_COLORS, NULL, NULL, bfh.bfOffBits);
#else
	pwb->bitmap = CreateDIBitmap(hDC, (BITMAPINFOHEADER*)pbmi, CBM_INIT, lpBits, pbmi, DIB_RGB_COLORS);
#endif

	return (bitmap_t)&pwb->head;
}

dword_t _save_bitmap_to_bytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb = (win32_bitmap_t*)rb;

	BITMAP bmp;
	PBITMAPINFO pbmi;
	WORD    cClrBits;
	BITMAPFILEHEADER bfh;
	PBITMAPINFOHEADER pbih;
	LPBYTE lpBits;
	DWORD dwTotal;
#ifdef WINCE
	HBITMAP hSec;
	void* pbuf;
#endif

	XDK_ASSERT(rb && rb->tag == _HANDLE_BITMAP);

	if (!GetObject(pwb->bitmap, sizeof(BITMAP), (LPSTR)&bmp))
		return 0;

	cClrBits = (WORD)(bmp.bmPlanes * bmp.bmBitsPixel);

	if (cClrBits == 1)
		cClrBits = 1;
	else if (cClrBits <= 4)
		cClrBits = 4;
	else if (cClrBits <= 8)
		cClrBits = 8;
	else if (cClrBits <= 16)
		cClrBits = 16;
	else if (cClrBits <= 24)
		cClrBits = 24;
	else
		cClrBits = 32;

	if (cClrBits < 24)
		pbmi = (PBITMAPINFO)xmem_alloc(sizeof(BITMAPINFOHEADER) + sizeof(RGBQUAD) * (DWORD)(1 << cClrBits));
	else
		pbmi = (PBITMAPINFO)xmem_alloc(sizeof(BITMAPINFOHEADER));

	pbmi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	pbmi->bmiHeader.biWidth = bmp.bmWidth;
	pbmi->bmiHeader.biHeight = bmp.bmHeight;
	pbmi->bmiHeader.biPlanes = bmp.bmPlanes;
	pbmi->bmiHeader.biBitCount = bmp.bmBitsPixel;
	if (cClrBits < 24)
		pbmi->bmiHeader.biClrUsed = (1 << cClrBits);
	else
		pbmi->bmiHeader.biClrUsed = 0;
	pbmi->bmiHeader.biCompression = BI_RGB;
	pbmi->bmiHeader.biSizeImage = ((pbmi->bmiHeader.biWidth * cClrBits + 31) & ~31) / 8 * pbmi->bmiHeader.biHeight;
	pbmi->bmiHeader.biClrImportant = 0;

	pbih = (PBITMAPINFOHEADER)pbmi;

	bfh.bfType = 0x4d42;        // 0x42 = "B" 0x4d = "M" 
	bfh.bfSize = (DWORD)(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + pbih->biClrUsed * sizeof(RGBQUAD) + pbih->biSizeImage);
	bfh.bfReserved1 = 0;
	bfh.bfReserved2 = 0;
	bfh.bfOffBits = (DWORD)(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + pbih->biClrUsed * sizeof(RGBQUAD));

	if (pbih->biSizeImage > (DWORD)max)
	{
		xmem_free(pbmi);
		return 0;
	}

	dwTotal = 0;
	if (buf)
	{
		CopyMemory((void*)(buf + dwTotal), (void*)&bfh, sizeof(BITMAPFILEHEADER));
	}
	dwTotal += sizeof(BITMAPFILEHEADER);

	if (buf)
	{
		CopyMemory((void*)(buf + dwTotal), (void*)pbih, sizeof(BITMAPINFOHEADER) + pbih->biClrUsed * sizeof(RGBQUAD));
	}
	dwTotal += sizeof(BITMAPINFOHEADER) + pbih->biClrUsed * sizeof(RGBQUAD);

	if (buf)
	{
		lpBits = (LPBYTE)(buf + dwTotal);
	}
	else
	{
		lpBits = NULL;
	}
	dwTotal += pbih->biSizeImage;

	if (buf)
	{
#ifdef WINCE
		pbuf = NULL;
		hSec = CreateDIBSection(hDC, pbmi, DIB_RGB_COLORS, &pbuf, NULL, bfh.bfOffBits);
		if(!hSec)
		{
			xmem_free(pbmi);
			return 0;
		}
		CopyMemory((void*)lpBits, (void*)pbuf, pbih->biSizeImage);
		DeleteObject(hSec);
#else
		if (!GetDIBits(hDC, pwb->bitmap, 0, (WORD)pbih->biHeight, lpBits, pbmi, DIB_RGB_COLORS))
		{
			xmem_free(pbmi);
			return 0;
		}
#endif
	}

	xmem_free(pbmi);

	return dwTotal;
}

#ifdef XDU_SUPPORT_SHELL
bitmap_t _load_bitmap_from_icon(visual_t rdc, const tchar_t* iname)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb;

	HICON hIcon;
	ICONINFO ico = { 0 };

	int w, h;
	RECT rt;
	HDC hdc;
	HBITMAP hbmp, horg;
	HBRUSH hBrush;

	if (_tcsicmp(iname, ICON_QUESTION) == 0)
		hIcon = LoadIcon(NULL, IDI_QUESTION);
	else if (_tcsicmp(iname, ICON_EXCLAMATION) == 0)
		hIcon = LoadIcon(NULL, IDI_EXCLAMATION);
	else if (_tcsicmp(iname, ICON_INFORMATION) == 0)
		hIcon = LoadIcon(NULL, IDI_EXCLAMATION);
	else if (_tcsicmp(iname, ICON_WARING) == 0)
		hIcon = LoadIcon(NULL, IDI_WARNING);
	else if (_tcsicmp(iname, ICON_ERROR) == 0)
		hIcon = LoadIcon(NULL, IDI_ERROR);
	else if (_tcsicmp(iname, ICON_HAND) == 0)
		hIcon = LoadIcon(NULL, IDI_HAND);
	else if (_tcsicmp(iname, ICON_ASTERISK) == 0)
		hIcon = LoadIcon(NULL, IDI_ASTERISK);
	else
		hIcon = LoadIcon(NULL, IDI_APPLICATION);

	GetIconInfo(hIcon, &ico);

	w = ico.xHotspot * 2;
	h = ico.yHotspot * 2;

	rt.top = rt.bottom = 0;
	rt.right = w;
	rt.bottom = h;

	hdc = CreateCompatibleDC(hDC);
	hbmp = CreateCompatibleBitmap(hDC, w, h);
	horg = (HBITMAP)SelectObject(hdc, hbmp);

	hBrush = CreateSolidBrush(RGB(250, 250, 250));

	FillRect(hdc, &rt, hBrush);

	DrawIcon(hdc, 0, 0, hIcon);

	DeleteObject(hBrush);
	hbmp = (HBITMAP)SelectObject(hdc, horg);
	DeleteDC(hdc);

	DeleteObject(ico.hbmColor);
	DeleteObject(ico.hbmMask);

	pwb = (win32_bitmap_t*)xmem_alloc(sizeof(win32_bitmap_t));
	pwb->head.tag = _HANDLE_BITMAP;

	pwb->bitmap = (HBITMAP)hbmp;

	return (bitmap_t)&pwb->head;
}

bitmap_t _load_bitmap_from_thumb(visual_t rdc, const tchar_t* file)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb;

	SHFILEINFO shi = { 0 };
	ICONINFO ico = { 0 };

	RECT rt;
	int w, h;
	HDC hdc;
	HBITMAP hbmp, horg;
	HBRUSH hBrush;

	SHGetFileInfo(file, 0, &shi, sizeof(shi), SHGFI_ICON);

	if (!shi.hIcon)
		return NULL;

	GetIconInfo(shi.hIcon, &ico);

	w = ico.xHotspot * 2;
	h = ico.yHotspot * 2;

	rt.top = rt.bottom = 0;
	rt.right = w;
	rt.bottom = h;

	hdc = CreateCompatibleDC(hDC);
	hbmp = CreateCompatibleBitmap(hDC, w, h);
	horg = (HBITMAP)SelectObject(hdc, hbmp);

	hBrush = CreateSolidBrush(RGB(250, 250, 250));

	FillRect(hdc, &rt, hBrush);

	DrawIcon(hdc, 0, 0, shi.hIcon);

	DeleteObject(hBrush);
	hbmp = (HBITMAP)SelectObject(hdc, horg);
	DeleteDC(hdc);

	DeleteObject(ico.hbmColor);
	DeleteObject(ico.hbmMask);

	pwb = (win32_bitmap_t*)xmem_alloc(sizeof(win32_bitmap_t));
	pwb->head.tag = _HANDLE_BITMAP;

	pwb->bitmap = (HBITMAP)hbmp;

	return (bitmap_t)&pwb->head;
}
#endif //XDU_SUPPORT_SHELL

#endif //XDU_SUPPORT_CONTEXT_BITMAP
