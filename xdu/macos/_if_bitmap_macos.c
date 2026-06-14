/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc bitmap document

	@module	if_bitmap_linux.c | linux implement file

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

#if defined(_COCOA)
#include "cocoa/_if_cocoa.h"
#elif defined(_XQUARTZ)
#include "xquartz/_if_xquartz.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT_BITMAP

void _destroy_bitmap(bitmap_t rbm)
{
#if defined(_COCOA)
	coDestroyBitmap(rbm);
#elif defined(_XQUARTZ)
	xqDestroyBitmap(rbm);
#endif
}

void _get_bitmap_size(bitmap_t rbm, int* pw, int* ph)
{
#if defined(_COCOA)
	coGetBitmapSize(rbm, pw, ph);
#elif defined(_XQUARTZ)
	xqGetBitmapSize(rbm, pw, ph);
#endif
}

bitmap_t _create_context_bitmap(visual_t rdc)
{
#if defined(_COCOA)
	return coCreateContextBitmap(rdc);
#elif defined(_XQUARTZ)
	return xqCreateContextBitmap(rdc);
#endif
}

bitmap_t _create_color_bitmap(visual_t rdc, const xcolor_t* pxc, int w, int h)
{
#if defined(_COCOA)
	return coCreateColorBitmap(rdc, pxc, w, h);
#elif defined(_XQUARTZ)
	return xqCreateColorBitmap(rdc, pxc, w, h);
#endif
}

bitmap_t _create_pattern_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h)
{
#if defined(_COCOA)
	return coCreatePatternBitmap(rdc, pxc_front, pxc_back, w, h);
#elif defined(_XQUARTZ)
	return xqCreatePatternBitmap(rdc, pxc_front, pxc_back, w, h);
#endif
}

bitmap_t _create_gradient_bitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type)
{
#if defined(_COCOA)
	return coCreateGradientBitmap(rdc, pxc_brim, pxc_core, w, h, type);
#elif defined(_XQUARTZ)
	return xqCreateGradientBitmap(rdc, pxc_brim, pxc_core, w, h, type);
#endif
}

bitmap_t _create_code128_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols)
{
#if defined(_COCOA)
	return coCreateCode128Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_cols);
#elif defined(_XQUARTZ)
	return xqCreateCode128Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_cols);
#endif
}

bitmap_t _create_pdf417_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
#if defined(_COCOA)
	return coCreatePDF417Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#elif defined(_XQUARTZ)
	return xqCreatePDF417Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#endif
}

bitmap_t _create_qrcode_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
#if defined(_COCOA)
	return coCreateQRCodeBitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#elif defined(_XQUARTZ)
	return xqCreateQRCodeBitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#endif
} 

bitmap_t _create_storage_bitmap(visual_t rdc, const tchar_t* fname)
{
#if defined(_COCOA)
	return coCreateStorageBitmap(rdc, fname);
#elif defined(_XQUARTZ)
	return xqCreateStorageBitmap(rdc, fname);
#endif
}

/*******************************************************************************/

dword_t _get_bitmap_bytes(bitmap_t rb)
{
#if defined(_COCOA)
	return coGetBitmapBytes(rb);
#elif defined(_XQUARTZ)
	return xqGetBitmapBytes(rb);
#endif
}

bitmap_t _load_bitmap_from_bytes(visual_t rdc, const unsigned char* pb, dword_t bytes)
{
#if defined(_COCOA)
	return coLoadBitmapFromBytes(rdc, pb, bytes);
#elif defined(_XQUARTZ)
	return xqLoadBitmapFromBytes(rdc, pb, bytes);
#endif
}

dword_t _save_bitmap_to_bytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max)
{
#if defined(_COCOA)
	return coSaveBitmapToBytes(rdc, rb, buf, max);
#elif defined(_XQUARTZ)
	return xqSaveBitmapToBytes(rdc, rb, buf, max);
#endif
}

bitmap_t _load_bitmap_from_icon(visual_t rdc, const tchar_t* iname)
{
#if defined(_COCOA)
	return coLoadBitmapFromIcon(rdc, iname);
#elif defined(_XQUARTZ)
	return xqLoadBitmapFromIcon(rdc, iname);
#endif
}

bitmap_t _load_bitmap_from_thumb(visual_t rdc, const tchar_t* file)
{    
#if defined(_COCOA)
	return coLoadBitmapFromThumb(rdc, file);
#elif defined(_XQUARTZ)
	return xqLoadBitmapFromThumb(rdc, file);
#endif
}

#endif //XDU_SUPPORT_CONTEXT_BITMAP