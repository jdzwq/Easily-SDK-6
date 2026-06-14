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

#if defined(_WCE)
#include "wince/_if_wince.h"
#elif defined(_W32)
#include "win32/_if_win32.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT_BITMAP

void _destroy_bitmap(bitmap_t rbm)
{
#if defined(WINCE)
	wceDestroyBitmap(rbm);
#elif defined(WIN32)
	winDestroyBitmap(rbm);
#endif
}

void _get_bitmap_size(bitmap_t rbm, int* pw, int* ph)
{
#if defined(WINCE)
	wceGetBitmapSize(rbm, pw, ph);
#elif defined(WIN32)
	winGetBitmapSize(rbm, pw, ph);
#endif
}

bitmap_t _create_context_bitmap(visual_t rdc)
{
#if defined(WINCE)
	return wceCreateContextBitmap(rdc);
#elif defined(WIN32)
	return winCreateContextBitmap(rdc);
#endif
}

bitmap_t _create_color_bitmap(visual_t rdc, const xcolor_t* pxc, int w, int h)
{
#if defined(WINCE)
	return wceCreateColorBitmap(rdc, pxc, w, h);
#elif defined(WIN32)
	return winCreateColorBitmap(rdc, pxc, w, h);
#endif
}

bitmap_t _create_pattern_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h)
{
#if defined(WINCE)
	return wceCreatePatternBitmap(rdc, pxc_front, pxc_back, w, h);
#elif defined(WIN32)
	return winCreatePatternBitmap(rdc, pxc_front, pxc_back, w, h);
#endif
}

bitmap_t _create_gradient_bitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type)
{
#if defined(WINCE)
	return wceCreateGradientBitmap(rdc, pxc_brim, pxc_core, w, h, type);
#elif defined(WIN32)
	return winCreateGradientBitmap(rdc, pxc_brim, pxc_core, w, h, type);
#endif
}

bitmap_t _create_code128_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols)
{
#if defined(WINCE)
	return wceCreateCode128Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_cols);
#elif defined(WIN32)
	return winCreateCode128Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_cols);
#endif
}

bitmap_t _create_pdf417_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
#if defined(WINCE)
	return wceCreatePDF417Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#elif defined(WIN32)
	return winCreatePDF417Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#endif
}

bitmap_t _create_qrcode_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
#if defined(WINCE)
	return wceCreateQRCodeBitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#elif defined(WIN32)
	return winCreateQRCodeBitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#endif
} 

bitmap_t _create_storage_bitmap(visual_t rdc, const tchar_t* fname)
{
#if defined(WINCE)
	return wceCreateStorageBitmap(rdc, fname);
#elif defined(WIN32)
	return winCreateStorageBitmap(rdc, fname);
#endif
}

/*******************************************************************************/

dword_t _get_bitmap_bytes(bitmap_t rb)
{
#if defined(WINCE)
	return wceGetBitmapBytes(rb);
#elif defined(WIN32)
	return winGetBitmapBytes(rb);
#endif
}

bitmap_t _load_bitmap_from_bytes(visual_t rdc, const unsigned char* pb, dword_t bytes)
{
#if defined(WINCE)
	return wceLoadBitmapFromBytes(rdc, pb, bytes);
#elif defined(WIN32)
	return winLoadBitmapFromBytes(rdc, pb, bytes);
#endif
}

dword_t _save_bitmap_to_bytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max)
{
#if defined(WINCE)
	return wceSaveBitmapToBytes(rdc, rb, buf, max);
#elif defined(WIN32)
	return winSaveBitmapToBytes(rdc, rb, buf, max);
#endif
}

bitmap_t _load_bitmap_from_icon(visual_t rdc, const tchar_t* iname)
{
#if defined(WINCE)
	return wceLoadBitmapFromIcon(rdc, iname);
#elif defined(WIN32)
	return winLoadBitmapFromIcon(rdc, iname);
#endif
}

bitmap_t _load_bitmap_from_thumb(visual_t rdc, const tchar_t* file)
{    
#if defined(WINCE)
	return wceLoadBitmapFromThumb(rdc, file);
#elif defined(WIN32)
	return winLoadBitmapFromThumb(rdc, file);
#endif
}

#endif //XDU_SUPPORT_CONTEXT_BITMAP