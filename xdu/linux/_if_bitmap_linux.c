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

#if defined(_X11)
#include "X11/_if_x11.h"
#elif defined(_WAYLAND)
#include "wayland/_if_wayland.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT_BITMAP

void _destroy_bitmap(bitmap_t rbm)
{
#if defined(_X11)
	xlDestroyBitmap(rbm);
#elif defined(_WAYLAND)
	wlDestroyBitmap(rbm);
#endif
}

void _get_bitmap_size(bitmap_t rbm, int* pw, int* ph)
{
#if defined(_X11)
	xlGetBitmapSize(rbm, pw, ph);
#elif defined(_WAYLAND)
	wlGetBitmapSize(rbm, pw, ph);
#endif
}

bitmap_t _create_context_bitmap(visual_t rdc)
{
#if defined(_X11)
	return xlCreateContextBitmap(rdc);
#elif defined(_WAYLAND)
	return wlCreateContextBitmap(rdc);
#endif
}

bitmap_t _create_color_bitmap(visual_t rdc, const xcolor_t* pxc, int w, int h)
{
#if defined(_X11)
	return xlCreateColorBitmap(rdc, pxc, w, h);
#elif defined(_WAYLAND)
	return wlCreateColorBitmap(rdc, pxc, w, h);
#endif
}

bitmap_t _create_pattern_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h)
{
#if defined(_X11)
	return xlCreatePatternBitmap(rdc, pxc_front, pxc_back, w, h);
#elif defined(_WAYLAND)
	return wlCreatePatternBitmap(rdc, pxc_front, pxc_back, w, h);
#endif
}

bitmap_t _create_gradient_bitmap(visual_t rdc, const xcolor_t* pxc_brim, const xcolor_t* pxc_core, int w, int h, const tchar_t* type)
{
#if defined(_X11)
	return xlCreateGradientBitmap(rdc, pxc_brim, pxc_core, w, h, type);
#elif defined(_WAYLAND)
	return wlCreateGradientBitmap(rdc, pxc_brim, pxc_core, w, h, type);
#endif
}

bitmap_t _create_code128_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_cols)
{
#if defined(_X11)
	return xlCreateCode128Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_cols);
#elif defined(_WAYLAND)
	return wlCreateCode128Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_cols);
#endif
}

bitmap_t _create_pdf417_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
#if defined(_X11)
	return xlCreatePDF417Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#elif defined(_WAYLAND)
	return wlCreatePDF417Bitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#endif
}

bitmap_t _create_qrcode_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const byte_t* bar_buf, int bar_rows, int bar_cols)
{
#if defined(_X11)
	return xlCreateQRCodeBitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#elif defined(_WAYLAND)
	return wlCreateQRCodeBitmap(rdc, pxc_front, pxc_back, bar_buf, bar_rows, bar_cols);
#endif
} 

bitmap_t _create_storage_bitmap(visual_t rdc, const tchar_t* fname)
{
#if defined(_X11)
	return xlCreateStorageBitmap(rdc, fname);
#elif defined(_WAYLAND)
	return wlCreateStorageBitmap(rdc, fname);
#endif
}

/*******************************************************************************/

dword_t _get_bitmap_bytes(bitmap_t rb)
{
#if defined(_X11)
	return xlGetBitmapBytes(rb);
#elif defined(_WAYLAND)
	return wlGetBitmapBytes(rb);
#endif
}

bitmap_t _load_bitmap_from_bytes(visual_t rdc, const unsigned char* pb, dword_t bytes)
{
#if defined(_X11)
	return xlLoadBitmapFromBytes(rdc, pb, bytes);
#elif defined(_WAYLAND)
	return wlLoadBitmapFromBytes(rdc, pb, bytes);
#endif
}

dword_t _save_bitmap_to_bytes(visual_t rdc, bitmap_t rb, unsigned char* buf, dword_t max)
{
#if defined(_X11)
	return xlSaveBitmapToBytes(rdc, rb, buf, max);
#elif defined(_WAYLAND)
	return wlSaveBitmapToBytes(rdc, rb, buf, max);
#endif
}

bitmap_t _load_bitmap_from_icon(visual_t rdc, const tchar_t* iname)
{
#if defined(_X11)
	return xlLoadBitmapFromIcon(rdc, iname);
#elif defined(_WAYLAND)
	return wlLoadBitmapFromIcon(rdc, iname);
#endif
}

bitmap_t _load_bitmap_from_thumb(visual_t rdc, const tchar_t* file)
{    
#if defined(_X11)
	return xlLoadBitmapFromThumb(rdc, file);
#elif defined(_WAYLAND)
	return wlLoadBitmapFromThumb(rdc, file);
#endif
}

#endif //XDU_SUPPORT_CONTEXT_BITMAP