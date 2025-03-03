﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdc display context document

	@module	impbitmap.h | interface file

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

#ifndef _IMPBITMAP_H
#define _IMPBITMAP_H

#include "../xdcdef.h"

#if defined(XDU_SUPPORT_CONTEXT_BITMAP)

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION destroy_bitmap: destroy bitmap object.
@INPUT bitmap_t bmp: device context resource handle.
@RETURN void: none.
*/
EXP_API void destroy_bitmap(bitmap_t bmp);

/*
@FUNCTION get_bitmap_size: get bitmap size in points.
@INPUT bitmap_t bmp: bitmap resource handle.
@OUTPUT int* pw: int value for returning width.
@OUTPUT int* ph: int value for returning height.
@RETURN void: none.
*/
EXP_API void get_bitmap_size(bitmap_t bmp, int* pw, int* ph);

/*
@FUNCTION create_context_bitmap: create a bitmap from memory context.
@INPUT visual_t rdc: memoey context resource handle.
@RETURN bitmap_t: if succeeds return bitmap resource handle, fails return NULL.
*/
EXP_API bitmap_t create_context_bitmap(visual_t rdc);

/*
@FUNCTION create_color_bitmap: create a color based bitmap.
@INPUT visual_t rdc: device context resource handle.
@INPUT const xcolor_t* pxc: the color struct.
@INPUT int w: the bitmap width in points.
@INPUT int h: the bitmap height in points.
@RETURN bitmap_t: if succeeds return bitmap resource handle, fails return NULL.
*/
EXP_API bitmap_t create_color_bitmap(visual_t rdc, const xcolor_t* pxc, int w, int h);

/*
@FUNCTION create_pattern_bitmap: create a pattern bitmap.
@INPUT visual_t rdc: device context resource handle.
@INPUT const xcolor_t* pxc_front: the color struct for front drawing.
@INPUT const xcolor_t* pxc_back: the color struct for background drawing.
@INPUT int w: the bitmap width in points.
@INPUT int h: the bitmap height in points.
@INPUT const tchar_t* lay: the layout mode, it can be GDI_ATTR_LAYOUT_HORZ, GDI_ATTR_LAYOUT_VERT, GDI_ATTR_LAYOUT_CROSS.
@RETURN bitmap_t: if succeeds return bitmap resource handle, fails return NULL.
*/
EXP_API bitmap_t create_pattern_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, int w, int h);

/*
@FUNCTION create_gradient_bitmap: create a gradient bitmap.
@INPUT visual_t rdc: device context resource handle.
@INPUT const xcolor_t* pxc_near: the color struct for nearest drawing.
@INPUT const xcolor_t* pxc_center: the color struct for center drawing.
@INPUT int w: the bitmap width in points.
@INPUT int h: the bitmap height in points.
@INPUT const tchar_t* lay: the layout mode, it can be GDI_ATTR_LAYOUT_HORZ, GDI_ATTR_LAYOUT_VERT, GDI_ATTR_LAYOUT_CROSS.
@RETURN bitmap_t: if succeeds return bitmap resource handle, fails return NULL.
*/
EXP_API bitmap_t create_gradient_bitmap(visual_t rdc, const xcolor_t* pxc_near, const xcolor_t* pxc_center, int w, int h, const tchar_t* lay);

/*
@FUNCTION load_bitmap_from_bytes: create bitmap from dib data buffer.
@INPUT visual_t rdc: device context resource handle.
@INPUT const byte_t* pb: the dib data buffer.
@INPUT dword_t len: the dib bytes
@RETURN bitmap_t: if succeeds return bitmap resource handle, fails return NULL.
*/
EXP_API bitmap_t load_bitmap_from_bytes(visual_t rdc, const byte_t* pb, dword_t len);

/*
@FUNCTION save_bitmap_to_bytes: save bitmap as dib data.
@INPUT visual_t rdc: device context resource handle.
@INPUT bitmap_t rb: bitmap resource handle.
@OUTPUT byte_t* pb: the buffer for returning dib data.
@INPUT dword_t max: the buffer size in bytes
@RETURN bitmap_t: if succeeds return bitmap resource handle, fails return NULL.
*/
EXP_API dword_t	save_bitmap_to_bytes(visual_t rdc, bitmap_t rb, byte_t* pb, dword_t max);

/*
@FUNCTION get_bitmap_bytes: get bitmap dib bytes.
@INPUT bitmap_t bmp: memory resource handle.
@RETURN dword_t: if succeeds return dib bytes, fails return zero.
*/
EXP_API dword_t	get_bitmap_bytes(bitmap_t bmp);

/*
@FUNCTION create_code128_bitmap: create code128 bar bitmap.
@INPUT visual_t rdc: device context resource handle.
@INPUT int w: the bitmap width in points.
@INPUT int w: the bitmap height in points.
@INPUT const tchar_t* text: the string data.
@RETURN bitmap_t: if succeeds return memory resource handle, fails return NULL.
*/
EXP_API bitmap_t create_code128_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const tchar_t* text);

/*
@FUNCTION create_pdf417_bitmap: create pdf417 bar bitmap.
@INPUT visual_t rdc: device context resource handle.
@INPUT int w: the bitmap width in points.
@INPUT int w: the bitmap height in points.
@INPUT const tchar_t* text: the string data.
@RETURN bitmap_t: if succeeds return memory resource handle, fails return NULL.
*/
EXP_API bitmap_t create_pdf417_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const tchar_t* text);

/*
@FUNCTION create_qrcode_bitmap: create qrcode bar bitmap.
@INPUT visual_t rdc: device context resource handle.
@INPUT int w: the bitmap width in points.
@INPUT int w: the bitmap height in points.
@INPUT const tchar_t* text: the string data.
@RETURN bitmap_t: if succeeds return memory resource handle, fails return NULL.
*/
EXP_API bitmap_t create_qrcode_bitmap(visual_t rdc, const xcolor_t* pxc_front, const xcolor_t* pxc_back, const tchar_t* text);

/*
@FUNCTION load_bitmap_from_file: create bitmap from image file.
@INPUT visual_t rdc: device context resource handle.
@INPUT const tchar_t* fname: the image file name.
@RETURN bitmap_t: if succeeds return memory resource handle, fails return NULL.
*/
EXP_API bitmap_t load_bitmap_from_file(visual_t rdc, const tchar_t* fname);

/*
@FUNCTION save_bitmap_to_file: save bitmap to image file.
@INPUT visual_t rdc: device context resource handle.
@INPUT bitmap_t rb: bitmap resource handle.
@INPUT const tchar_t* type: the image type, it can be GDI_ATTR_IMAGE_TYPE_JPG, GDI_ATTR_IMAGE_TYPE_PNG, GDI_ATTR_IMAGE_TYPE_BMP.
@INPUT const tchar_t* fname: the image file name.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t save_bitmap_to_file(visual_t rdc, bitmap_t rb, const tchar_t* type, const tchar_t* fname);

/*
@FUNCTION load_bitmap_from_ximage: create bitmap from ximage struct.
@INPUT visual_t rdc: device context resource handle.
@INPUT const ximage_t* p: the image struct.
@INPUT int cx: the bitmap width in points.
@INPUT int cy: the bitmap height in points.
@RETURN bitmap_t: if succeeds return memory resource handle, fails return NULL.
*/
EXP_API bitmap_t load_bitmap_from_ximage(visual_t rdc, const ximage_t* p, int cx, int cy);

/*
@FUNCTION save_bitmap_to_ximage: save bitmap to ximage struct.
@INPUT visual_t rdc: device context resource handle.
@INPUT bitmap_t bmp: bitmap resource handle.
@INPUT ximage_t* pmi: the ximage struct for saving data.
@RETURN bool_t: if succeeds return nonzero, fails return zero.
*/
EXP_API bool_t save_bitmap_to_ximage(visual_t rdc, bitmap_t bmp, ximage_t* pmi);

#ifdef XDU_SUPPORT_SHELL
/*
@FUNCTION load_bitmap_from_thumb: create thumb bitmap from file.
@INPUT visual_t rdc: device context resource handle.
@INPUT const tchar_t* fname: the file path name for loading thumb bitmap.
@RETURN bitmap_t: if succeeds return memory resource handle, fails return NULL.
*/
EXP_API bitmap_t load_bitmap_from_thumb(visual_t rdc, const tchar_t* fname);

/*
@FUNCTION load_bitmap_from_thumb: create thumb bitmap from icon.
@INPUT visual_t rdc: device context resource handle.
@INPUT const tchar_t* iname: the icon name.
@RETURN bitmap_t: if succeeds return memory resource handle, fails return NULL.
*/
EXP_API bitmap_t load_bitmap_from_icon(visual_t rdc, const tchar_t* iname);
#endif

#ifdef	__cplusplus
}
#endif

#endif /*XDU_SUPPORT_CONTEXT_BITMAP*/

#endif /*IMPBITMAP_H*/