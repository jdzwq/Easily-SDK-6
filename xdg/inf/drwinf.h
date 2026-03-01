/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc svg interface document

	@module	gdiinf.h | interface file

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

#ifndef _DRWINF_H
#define _DRWINF_H

typedef void(*PF_SET_XFONT)(void*, const xfont_t*); 
typedef void(*PF_GET_XFONT)(void*, xfont_t*); 
typedef void(*PF_MEASURE_FONT)(void*, const xsize_t*);
typedef void(*PF_MEASURE_RECT)(void*, const xface_t*, const tchar_t*, int, xrect_t* pxr);
typedef void(*PF_MEASURE_SIZE)(void*, const tchar_t*, int, xsize_t* pxs);

typedef struct _measure_interface{
	void* ctx; //visual_t or canvas_t

	PF_SET_XFONT		pf_set_xfont;
	PF_GET_XFONT		pf_get_xfont;
	PF_MEASURE_FONT		pf_measure_font;
	PF_MEASURE_RECT		pf_measure_rect;
	PF_MEASURE_SIZE		pf_measure_size;

	xrect_t rect;
}measure_interface;


typedef void(*PF_RECT_PT_TO_MM)(void*, xrect_t*);
typedef void(*PF_RECT_MM_TO_PT)(void*, xrect_t*);
typedef void(*PF_SIZE_PT_TO_MM)(void*, xsize_t*);
typedef void(*PF_SIZE_MM_TO_PT)(void*, xsize_t*);
typedef void(*PF_POINT_PT_TO_MM)(void*, xpoint_t*);
typedef void(*PF_POINT_MM_TO_PT)(void*, xpoint_t*);

typedef void(*PF_GET_MEASURE)(void*, measure_interface*);

typedef void(*PF_DRAW_LINE)(void*, const xpen_t*, const xpoint_t*, const xpoint_t*);
typedef void(*PF_DRAW_BEZIER)(void*, const xpen_t*, const xpoint_t*, const xpoint_t*, const xpoint_t*, const xpoint_t*);
typedef void(*PF_DRAW_CURVE)(void*, const xpen_t*, const xpoint_t*, int);
typedef void(*PF_DRAW_ARC)(void*, const xpen_t*, const xpoint_t*, const xpoint_t*, const xsize_t*, bool_t, bool_t);
typedef void(*PF_DRAW_POLYLINE)(void*, const xpen_t*, const xpoint_t*, int);

typedef void(*PF_DRAW_RECT)(void*, const xpen_t*, const xbrush_t*, const xrect_t*);
typedef void(*PF_DRAW_ROUND)(void*, const xpen_t*, const xbrush_t*, const xrect_t*, const xsize_t*);
typedef void(*PF_DRAW_ELLIPSE)(void*, const xpen_t*, const xbrush_t*, const xrect_t*);
typedef void(*PF_DRAW_PIE)(void*, const xpen_t*, const xbrush_t*, const xrect_t*, double, double);
typedef void(*PF_DRAW_SECTOR)(void*, const xpen_t*, const xbrush_t*, const xpoint_t*, const xspan_t*, const xspan_t*, double, double);
typedef void(*PF_DRAW_TRIANGLE)(void*, const xpen_t*, const xbrush_t*, const xrect_t*, const tchar_t*);
typedef void(*PF_DRAW_POLYGON)(void*, const xpen_t*, const xbrush_t*, const xpoint_t*, int);
typedef void(*PF_DRAW_EQUILAGON)(void*, const xpen_t*, const xbrush_t*, const xpoint_t*, const xspan_t*, int);
typedef void(*PF_DRAW_PATH)(void*, const xpen_t*, const xbrush_t*, const tchar_t*, const xpoint_t*, int n);

typedef void(*PF_TEXT_RECT)(void*, const xface_t*, const tchar_t*, int, xrect_t* pxr);
typedef void(*PF_TEXT_SIZE)(void*, const tchar_t*, int, xsize_t* pps);
typedef void(*PF_FONT_SIZE)(void*, xsize_t* pps);
typedef void(*PF_DRAW_TEXT)(void*, const xface_t*, const xrect_t*, const tchar_t*, int);
typedef void(*PF_TEXT_OUT)(void*, const xface_t*, const xpoint_t*, const tchar_t*, int);
typedef void(*PF_MULTI_LINE)(void*, const xface_t*, const xpen_t*, const xrect_t*);

typedef void(*PF_COLOR_OUT)(void*, const xrect_t*, bool_t horz, const tchar_t*, int);
typedef void(*PF_DRAW_IMAGE)(void*, const ximage_t*, const xrect_t*);
typedef void(*PF_DRAW_ICON)(void*, const tchar_t*, const xrect_t*);
typedef void(*PF_DRAW_THUMB)(void*, const tchar_t*, const xrect_t*);
typedef void(*PF_DRAW_BITMAP)(void*, bitmap_t, const xpoint_t*);

typedef void(*PF_GRADIENT_RECT)(void*, const xcolor_t*, const xcolor_t*, const tchar_t*, const xrect_t*);
typedef void(*PF_ALPHABLEND_RECT)(void*, const xcolor_t*, const xrect_t*, int);
typedef void(*PF_INVERT_RECT)(visual_t, const xrect_t*);
typedef void(*PF_EXCLUDE_RECT)(visual_t, const xrect_t*);
typedef void(*PF_INCLIP_RECT)(visual_t, const xrect_t*);


typedef struct _drawing_interface* drawing_interface_ptr;

typedef visual_t(*PF_GET_VISUAL)(void*);
typedef void(*PF_GET_INTERFACE)(void*, drawing_interface_ptr);

typedef struct _drawing_interface{
	int tag;
	void* ctx;
	const color_mod_t* pclrs;

	PF_GET_MEASURE		pf_get_measure;

	PF_DRAW_LINE		pf_draw_line;
	PF_DRAW_BEZIER		pf_draw_bezier;
	PF_DRAW_CURVE		pf_draw_curve;
	PF_DRAW_ARC			pf_draw_arc;
	PF_DRAW_POLYLINE	pf_draw_polyline;

	PF_DRAW_RECT		pf_draw_rect;
	PF_DRAW_TRIANGLE	pf_draw_triangle;
	PF_DRAW_ROUND		pf_draw_round;
	PF_DRAW_ELLIPSE		pf_draw_ellipse;
	PF_DRAW_PIE			pf_draw_pie;
	PF_DRAW_SECTOR		pf_draw_sector;
	PF_DRAW_POLYGON		pf_draw_polygon;
	PF_DRAW_EQUILAGON	pf_draw_equilagon;
	PF_DRAW_PATH		pf_draw_path;

	PF_SET_XFONT		pf_set_xfont;
	PF_GET_XFONT		pf_get_xfont;
	PF_FONT_SIZE		pf_font_size;
	PF_TEXT_RECT		pf_text_rect;
	PF_TEXT_SIZE		pf_text_size;
	PF_DRAW_TEXT		pf_draw_text;
	PF_TEXT_OUT			pf_text_out;
	PF_MULTI_LINE		pf_multi_line;

	PF_COLOR_OUT		pf_color_out;
	PF_DRAW_ICON		pf_draw_icon;
	PF_DRAW_THUMB		pf_draw_thumb;
	PF_DRAW_IMAGE		pf_draw_image;
	PF_DRAW_BITMAP		pf_draw_bitmap;

	//the visual only
	PF_GRADIENT_RECT	pf_gradient_rect;
	PF_ALPHABLEND_RECT	pf_alphablend_rect;
	PF_INVERT_RECT		pf_invert_rect;
	PF_EXCLUDE_RECT		pf_exclude_rect;
	PF_INCLIP_RECT		pf_inclip_rect;

	// the canvas only
	PF_RECT_PT_TO_MM	pf_rect_pt_to_mm;
	PF_RECT_MM_TO_PT	pf_rect_mm_to_pt;
	PF_SIZE_PT_TO_MM	pf_size_pt_to_mm;
	PF_SIZE_MM_TO_PT	pf_size_mm_to_pt;
	PF_POINT_PT_TO_MM	pf_point_pt_to_mm;
	PF_POINT_MM_TO_PT	pf_point_mm_to_pt;

	PF_GET_MEASURE		pf_get_visual_measure;
	PF_GET_INTERFACE	pf_get_visual_interface;
	PF_GET_VISUAL		pf_get_visual_handle;

	xrect_t rect;
}drawing_interface;


#endif /*_DRWINF_H*/