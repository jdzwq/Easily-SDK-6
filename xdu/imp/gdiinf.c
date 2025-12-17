/***********************************************************************
	Easily xdl v5.5

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdi document

	@module	impgdi.c | implement file

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

#include "gdiinf.h"

#include "../xduimp.h"

#if defined(XDU_SUPPORT_CONTEXT)

void get_canvas_interface(canvas_t canv, drawing_interface* pif)
{
	pif->ctx = (void*)canv;

	pif->pf_get_measure = (PF_GET_MEASURE)get_canvas_measure;

	pif->pf_rect_mm_to_pt = (PF_RECT_MM_TO_PT)rect_mm_to_pt;
	pif->pf_rect_pt_to_mm = (PF_RECT_PT_TO_MM)rect_pt_to_mm;
	pif->pf_size_mm_to_pt = (PF_SIZE_MM_TO_PT)size_mm_to_pt;
	pif->pf_size_pt_to_mm = (PF_SIZE_PT_TO_MM)size_pt_to_mm;
	pif->pf_point_mm_to_pt = (PF_POINT_MM_TO_PT)point_mm_to_pt;
	pif->pf_point_pt_to_mm = (PF_POINT_PT_TO_MM)point_pt_to_mm;

	pif->pf_draw_line = (PF_DRAW_LINE)draw_line;
	pif->pf_draw_bezier = (PF_DRAW_BEZIER)draw_bezier;
	pif->pf_draw_curve = (PF_DRAW_CURVE)draw_curve;
	pif->pf_draw_arc = (PF_DRAW_ARC)draw_arc;
	pif->pf_draw_polyline = (PF_DRAW_POLYLINE)draw_polyline;

	pif->pf_draw_sector = (PF_DRAW_SECTOR)draw_sector;
	pif->pf_draw_pie = (PF_DRAW_PIE)draw_pie;
	pif->pf_draw_triangle = (PF_DRAW_TRIANGLE)draw_triangle;
	pif->pf_draw_rect = (PF_DRAW_RECT)draw_rect;
	pif->pf_draw_round = (PF_DRAW_ROUND)draw_round;
	pif->pf_draw_ellipse = (PF_DRAW_ELLIPSE)draw_ellipse;
	pif->pf_draw_polygon = (PF_DRAW_POLYGON)draw_polygon;
	pif->pf_draw_equilagon = (PF_DRAW_EQUILAGON)draw_equilagon;
	pif->pf_draw_path = (PF_DRAW_PATH)draw_path;

	pif->pf_set_xfont = (PF_SET_XFONT)set_xfont;
	pif->pf_get_xfont = (PF_GET_XFONT)get_xfont;
	pif->pf_font_size = (PF_FONT_SIZE)font_size;
	pif->pf_text_size = (PF_TEXT_SIZE)text_size;
	pif->pf_text_rect = (PF_TEXT_RECT)text_rect;
	pif->pf_draw_text = (PF_DRAW_TEXT)draw_text;
	pif->pf_text_out = (PF_TEXT_OUT)text_out;
	pif->pf_multi_line = (PF_MULTI_LINE)multi_line;

	pif->pf_color_out = (PF_COLOR_OUT)color_out;
	pif->pf_draw_image = (PF_DRAW_IMAGE)draw_image;

	pif->pf_get_visual_interface = (PF_GET_INTERFACE)get_visual_interface;
	pif->pf_get_visual_handle = (PF_GET_VISUAL)get_canvas_visual;
}

void get_visual_interface(visual_t visu, drawing_interface* piv)
{
	piv->ctx = (void*)visu;

	piv->pf_get_measure = (PF_GET_MEASURE)get_visual_measure;

	piv->pf_rect_mm_to_pt = (PF_RECT_MM_TO_PT)rect_mm_to_pt;
	piv->pf_rect_pt_to_mm = (PF_RECT_PT_TO_MM)rect_pt_to_mm;
	piv->pf_size_mm_to_pt = (PF_SIZE_MM_TO_PT)size_mm_to_pt;
	piv->pf_size_pt_to_mm = (PF_SIZE_PT_TO_MM)size_pt_to_mm;
	piv->pf_point_mm_to_pt = (PF_POINT_MM_TO_PT)point_mm_to_pt;
	piv->pf_point_pt_to_mm = (PF_POINT_PT_TO_MM)point_pt_to_mm;

	piv->pf_draw_line = (PF_DRAW_LINE)draw_line_raw;
	piv->pf_draw_bezier = (PF_DRAW_BEZIER)draw_bezier_raw;
	piv->pf_draw_curve = (PF_DRAW_CURVE)draw_curve_raw;
	piv->pf_draw_arc = (PF_DRAW_ARC)draw_arc_raw;
	piv->pf_draw_polyline = (PF_DRAW_POLYLINE)draw_polyline_raw;

	piv->pf_draw_sector = (PF_DRAW_SECTOR)draw_sector_raw;
	piv->pf_draw_pie = (PF_DRAW_PIE)draw_pie_raw;
	piv->pf_draw_triangle = (PF_DRAW_TRIANGLE)draw_triangle_raw;
	piv->pf_draw_rect = (PF_DRAW_RECT)draw_rect_raw;
	piv->pf_draw_round = (PF_DRAW_ROUND)draw_round_raw;
	piv->pf_draw_ellipse = (PF_DRAW_ELLIPSE)draw_ellipse_raw;
	piv->pf_draw_polygon = (PF_DRAW_POLYGON)draw_polygon_raw;
	piv->pf_draw_equilagon = (PF_DRAW_EQUILAGON)draw_equilagon_raw;
	piv->pf_draw_path = (PF_DRAW_PATH)draw_path_raw;

	piv->pf_set_xfont = (PF_SET_XFONT)set_xfont_raw;
	piv->pf_get_xfont = (PF_GET_XFONT)get_xfont_raw;
	piv->pf_font_size = (PF_FONT_SIZE)font_size_raw;
	piv->pf_text_size = (PF_TEXT_SIZE)text_size_raw;
	piv->pf_text_rect = (PF_TEXT_RECT)text_rect_raw;
	piv->pf_draw_text = (PF_DRAW_TEXT)draw_text_raw;
	piv->pf_text_out = (PF_TEXT_OUT)text_out_raw;
	piv->pf_multi_line = (PF_MULTI_LINE)multi_line_raw;

	piv->pf_color_out = (PF_COLOR_OUT)color_out_raw;
	piv->pf_draw_image = (PF_DRAW_IMAGE)draw_image_raw;
	piv->pf_draw_icon = (PF_DRAW_ICON)draw_icon_raw;
	piv->pf_draw_thumb = (PF_DRAW_THUMB)draw_thumb_raw;
	piv->pf_draw_bitmap = (PF_DRAW_BITMAP)draw_bitmap_raw;

	piv->pf_gradient_rect = (PF_GRADIENT_RECT)gradient_rect_raw;
	piv->pf_alphablend_rect = (PF_ALPHABLEND_RECT)alphablend_rect_raw;
	piv->pf_invert_rect = (PF_INVERT_RECT)invert_rect_raw;

	piv->pf_exclude_rect = (PF_EXCLUDE_RECT)exclude_rect_raw;
	piv->pf_inclip_rect = (PF_INCLIP_RECT)inclip_rect_raw;
}

void get_visual_measure(visual_t view, measure_interface* pim)
{
	pim->ctx = (void*)view;

	pim->pf_set_xfont = (PF_SET_XFONT)set_xfont_raw;
	pim->pf_get_xfont = (PF_GET_XFONT)get_xfont_raw;
	pim->pf_measure_font = (PF_MEASURE_FONT)font_size_raw;
	pim->pf_measure_size = (PF_MEASURE_SIZE)text_size_raw;
	pim->pf_measure_rect = (PF_MEASURE_RECT)text_rect_raw;
}

void get_canvas_measure(canvas_t canv, measure_interface* pim)
{
	pim->ctx = (void*)canv;

	pim->pf_set_xfont = (PF_SET_XFONT)set_xfont;
	pim->pf_get_xfont = (PF_GET_XFONT)get_xfont;
	pim->pf_measure_font = (PF_MEASURE_FONT)font_size;
	pim->pf_measure_size = (PF_MEASURE_SIZE)text_size;
	pim->pf_measure_rect = (PF_MEASURE_RECT)text_rect;
}

#endif /*XDU_SUPPORT_CONTEXT*/
