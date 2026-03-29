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

#include "wgcinf.h"

#include "../xduimp.h"

#if defined(XDU_SUPPORT_CONTEXT)


static if_drawing_t visual_drawing = {
	.pf_get_measure = (PF_GET_MEASURE)get_visual_measure,

	.pf_draw_line = (PF_DRAW_LINE)draw_line_raw,
	.pf_draw_bezier = (PF_DRAW_BEZIER)draw_bezier_raw,
	.pf_draw_curve = (PF_DRAW_CURVE)draw_curve_raw,
	.pf_draw_arc = (PF_DRAW_ARC)draw_arc_raw,
	.pf_draw_polyline = (PF_DRAW_POLYLINE)draw_polyline_raw,

	.pf_draw_sector = (PF_DRAW_SECTOR)draw_sector_raw,
	.pf_draw_pie = (PF_DRAW_PIE)draw_pie_raw,
	.pf_draw_triangle = (PF_DRAW_TRIANGLE)draw_triangle_raw,
	.pf_draw_rect = (PF_DRAW_RECT)draw_rect_raw,
	.pf_draw_round = (PF_DRAW_ROUND)draw_round_raw,
	.pf_draw_ellipse = (PF_DRAW_ELLIPSE)draw_ellipse_raw,
	.pf_draw_polygon = (PF_DRAW_POLYGON)draw_polygon_raw,
	.pf_draw_equilagon = (PF_DRAW_EQUILAGON)draw_equilagon_raw,
	.pf_draw_path = (PF_DRAW_PATH)draw_path_raw,

	.pf_set_xfont = (PF_SET_XFONT)set_xfont_raw,
	.pf_get_xfont = (PF_GET_XFONT)get_xfont_raw,
	.pf_font_size = (PF_FONT_SIZE)font_size_raw,
	.pf_text_size = (PF_TEXT_SIZE)text_size_raw,
	.pf_text_rect = (PF_TEXT_RECT)text_rect_raw,
	.pf_draw_text = (PF_DRAW_TEXT)draw_text_raw,
	.pf_text_out = (PF_TEXT_OUT)text_out_raw,
	.pf_multi_line = (PF_MULTI_LINE)multi_line_raw,

	.pf_color_out = (PF_COLOR_OUT)color_out_raw,
	.pf_draw_image = (PF_DRAW_IMAGE)draw_image_raw,
	.pf_draw_icon = (PF_DRAW_ICON)draw_icon_raw,
	.pf_draw_thumb = (PF_DRAW_THUMB)draw_thumb_raw,
	.pf_draw_bitmap = (PF_DRAW_BITMAP)draw_bitmap_raw,

	.pf_gradient_rect = (PF_GRADIENT_RECT)gradient_rect_raw,
	.pf_alphablend_rect = (PF_ALPHABLEND_RECT)alphablend_rect_raw,
	.pf_invert_rect = (PF_INVERT_RECT)invert_rect_raw,
	.pf_exclude_rect = (PF_EXCLUDE_RECT)exclude_rect_raw,
	.pf_inclip_rect = (PF_INCLIP_RECT)inclip_rect_raw
};

static if_drawing_t canvas_drawing = {
	.pf_get_measure = (PF_GET_MEASURE)get_canvas_measure,

	.pf_draw_line = (PF_DRAW_LINE)draw_line,
	.pf_draw_bezier = (PF_DRAW_BEZIER)draw_bezier,
	.pf_draw_curve = (PF_DRAW_CURVE)draw_curve,
	.pf_draw_arc = (PF_DRAW_ARC)draw_arc,
	.pf_draw_polyline = (PF_DRAW_POLYLINE)draw_polyline,

	.pf_draw_sector = (PF_DRAW_SECTOR)draw_sector,
	.pf_draw_pie = (PF_DRAW_PIE)draw_pie,
	.pf_draw_triangle = (PF_DRAW_TRIANGLE)draw_triangle,
	.pf_draw_rect = (PF_DRAW_RECT)draw_rect,
	.pf_draw_round = (PF_DRAW_ROUND)draw_round,
	.pf_draw_ellipse = (PF_DRAW_ELLIPSE)draw_ellipse,
	.pf_draw_polygon = (PF_DRAW_POLYGON)draw_polygon,
	.pf_draw_equilagon = (PF_DRAW_EQUILAGON)draw_equilagon,
	.pf_draw_path = (PF_DRAW_PATH)draw_path,

	.pf_set_xfont = (PF_SET_XFONT)set_xfont,
	.pf_get_xfont = (PF_GET_XFONT)get_xfont,
	.pf_font_size = (PF_FONT_SIZE)font_size,
	.pf_text_size = (PF_TEXT_SIZE)text_size,
	.pf_text_rect = (PF_TEXT_RECT)text_rect,
	.pf_draw_text = (PF_DRAW_TEXT)draw_text,
	.pf_text_out = (PF_TEXT_OUT)text_out,
	.pf_multi_line = (PF_MULTI_LINE)multi_line,

	.pf_color_out = (PF_COLOR_OUT)color_out,
	.pf_draw_image = (PF_DRAW_IMAGE)draw_image,

	.pf_rect_mm_to_pt = (PF_RECT_MM_TO_PT)rect_mm_to_pt,
	.pf_rect_pt_to_mm = (PF_RECT_PT_TO_MM)rect_pt_to_mm,
	.pf_size_mm_to_pt = (PF_SIZE_MM_TO_PT)size_mm_to_pt,
	.pf_size_pt_to_mm = (PF_SIZE_PT_TO_MM)size_pt_to_mm,
	.pf_point_mm_to_pt = (PF_POINT_MM_TO_PT)point_mm_to_pt,
	.pf_point_pt_to_mm = (PF_POINT_PT_TO_MM)point_pt_to_mm,

	.pf_get_visual_measure = (PF_GET_MEASURE)get_visual_measure,
	.pf_get_visual_interface = (PF_GET_INTERFACE)get_visual_interface,
	.pf_get_visual_handle = (PF_GET_VISUAL)get_canvas_visual
};

void get_visual_interface(visual_t visu, drawing_interface* pvi)
{
	pvi->ctx = (void*)visu;
	pvi->drw = &visual_drawing;
}

void get_canvas_interface(canvas_t canv, drawing_interface* pci)
{
	pci->ctx = (void*)canv;
	pci->drw = &canvas_drawing;
}

/***********************************************************************/

static if_measure_t visual_measure = {
	.pf_measure_font = (PF_MEASURE_FONT)measure_font_raw,
	.pf_measure_size = (PF_MEASURE_SIZE)measure_size_raw,
	.pf_measure_rect = (PF_MEASURE_RECT)measure_rect_raw
};

static if_measure_t canvas_measure = {
	.pf_measure_font = (PF_MEASURE_FONT)measure_font,
	.pf_measure_size = (PF_MEASURE_SIZE)measure_size,
	.pf_measure_rect = (PF_MEASURE_RECT)measure_rect
};

void get_visual_measure(visual_t view, measure_interface* pim)
{
	pim->ctx = (void*)view;
	pim->mea = &visual_measure;
}

void get_canvas_measure(canvas_t canv, measure_interface* pim)
{
	pim->ctx = (void*)canv;
	pim->mea = &canvas_measure;
}

#endif /*XDU_SUPPORT_CONTEXT*/
