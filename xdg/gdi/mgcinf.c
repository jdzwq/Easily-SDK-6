/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc mgc interface document

	@module	mgcinf.c | implement file

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

#include "mgcinf.h"

#include "../xdgmgc.h"

static if_drawing_t visual_drawing = {
	.pf_get_measure = (PF_GET_MEASURE)mgc_get_visual_measure,

	.pf_draw_line = (PF_DRAW_LINE)mgc_draw_line_raw,
	.pf_draw_bezier = (PF_DRAW_BEZIER)mgc_draw_bezier_raw,
	.pf_draw_curve = (PF_DRAW_CURVE)mgc_draw_curve_raw,
	.pf_draw_arc = (PF_DRAW_ARC)mgc_draw_arc_raw,
	.pf_draw_polyline = (PF_DRAW_POLYLINE)mgc_draw_polyline_raw,

	.pf_draw_sector = (PF_DRAW_SECTOR)mgc_draw_sector_raw,
	.pf_draw_pie = (PF_DRAW_PIE)mgc_draw_pie_raw,
	.pf_draw_triangle = (PF_DRAW_TRIANGLE)mgc_draw_triangle_raw,
	.pf_draw_rect = (PF_DRAW_RECT)mgc_draw_rect_raw,
	.pf_draw_round = (PF_DRAW_ROUND)mgc_draw_round_raw,
	.pf_draw_ellipse = (PF_DRAW_ELLIPSE)mgc_draw_ellipse_raw,
	.pf_draw_polygon = (PF_DRAW_POLYGON)mgc_draw_polygon_raw,
	.pf_draw_equilagon = (PF_DRAW_EQUILAGON)mgc_draw_equilagon_raw,
	.pf_draw_path = (PF_DRAW_PATH)mgc_draw_path_raw,

	.pf_set_xfont = (PF_SET_XFONT)mgc_set_xfont_raw,
	.pf_get_xfont = (PF_GET_XFONT)mgc_get_xfont_raw,
	.pf_font_size = (PF_FONT_SIZE)mgc_font_size_raw,
	.pf_text_size = (PF_TEXT_SIZE)mgc_text_size_raw,
	.pf_text_rect = (PF_TEXT_RECT)mgc_text_rect_raw,
	.pf_draw_text = (PF_DRAW_TEXT)mgc_draw_text_raw,
	.pf_text_out = (PF_TEXT_OUT)mgc_text_out_raw,
	.pf_multi_line = (PF_MULTI_LINE)mgc_multi_line_raw,

	.pf_color_out = (PF_COLOR_OUT)mgc_color_out_raw,
	.pf_draw_image = (PF_DRAW_IMAGE)mgc_draw_image_raw
};

static if_drawing_t canvas_drawing = {
	.pf_get_measure = (PF_GET_MEASURE)mgc_get_canvas_measure,

	.pf_draw_line = (PF_DRAW_LINE)mgc_draw_line,
	.pf_draw_bezier = (PF_DRAW_BEZIER)mgc_draw_bezier,
	.pf_draw_curve = (PF_DRAW_CURVE)mgc_draw_curve,
	.pf_draw_arc = (PF_DRAW_ARC)mgc_draw_arc,
	.pf_draw_polyline = (PF_DRAW_POLYLINE)mgc_draw_polyline,

	.pf_draw_sector = (PF_DRAW_SECTOR)mgc_draw_sector,
	.pf_draw_pie = (PF_DRAW_PIE)mgc_draw_pie,
	.pf_draw_triangle = (PF_DRAW_TRIANGLE)mgc_draw_triangle,
	.pf_draw_rect = (PF_DRAW_RECT)mgc_draw_rect,
	.pf_draw_round = (PF_DRAW_ROUND)mgc_draw_round,
	.pf_draw_ellipse = (PF_DRAW_ELLIPSE)mgc_draw_ellipse,
	.pf_draw_polygon = (PF_DRAW_POLYGON)mgc_draw_polygon,
	.pf_draw_equilagon = (PF_DRAW_EQUILAGON)mgc_draw_equilagon,
	.pf_draw_path = (PF_DRAW_PATH)mgc_draw_path,

	.pf_set_xfont = (PF_SET_XFONT)mgc_set_xfont,
	.pf_get_xfont = (PF_GET_XFONT)mgc_get_xfont,
	.pf_font_size = (PF_FONT_SIZE)mgc_font_size,
	.pf_text_size = (PF_TEXT_SIZE)mgc_text_size,
	.pf_text_rect = (PF_TEXT_RECT)mgc_text_rect,
	.pf_draw_text = (PF_DRAW_TEXT)mgc_draw_text,
	.pf_text_out = (PF_TEXT_OUT)mgc_text_out,
	.pf_multi_line = (PF_MULTI_LINE)mgc_multi_line,

	.pf_color_out = (PF_COLOR_OUT)mgc_color_out,
	.pf_draw_image = (PF_DRAW_IMAGE)mgc_draw_image,

	.pf_rect_mm_to_pt = (PF_RECT_MM_TO_PT)mgc_rect_mm_to_pt,
	.pf_rect_pt_to_mm = (PF_RECT_PT_TO_MM)mgc_rect_pt_to_mm,
	.pf_size_mm_to_pt = (PF_SIZE_MM_TO_PT)mgc_size_mm_to_pt,
	.pf_size_pt_to_mm = (PF_SIZE_PT_TO_MM)mgc_size_pt_to_mm,
	.pf_point_mm_to_pt = (PF_POINT_MM_TO_PT)mgc_point_mm_to_pt,
	.pf_point_pt_to_mm = (PF_POINT_PT_TO_MM)mgc_point_pt_to_mm,

	.pf_get_visual_interface = (PF_GET_INTERFACE)mgc_get_visual_interface,
	.pf_get_visual_handle = (PF_GET_VISUAL)mgc_get_canvas_visual
};

void mgc_get_visual_interface(visual_t visual, drawing_interface* pvi)
{
	pvi->ctx = (void*)visual;
	pvi->drw = &visual_drawing;
}

void mgc_get_canvas_interface(canvas_t canv, drawing_interface* pci)
{
	pci->ctx = (void*)canv;
	pci->drw = &canvas_drawing;
}

/***********************************************************************/

static if_measure_t visual_measure = {
	.pf_measure_font = (PF_MEASURE_FONT)mgc_measure_font_raw,
	.pf_measure_size = (PF_MEASURE_SIZE)mgc_measure_size_raw,
	.pf_measure_rect = (PF_MEASURE_RECT)mgc_measure_rect_raw
};

static if_measure_t canvas_measure = {
	.pf_measure_font = (PF_MEASURE_FONT)mgc_measure_font,
	.pf_measure_size = (PF_MEASURE_SIZE)mgc_measure_size,
	.pf_measure_rect = (PF_MEASURE_RECT)mgc_measure_rect
};

void mgc_get_visual_measure(visual_t view, measure_interface* pmv)
{
	pmv->ctx = (void*)view;
	pmv->mea = &visual_measure;
}

void mgc_get_canvas_measure(canvas_t canv, measure_interface* pmc)
{
	pmc->ctx = (void*)canv;
	pmc->mea = &canvas_measure;
}
