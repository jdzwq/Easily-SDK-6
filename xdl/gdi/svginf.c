/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc svg interface document

	@module	svginf.c | implement file

	@devnote 张文权 2021.01 - 2021.12	v6.0
***********************************************************************/

/**********************************************************************
This program is free software : you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY, without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
LICENSE.GPL3 for more details.
***********************************************************************/

#include "svginf.h"

#include "../xdlsdi.h"
#include "../xdlview.h"

static if_drawing_t visual_drawing = {
	.pf_get_measure = (PF_GET_MEASURE)svg_get_visual_measure,

	.pf_draw_line = (PF_DRAW_LINE)svg_draw_line_raw,
	.pf_draw_bezier = (PF_DRAW_BEZIER)svg_draw_bezier_raw,
	.pf_draw_curve = (PF_DRAW_CURVE)svg_draw_curve_raw,
	.pf_draw_arc = (PF_DRAW_ARC)svg_draw_arc_raw,
	.pf_draw_polyline = (PF_DRAW_POLYLINE)svg_draw_polyline_raw,

	.pf_draw_sector = (PF_DRAW_SECTOR)svg_draw_sector_raw,
	.pf_draw_pie = (PF_DRAW_PIE)svg_draw_pie_raw,
	.pf_draw_triangle = (PF_DRAW_TRIANGLE)svg_draw_triangle_raw,
	.pf_draw_rect = (PF_DRAW_RECT)svg_draw_rect_raw,
	.pf_draw_round = (PF_DRAW_ROUND)svg_draw_round_raw,
	.pf_draw_ellipse = (PF_DRAW_ELLIPSE)svg_draw_ellipse_raw,
	.pf_draw_polygon = (PF_DRAW_POLYGON)svg_draw_polygon_raw,
	.pf_draw_equilagon = (PF_DRAW_EQUILAGON)svg_draw_equilagon_raw,
	.pf_draw_path = (PF_DRAW_PATH)svg_draw_path_raw,

	.pf_set_xfont = (PF_SET_XFONT)svg_set_xfont_raw,
	.pf_get_xfont = (PF_GET_XFONT)svg_get_xfont_raw,
	.pf_font_size = (PF_FONT_SIZE)svg_font_size_raw,
	.pf_text_size = (PF_TEXT_SIZE)svg_text_size_raw,
	.pf_text_rect = (PF_TEXT_RECT)svg_text_rect_raw,
	.pf_draw_text = (PF_DRAW_TEXT)svg_draw_text_raw,
	.pf_text_out = (PF_TEXT_OUT)svg_text_out_raw,
	.pf_multi_line = (PF_MULTI_LINE)svg_multi_line_raw,

	.pf_color_out = (PF_COLOR_OUT)svg_color_out_raw,
	.pf_draw_image = (PF_DRAW_IMAGE)svg_draw_image_raw
};

static if_drawing_t canvas_drawing = {
	.pf_get_measure = (PF_GET_MEASURE)svg_get_canvas_measure,

	.pf_draw_line = (PF_DRAW_LINE)svg_draw_line,
	.pf_draw_bezier = (PF_DRAW_BEZIER)svg_draw_bezier,
	.pf_draw_curve = (PF_DRAW_CURVE)svg_draw_curve,
	.pf_draw_arc = (PF_DRAW_ARC)svg_draw_arc,
	.pf_draw_polyline = (PF_DRAW_POLYLINE)svg_draw_polyline,

	.pf_draw_sector = (PF_DRAW_SECTOR)svg_draw_sector,
	.pf_draw_pie = (PF_DRAW_PIE)svg_draw_pie,
	.pf_draw_triangle = (PF_DRAW_TRIANGLE)svg_draw_triangle,
	.pf_draw_rect = (PF_DRAW_RECT)svg_draw_rect,
	.pf_draw_round = (PF_DRAW_ROUND)svg_draw_round,
	.pf_draw_ellipse = (PF_DRAW_ELLIPSE)svg_draw_ellipse,
	.pf_draw_polygon = (PF_DRAW_POLYGON)svg_draw_polygon,
	.pf_draw_equilagon = (PF_DRAW_EQUILAGON)svg_draw_equilagon,
	.pf_draw_path = (PF_DRAW_PATH)svg_draw_path,

	.pf_set_xfont = (PF_SET_XFONT)svg_set_xfont,
	.pf_get_xfont = (PF_GET_XFONT)svg_get_xfont,
	.pf_font_size = (PF_FONT_SIZE)svg_font_size,
	.pf_text_size = (PF_TEXT_SIZE)svg_text_size,
	.pf_text_rect = (PF_TEXT_RECT)svg_text_rect,
	.pf_draw_text = (PF_DRAW_TEXT)svg_draw_text,
	.pf_text_out = (PF_TEXT_OUT)svg_text_out,
	.pf_multi_line = (PF_MULTI_LINE)svg_multi_line,

	.pf_color_out = (PF_COLOR_OUT)svg_color_out,
	.pf_draw_image = (PF_DRAW_IMAGE)svg_draw_image,

	.pf_rect_mm_to_pt = (PF_RECT_MM_TO_PT)svg_rect_mm_to_pt,
	.pf_rect_pt_to_mm = (PF_RECT_PT_TO_MM)svg_rect_pt_to_mm,
	.pf_size_mm_to_pt = (PF_SIZE_MM_TO_PT)svg_size_mm_to_pt,
	.pf_size_pt_to_mm = (PF_SIZE_PT_TO_MM)svg_size_pt_to_mm,
	.pf_point_mm_to_pt = (PF_POINT_MM_TO_PT)svg_point_mm_to_pt,
	.pf_point_pt_to_mm = (PF_POINT_PT_TO_MM)svg_point_pt_to_mm,

	.pf_get_visual_interface = (PF_GET_INTERFACE)svg_get_visual_interface,
	.pf_get_visual_handle = (PF_GET_VISUAL)svg_get_canvas_visual
};

void svg_get_visual_interface(visual_t visual, drawing_interface* pvi)
{
	pvi->ctx = (void*)visual;
	pvi->drw = &visual_drawing;
}

void svg_get_canvas_interface(canvas_t canv, drawing_interface* pci)
{
	pci->ctx = (void*)canv;
	pci->drw = &canvas_drawing;
}

/***********************************************************************/

static if_measure_t visual_measure = {
	.pf_measure_font = (PF_MEASURE_FONT)svg_measure_font_raw,
	.pf_measure_size = (PF_MEASURE_SIZE)svg_measure_size_raw,
	.pf_measure_rect = (PF_MEASURE_RECT)svg_measure_rect_raw
};

static if_measure_t canvas_measure = {
	.pf_measure_font = (PF_MEASURE_FONT)svg_measure_font,
	.pf_measure_size = (PF_MEASURE_SIZE)svg_measure_size,
	.pf_measure_rect = (PF_MEASURE_RECT)svg_measure_rect
};

void svg_get_visual_measure(visual_t view, measure_interface* pmv)
{
	pmv->ctx = (void*)view,
	pmv->mea = &visual_measure;
}

void svg_get_canvas_measure(canvas_t canv, measure_interface* pmc)
{
	pmc->ctx = (void*)canv,
	pmc->mea = &canvas_measure;
}
