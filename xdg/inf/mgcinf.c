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

#include "../xdgobj.h"

void mgc_get_canvas_interface(canvas_t canv, drawing_interface* pif)
{
	pif->ctx = (void*)canv;

	pif->pf_get_measure = (PF_GET_MEASURE)mgc_get_canvas_measure;

	pif->pf_rect_mm_to_pt = (PF_RECT_MM_TO_PT)mgc_rect_mm_to_pt;
	pif->pf_rect_pt_to_mm = (PF_RECT_PT_TO_MM)mgc_rect_pt_to_mm;
	pif->pf_size_mm_to_pt = (PF_SIZE_MM_TO_PT)mgc_size_mm_to_pt;
	pif->pf_size_pt_to_mm = (PF_SIZE_PT_TO_MM)mgc_size_pt_to_mm;
	pif->pf_point_mm_to_pt = (PF_POINT_MM_TO_PT)mgc_point_mm_to_pt;
	pif->pf_point_pt_to_mm = (PF_POINT_PT_TO_MM)mgc_point_pt_to_mm;

	pif->pf_draw_line = (PF_DRAW_LINE)mgc_draw_line;
	pif->pf_draw_bezier = (PF_DRAW_BEZIER)mgc_draw_bezier;
	pif->pf_draw_curve = (PF_DRAW_CURVE)mgc_draw_curve;
	pif->pf_draw_arc = (PF_DRAW_ARC)mgc_draw_arc;
	pif->pf_draw_polyline = (PF_DRAW_POLYLINE)mgc_draw_polyline;

	pif->pf_draw_sector = (PF_DRAW_SECTOR)mgc_draw_sector;
	pif->pf_draw_pie = (PF_DRAW_PIE)mgc_draw_pie;
	pif->pf_draw_triangle = (PF_DRAW_TRIANGLE)mgc_draw_triangle;
	pif->pf_draw_rect = (PF_DRAW_RECT)mgc_draw_rect;
	pif->pf_draw_round = (PF_DRAW_ROUND)mgc_draw_round;
	pif->pf_draw_ellipse = (PF_DRAW_ELLIPSE)mgc_draw_ellipse;
	pif->pf_draw_polygon = (PF_DRAW_POLYGON)mgc_draw_polygon;
	pif->pf_draw_equilagon = (PF_DRAW_EQUILAGON)mgc_draw_equilagon;
	pif->pf_draw_path = (PF_DRAW_PATH)mgc_draw_path;

	pif->pf_font_size = (PF_FONT_SIZE)mgc_font_size;
	pif->pf_text_size = (PF_TEXT_SIZE)mgc_text_size;
	pif->pf_text_rect = (PF_TEXT_RECT)mgc_text_rect;
	pif->pf_draw_text = (PF_DRAW_TEXT)mgc_draw_text;
	pif->pf_text_out = (PF_TEXT_OUT)mgc_text_out;
	pif->pf_multi_line = (PF_MULTI_LINE)mgc_multi_line;

	pif->pf_color_out = (PF_COLOR_OUT)mgc_color_out;
	pif->pf_draw_image = (PF_DRAW_IMAGE)mgc_draw_image;

	pif->pf_get_visual_interface = (PF_GET_INTERFACE)mgc_get_visual_interface;
	pif->pf_get_visual_handle = (PF_GET_VISUAL)mgc_get_canvas_visual;

	parse_xcolor(&pif->mode.clr_bkg, GDI_ATTR_RGB_WHITE);
	parse_xcolor(&pif->mode.clr_frg, GDI_ATTR_RGB_GRAY);
	parse_xcolor(&pif->mode.clr_txt, GDI_ATTR_RGB_BLACK);
	parse_xcolor(&pif->mode.clr_msk, GDI_ATTR_RGB_WHITE);
	parse_xcolor(&pif->mode.clr_ico, GDI_ATTR_RGB_BLACK);
}

void mgc_get_visual_interface(visual_t visual, drawing_interface* pif)
{
	pif->ctx = (void*)visual;

	pif->pf_get_measure = (PF_GET_MEASURE)mgc_get_visual_measure;

	pif->pf_rect_mm_to_pt = (PF_RECT_MM_TO_PT)mgc_rect_mm_to_pt;
	pif->pf_rect_pt_to_mm = (PF_RECT_PT_TO_MM)mgc_rect_pt_to_mm;
	pif->pf_size_mm_to_pt = (PF_SIZE_MM_TO_PT)mgc_size_mm_to_pt;
	pif->pf_size_pt_to_mm = (PF_SIZE_PT_TO_MM)mgc_size_pt_to_mm;
	pif->pf_point_mm_to_pt = (PF_POINT_MM_TO_PT)mgc_point_mm_to_pt;
	pif->pf_point_pt_to_mm = (PF_POINT_PT_TO_MM)mgc_point_pt_to_mm;

	pif->pf_draw_line = (PF_DRAW_LINE)mgc_draw_line_raw;
	pif->pf_draw_bezier = (PF_DRAW_BEZIER)mgc_draw_bezier_raw;
	pif->pf_draw_curve = (PF_DRAW_CURVE)mgc_draw_curve_raw;
	pif->pf_draw_arc = (PF_DRAW_ARC)mgc_draw_arc_raw;
	pif->pf_draw_polyline = (PF_DRAW_POLYLINE)mgc_draw_polyline_raw;

	pif->pf_draw_sector = (PF_DRAW_SECTOR)mgc_draw_sector_raw;
	pif->pf_draw_pie = (PF_DRAW_PIE)mgc_draw_pie_raw;
	pif->pf_draw_triangle = (PF_DRAW_TRIANGLE)mgc_draw_triangle_raw;
	pif->pf_draw_rect = (PF_DRAW_RECT)mgc_draw_rect_raw;
	pif->pf_draw_round = (PF_DRAW_ROUND)mgc_draw_round_raw;
	pif->pf_draw_ellipse = (PF_DRAW_ELLIPSE)mgc_draw_ellipse_raw;
	pif->pf_draw_polygon = (PF_DRAW_POLYGON)mgc_draw_polygon_raw;
	pif->pf_draw_equilagon = (PF_DRAW_EQUILAGON)mgc_draw_equilagon_raw;
	pif->pf_draw_path = (PF_DRAW_PATH)mgc_draw_path_raw;

	pif->pf_font_size = (PF_FONT_SIZE)mgc_font_size_raw;
	pif->pf_text_size = (PF_TEXT_SIZE)mgc_text_size_raw;
	pif->pf_text_rect = (PF_TEXT_RECT)mgc_text_rect_raw;
	pif->pf_draw_text = (PF_DRAW_TEXT)mgc_draw_text_raw;
	pif->pf_text_out = (PF_TEXT_OUT)mgc_text_out_raw;
	pif->pf_multi_line = (PF_MULTI_LINE)mgc_multi_line_raw;

	pif->pf_color_out = (PF_COLOR_OUT)mgc_color_out_raw;
	pif->pf_draw_image = (PF_DRAW_IMAGE)mgc_draw_image_raw;
}

void mgc_get_visual_measure(visual_t view, measure_interface* pim)
{
	pim->ctx = (void*)view;

	pim->pf_measure_pixel = (PF_MEASURE_PIXEL)mgc_pixel_size_raw;
	pim->pf_measure_font = (PF_MEASURE_FONT)mgc_font_size_raw;
	pim->pf_measure_size = (PF_MEASURE_SIZE)mgc_text_size_raw;
	pim->pf_measure_rect = (PF_MEASURE_RECT)mgc_text_rect_raw;
}

void mgc_get_canvas_measure(canvas_t canv, measure_interface* pim)
{
	pim->ctx = (void*)canv;

	pim->pf_measure_pixel = (PF_MEASURE_PIXEL)mgc_pixel_size;
	pim->pf_measure_font = (PF_MEASURE_FONT)mgc_font_size;
	pim->pf_measure_size = (PF_MEASURE_SIZE)mgc_text_size;
	pim->pf_measure_rect = (PF_MEASURE_RECT)mgc_text_rect;
}
