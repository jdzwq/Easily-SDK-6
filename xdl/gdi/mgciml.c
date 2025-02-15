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

#include "mgciml.h"

#include "../xdlgdi.h"
#include "../xdlview.h"

#if defined(XDL_SUPPORT_MGC)

void mgc_get_canvas_interface(canvas_t canv, drawing_interface* pif)
{
	pif->ctx = (void*)canv;

	pif->pf_get_measure = mgc_get_canvas_measure;

	pif->pf_rect_tm_to_pt = mgc_rect_tm_to_pt;
	pif->pf_rect_pt_to_tm = mgc_rect_pt_to_tm;
	pif->pf_size_tm_to_pt = mgc_size_tm_to_pt;
	pif->pf_size_pt_to_tm = mgc_size_pt_to_tm;
	pif->pf_point_tm_to_pt = mgc_point_tm_to_pt;
	pif->pf_point_pt_to_tm = mgc_point_pt_to_tm;

	pif->pf_draw_line = mgc_draw_line;
	pif->pf_draw_bezier = mgc_draw_bezier;
	pif->pf_draw_curve = mgc_draw_curve;
	pif->pf_draw_arc = mgc_draw_arc;
	pif->pf_draw_polyline = mgc_draw_polyline;

	pif->pf_draw_sector = mgc_draw_sector;
	pif->pf_draw_pie = mgc_draw_pie;
	pif->pf_draw_triangle = mgc_draw_triangle;
	pif->pf_draw_rect = mgc_draw_rect;
	pif->pf_draw_round = mgc_draw_round;
	pif->pf_draw_ellipse = mgc_draw_ellipse;
	pif->pf_draw_polygon = mgc_draw_polygon;
	pif->pf_draw_equilagon = mgc_draw_equilagon;
	pif->pf_draw_path = mgc_draw_path;

	pif->pf_text_metric = mgc_text_metric;
	pif->pf_text_size = mgc_text_size;
	pif->pf_draw_text = mgc_draw_text;
	pif->pf_text_out = mgc_text_out;
	pif->pf_multi_line = mgc_multi_line;

	pif->pf_color_out = mgc_color_out;
	pif->pf_draw_image = mgc_draw_image;

	pif->pf_get_visual_interface = mgc_get_visual_interface;
	pif->pf_get_visual_handle = mgc_get_canvas_visual;

	parse_xcolor(&pif->mode.clr_bkg, GDI_ATTR_RGB_WHITE);
	parse_xcolor(&pif->mode.clr_frg, GDI_ATTR_RGB_GRAY);
	parse_xcolor(&pif->mode.clr_txt, GDI_ATTR_RGB_BLACK);
	parse_xcolor(&pif->mode.clr_msk, GDI_ATTR_RGB_WHITE);
	parse_xcolor(&pif->mode.clr_ico, GDI_ATTR_RGB_BLACK);
}

void mgc_get_visual_interface(visual_t visual, drawing_interface* pif)
{
	pif->ctx = (void*)visual;

	pif->pf_get_measure = mgc_get_visual_measure;

	pif->pf_draw_line = mgc_draw_line_raw;
	pif->pf_draw_bezier = mgc_draw_bezier_raw;
	pif->pf_draw_curve = mgc_draw_curve_raw;
	pif->pf_draw_arc = mgc_draw_arc_raw;
	pif->pf_draw_polyline = mgc_draw_polyline_raw;

	pif->pf_draw_rect = mgc_draw_rect_raw;
	pif->pf_draw_triangle = mgc_draw_triangle_raw;
	pif->pf_draw_round = mgc_draw_round_raw;
	pif->pf_draw_ellipse = mgc_draw_ellipse_raw;
	pif->pf_draw_pie = mgc_draw_pie_raw;
	pif->pf_draw_sector = mgc_draw_sector_raw;
	pif->pf_draw_polygon = mgc_draw_polygon_raw;
	pif->pf_draw_equilagon = mgc_draw_equilagon_raw;
	pif->pf_draw_path = mgc_draw_path_raw;

	pif->pf_text_metric = mgc_text_metric_raw;
	pif->pf_text_size = mgc_text_size_raw;
	pif->pf_draw_text = mgc_draw_text_raw;
	pif->pf_text_out = mgc_text_out_raw;
	pif->pf_multi_line = mgc_multi_line_raw;

	pif->pf_color_out = mgc_color_out_raw;
	pif->pf_draw_image = mgc_draw_image_raw;
}

void mgc_get_visual_measure(visual_t view, measure_interface* pim)
{
	pim->ctx = (void*)view;

	pim->pf_measure_pixel = mgc_pixel_metric_raw;
	pim->pf_measure_font = mgc_text_metric_raw;
	pim->pf_measure_size = mgc_text_size_raw;
	pim->pf_measure_rect = mgc_text_rect_raw;
}

void mgc_get_canvas_measure(canvas_t canv, measure_interface* pim)
{
	pim->ctx = (void*)canv;

	pim->pf_measure_pixel = mgc_pixel_metric;
	pim->pf_measure_font = mgc_text_metric;
	pim->pf_measure_size = mgc_text_size;
	pim->pf_measure_rect = mgc_text_rect;
}

#endif /**/