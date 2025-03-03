﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc svg gdi document

	@module	svggdi.h | interface file

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

#ifndef _SVGGDI_H
#define _SVGGDI_H

#include "../xdldef.h"

#if defined(XDL_SUPPORT_SVG)

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION svg_draw_line: draw line in svg canvas using milimeter coordinate
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xpoint_t* ppt1: the from point struct using float member.
@INPUT const xpoint_t* ppt2: the to point struct using float member.
@RETURN void: none.
*/
LOC_API void	svg_draw_line(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2);
LOC_API void	svg_draw_line_raw(visual_t view, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2);

/*
@FUNCTION svg_draw_bezier: draw bezier in svg canvas using millimeter coordinate
@INPUT canvas_t canv: the canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xpoint_t* ppt1: the start point using float member.
@INPUT const xpoint_t* ppt2: the control point using float member.
@INPUT const xpoint_t* ppt3: the control point using float member.
@INPUT const xpoint_t* ppt4: the end point using float member.
@RETURN void: none.
*/
LOC_API void	svg_draw_bezier(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4);
LOC_API void	svg_draw_bezier_raw(visual_t view, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4);

/*
@FUNCTION svg_draw_curve: draw curve in svg canvas using millimeter coordinate
@INPUT canvas_t canv: the canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xpoint_t* ppt: the point array.
@INPUT int n: the point array size.
@RETURN void: none.
*/
LOC_API void	svg_draw_curve(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt, int n);
LOC_API void	svg_draw_curve_raw(visual_t view, const xpen_t* pxp, const xpoint_t* ppt, int n);

/*
@FUNCTION svg_draw_arc : draw arc in svg canvas using millimeter coordinate.
@INPUT canvas_t canv : the svg canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xpoint_t* ppt1: the start point struct using float member.
@INPUT const xpoint_t* ppt2: the end point struct using float member.
@INPUT const xsize_t* pxs: the x-radius and  the y-radius
@INPUT bool_t sflag: is clock-wise drawing.
@INPUT bool_t lflag: is large arc.
@RETURN void: none.
*/
LOC_API void	svg_draw_arc(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t sflag, bool_t lflag);
LOC_API void	svg_draw_arc_raw(visual_t view, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t sflag, bool_t lflag);

/*
@FUNCTION svg_draw_polyline: draw polyline in svg canvas using milimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xpoint_t* ppt: the point struct array using float member.
@INPUT int n: the point entity count.
@RETURN void: none.
*/
LOC_API void	svg_draw_polyline(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt, int n);
LOC_API void	svg_draw_polyline_raw(visual_t view, const xpen_t* pxp, const xpoint_t* ppt, int n);

/*
@FUNCTION svg_draw_triangle: draw triangle in canvas using milimeter coordinate.
@INPUT canvas_t canv: the canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT const tchar_t* orient: the triangle orientation
@RETURN void: none.
*/
LOC_API void	svg_draw_triangle(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const tchar_t* orient);
LOC_API void	svg_draw_triangle_raw(visual_t view, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const tchar_t* orient);

/*
@FUNCTION draw_rect: draw svg_draw_rect in svg canvas using milimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@RETURN void: none.
*/
LOC_API void	svg_draw_rect(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr);
LOC_API void	svg_draw_rect_raw(visual_t view, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr);

/*
@FUNCTION svg_draw_round: draw round rect in svg canvas using millimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@RETURN void: none.
*/
LOC_API void	svg_draw_round(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const xsize_t* pxs);
LOC_API void	svg_draw_round_raw(visual_t view, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const xsize_t* pxs);

/*
@FUNCTION svg_draw_ellipse: draw ellipse in svg canvas using millimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@RETURN void: none.
*/
LOC_API void	svg_draw_ellipse(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr);
LOC_API void	svg_draw_ellipse_raw(visual_t view, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr);

/*
@FUNCTION svg_draw_pie: draw pie in svg canvas using millimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xpoint_t* ppt: the point struct using millimeter member.
@INPUT const xsize_t* pxs: the x-radius and  the y-radius
@INPUT double fang: the from angle PI value.
@INPUT double tang: the sweep angle PI value.
@RETURN void: none.
*/
LOC_API void	svg_draw_pie(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt, double fang, double sang);
LOC_API void	svg_draw_pie_raw(visual_t view, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pt, double fang, double sang);

/*
@FUNCTION svg_draw_sector: draw fan in svg canvas using millimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xpoint_t* ppt: the point struct using float member.
@INPUT const xsize_t* pxs: fw is the radius and fh is the span.
@INPUT double fang: the from angle PI value.
@INPUT double tang: the to angle PI value.
@RETURN void: none.
*/
LOC_API void	svg_draw_sector(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* prl, const xspan_t* prs, double fang, double sang);
LOC_API void	svg_draw_sector_raw(visual_t view, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* prl, const xspan_t* prs, double fang, double sang);

/*
@FUNCTION svg_draw_polygon: draw polygon in svg canvas using milimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xpoint_t* ppt: the point struct array using float member.
@INPUT int n: the point entity count.
@RETURN void: none.
*/
LOC_API void	svg_draw_polygon(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, int n);
LOC_API void	svg_draw_polygon_raw(visual_t view, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, int n);

/*
@FUNCTION svg_draw_equilagon: draw equal polygon using milimeter coordinate
@INPUT canvas_t canv: the canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xpoint_t* ppt: the center point using float member.
@INPUT const xspan_t* pxn: the radius.
@INPUT int n: the edge count.
@RETURN void: none.
*/
LOC_API void	svg_draw_equilagon(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* pxn, int n);
LOC_API void	svg_draw_equilagon_raw(visual_t view, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* pxn, int n);

/*
@FUNCTION svg_multi_line: draw multiple base line in svg canvas using millimeter coordinate, the line separated by line height of font and face.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xface_t* pxa: the face struct.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@RETURN void: none.
*/
LOC_API void	svg_multi_line(canvas_t canv, const xfont_t* pxf, const xface_t* pxa, const xpen_t* pxp, const xrect_t* pxr);
LOC_API void	svg_multi_line_raw(visual_t view, const xfont_t* pxf, const xface_t* pxa, const xpen_t* pxp, const xrect_t* pxr);

/*
@FUNCTION svg_draw_path: draw path in canvas using milimeter coordinate.
@INPUT canvas_t canv: the canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const tchar_t* aa: the action stack.
@INPUT const xpoint_t* pa: the points stack.
@INPUT int n: the points stack size.
@RETURN void: none.
*/
LOC_API void	svg_draw_path(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int n);
LOC_API void	svg_draw_path_raw(visual_t view, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int n);

/*
@FUNCTION svg_draw_text: draw text in svg canvas using millimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xface_t* pxa: the face struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT const tchar_t* txt: the text token.
@INPUT int len: the text length in characters, -1 indicate the text is terminated by zero.
@RETURN void: none.
*/
LOC_API void	svg_draw_text(canvas_t canv, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, const tchar_t* txt, int len);
LOC_API void	svg_draw_text_raw(visual_t view, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, const tchar_t* txt, int len);
/*
@FUNCTION svg_text_out: output text in svg canvas using millimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xpoint* ppt: the start point struct using float member.
@INPUT const tchar_t* txt: the text token.
@INPUT int len: the text length in characters, -1 indicate the text is terminated by zero.
@RETURN void: none.
*/
LOC_API void	svg_text_out(canvas_t canv, const xfont_t* pxf, const xpoint_t* ppt, const tchar_t* txt, int len);
LOC_API void	svg_text_out_raw(visual_t view, const xfont_t* pxf, const xpoint_t* ppt, const tchar_t* txt, int len);

/*
@FUNCTION svg_text_size: calc the text suitable size in svg canvas using millimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT cont xfont_t* pxf: the font struct.
@INPUT cont tchar_t* txt: the text token.
@INPUT int len: the text length in characters, -1 indicate zero character terminated.
@OUTPUT xsize_t* pxs: the size struct for returning float member.
@RETURN void: none.
*/
LOC_API void	svg_text_size(canvas_t canv, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs);
LOC_API void	svg_text_size_raw(visual_t view, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs);

/*
@FUNCTION svg_text_metric: calc the image size in svg canvas using millimeter coordinate.
@INPUT canvas_t canv: the canvas svg object.
@INPUT cont ximage_t* pxi: the image struct.
@OUTPUT xsize_t* pxs: the size struct for returning float member.
@RETURN void: none.
*/
LOC_API void	svg_text_metric(canvas_t canv, const xfont_t* pxf, xsize_t* pxs);
LOC_API void	svg_text_metric_raw(visual_t view, const xfont_t* pxf, xsize_t* pxs);

LOC_API void	svg_text_rect(canvas_t canv, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* pxr);
LOC_API void	svg_text_rect_raw(visual_t view, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* pxr);

LOC_API float	svg_pixel_metric(canvas_t canv, bool_t horz);
LOC_API float	svg_pixel_metric_raw(visual_t view, bool_t horz);

/*
@FUNCTION svg_color_out: output color sequence in svg canvas using millimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT bool_t horz: nonzero for horizon drawing, zero for vertical drawing.
@INPUT const tchar_t* rgbstr: the rgb tokens, every rgb token separated by ';'.
@INPUT int len: the text length in characters, -1 indicate the text is terminated by zero.
@RETURN void: none.
*/
LOC_API void	svg_color_out(canvas_t canv, const xrect_t* pxr, bool_t horz, const tchar_t* rgbstr, int len);
LOC_API void	svg_color_out_raw(visual_t view, const xrect_t* pxr, bool_t horz, const tchar_t* rgbstr, int len);

/*
@FUNCTION svg_draw_image: draw image in svg canvas using millimeter coordinate.
@INPUT canvas_t canv: the svg canvas object.
@INPUT const ximage_t* pxi: the image struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@RETURN void: none.
*/
LOC_API void	svg_draw_image(canvas_t canv, const ximage_t* pxi, const xrect_t* pxr);
LOC_API void	svg_draw_image_raw(visual_t view, const ximage_t* pxi, const xrect_t* pxr);



#ifdef	__cplusplus
}
#endif

#endif /*XDL_SUPPORT_SVG*/

#endif /*SVGGDI_H*/