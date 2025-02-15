/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc mgc gdi document

	@module	mgcgdi.h | interface file

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

#ifndef _MGC_H
#define _MGC_H

#include "../xdkdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

	/*
@FUNCTION create_mgc_canvas: create a mgc canvas.
@INPUT visual_t mgc: the visual object.
@RETURN canvas_t: if succeeds return canvas object, fails return NULL.
*/
EXP_API canvas_t create_mgc_canvas(visual_t mgc);

/*
@FUNCTION destroy_mgc_canvas: destroy the mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@RETURN void: none.
*/
EXP_API void destroy_mgc_canvas(canvas_t canv);

/*
@FUNCTION mgc_get_canvas_visual: get the mgc visual object.
@INPUT canvas_t canv: the mgc canvas object.
@RETURN visual_t: return the visual object if exists, otherwise return NULL.
*/
EXP_API visual_t mgc_get_canvas_visual(canvas_t canv);

/*
@FUNCTION mgc_rect_tm_to_pt: mapping rectangle points to millimeter in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INOUTPUT xrect_t* pxr: the rect struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void mgc_rect_tm_to_pt(canvas_t canv, xrect_t* pxr);

/*
@FUNCTION mgc_rect_pt_to_tm: mapping rectangle millimeter to points in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INOUTPUT xrect_t* pxr: the rect struct for inputing float member and outputing integer member.
@RETURN void: none.
*/
EXP_API void mgc_rect_pt_to_tm(canvas_t canv, xrect_t* pxr);

/*
@FUNCTION mgc_size_tm_to_pt: mapping size points to millimeter in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INOUTPUT xsize_t* pxs: the size struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void mgc_size_tm_to_pt(canvas_t canv, xsize_t* pxs);

/*
@FUNCTION mgc_size_pt_to_tm: mapping size points to millimeter in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INOUTPUT xsize_t* pxs: the size struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void mgc_size_pt_to_tm(canvas_t canv, xsize_t* pxs);

/*
@FUNCTION mgc_point_tm_to_pt: mapping point points to millimeter in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INOUTPUT xpoint_t* ppt: the point struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void mgc_point_tm_to_pt(canvas_t canv, xpoint_t* ppt);

/*
@FUNCTION mgc_point_pt_to_tm: mapping point points to millimeter in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INOUTPUT xpoint_t* ppt: the point struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void mgc_point_pt_to_tm(canvas_t canv, xpoint_t* ppt);

/*
@FUNCTION mgc_point_tm_to_pt: mapping point points to millimeter in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INOUTPUT xspan_t* ppt: the span struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void mgc_span_tm_to_pt(canvas_t canv, xspan_t* ppn);

/*
@FUNCTION mgc_point_pt_to_tm: mapping point points to millimeter in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INOUTPUT xspan_t* ppn: the span struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void mgc_span_pt_to_tm(canvas_t canv, xspan_t* ppn);

/*
@FUNCTION create_mgc_visual: create a mgc visual.
@INPUT link_t_ptr mgc: the mgc doucment.
@RETURN visual_t: if succeeds return visual object, fails return NULL.
*/
	EXP_API visual_t create_mgc_visual(const tchar_t* devName, const tchar_t* formName, int width, int height, int dpi);

/*
@FUNCTION destroy_mgc_visual: destroy the mgc visual.
@INPUT visual_t mgc: the mgc visual object.
@RETURN void: none.
*/
	EXP_API void destroy_mgc_visual(visual_t mgc);

	EXP_API void mgc_set_rop(visual_t mgc, int rop);
	EXP_API int mgc_get_rop(visual_t mgc);
	EXP_API void mgc_get_point(visual_t mgc, xcolor_t* pxc, const xpoint_t* ppt);
	EXP_API void mgc_set_point(visual_t mgc, const xcolor_t* pxc, const xpoint_t* ppt);
	EXP_API dword_t mgc_save_bytes(visual_t mgc, byte_t* buf, dword_t max);

	EXP_API int mgc_pt_per_in_raw(visual_t mgc, bool_t horz);
	EXP_API int mgc_pt_per_in(canvas_t canv, bool_t horz);

	EXP_API int mgc_pt_per_in_raw(visual_t mgc, bool_t horz);
	EXP_API int mgc_pt_per_mm(canvas_t canv, bool_t horz);

/*
@FUNCTION mgc_pt_to_tm: mapping points to millimeter in mgc canvas.
@INPUT visual_t mgc: the mgc visual object.
@INPUT int pt: the points value.
@INPUT bool_t horz: nonzero fro horizon mapping, zero for vertical mapping.
@RETURN float: return the value in millimeter.
*/
	EXP_API float mgc_pt_to_tm_raw(visual_t mgc, int pt, bool_t horz);
	EXP_API float mgc_pt_to_tm(canvas_t canv, int pt, bool_t horz);
/*
@FUNCTION mgc_tm_to_pt_raw: mapping millimeter to points in mgc canvas.
@INPUT visual_t mgc: the mgc visual object.
@INPUT float tm: the millimeter value.
@INPUT bool_t horz: nonzero fro horizon mapping, zero for vertical mapping.
@RETURN float: return the value in points.
*/
	EXP_API int mgc_tm_to_pt_raw(visual_t mgc, float tm, bool_t horz);
	EXP_API int mgc_tm_to_pt(canvas_t canv, float tm, bool_t horz);

/*
@FUNCTION mgc_draw_line: draw line in mgc canvas using milimeter coordinate
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xpoint_t* ppt1: the from point struct using float member.
@INPUT const xpoint_t* ppt2: the to point struct using float member.
@RETURN void: none.
*/
	EXP_API void	mgc_draw_line(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2);
	EXP_API void	mgc_draw_line_raw(visual_t mgc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2);

/*
@FUNCTION mgc_draw_bezier: draw bezier in mgc canvas using millimeter coordinate
@INPUT canvas_t canv: the canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xpoint_t* ppt1: the start point using float member.
@INPUT const xpoint_t* ppt2: the control point using float member.
@INPUT const xpoint_t* ppt3: the control point using float member.
@INPUT const xpoint_t* ppt4: the end point using float member.
@RETURN void: none.
*/
EXP_API void	mgc_draw_bezier(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4);
EXP_API void	mgc_draw_bezier_raw(visual_t mgc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4);

/*
@FUNCTION mgc_draw_curve: draw curve in mgc canvas using millimeter coordinate
@INPUT canvas_t canv: the canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xpoint_t* ppt: the point array.
@INPUT int n: the point array size.
@RETURN void: none.
*/
EXP_API void	mgc_draw_curve(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt, int n);
EXP_API void	mgc_draw_curve_raw(visual_t mgc, const xpen_t* pxp, const xpoint_t* ppt, int n);

/*
@FUNCTION mgc_draw_arc : draw arc in mgc canvas using millimeter coordinate.
@INPUT canvas_t canv : the mgc canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xpoint_t* ppt1: the start point struct using float member.
@INPUT const xpoint_t* ppt2: the end point struct using float member.
@INPUT const xsize_t* pxs: the x-radius and  the y-radius
@INPUT bool_t sflag: is clock-wise drawing.
@INPUT bool_t lflag: is large arc.
@RETURN void: none.
*/
EXP_API void	mgc_draw_arc(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t sflag, bool_t lflag);
EXP_API void	mgc_draw_arc_raw(visual_t mgc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t sflag, bool_t lflag);

/*
@FUNCTION mgc_draw_polyline: draw polyline in mgc canvas using milimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xpoint_t* ppt: the point struct array using float member.
@INPUT int n: the point entity count.
@RETURN void: none.
*/
EXP_API void	mgc_draw_polyline(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt, int n);
EXP_API void	mgc_draw_polyline_raw(visual_t mgc, const xpen_t* pxp, const xpoint_t* ppt, int n);

/*
@FUNCTION mgc_draw_triangle: draw triangle in canvas using milimeter coordinate.
@INPUT canvas_t canv: the canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT const tchar_t* orient: the triangle orientation
@RETURN void: none.
*/
EXP_API void	mgc_draw_triangle(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const tchar_t* orient);
EXP_API void	mgc_draw_triangle_raw(visual_t mgc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const tchar_t* orient);

/*
@FUNCTION draw_rect: draw mgc_draw_rect in mgc canvas using milimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@RETURN void: none.
*/
EXP_API void	mgc_draw_rect(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr);
EXP_API void	mgc_draw_rect_raw(visual_t mgc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr);

/*
@FUNCTION mgc_draw_round: draw round rect in mgc canvas using millimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@RETURN void: none.
*/
EXP_API void	mgc_draw_round(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const xsize_t* pxs);
EXP_API void	mgc_draw_round_raw(visual_t mgc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const xsize_t* pxs);

/*
@FUNCTION mgc_draw_ellipse: draw ellipse in mgc canvas using millimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@RETURN void: none.
*/
EXP_API void	mgc_draw_ellipse(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr);
EXP_API void	mgc_draw_ellipse_raw(visual_t mgc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr);

/*
@FUNCTION mgc_draw_pie: draw pie in mgc canvas using millimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xpoint_t* ppt: the point struct using millimeter member.
@INPUT const xsize_t* pxs: the x-radius and  the y-radius
@INPUT double fang: the from angle PI value.
@INPUT double tang: the sweep angle PI value.
@RETURN void: none.
*/
EXP_API void	mgc_draw_pie(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt, double fang, double tang);
EXP_API void	mgc_draw_pie_raw(visual_t mgc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pt, double fang, double tang);

/*
@FUNCTION mgc_draw_sector: draw fan in mgc canvas using millimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xpoint_t* ppt: the point struct using float member.
@INPUT const xsize_t* pxs: fw is the radius and fh is the span.
@INPUT double fang: the from angle PI value.
@INPUT double tang: the to angle PI value.
@RETURN void: none.
*/
EXP_API void	mgc_draw_sector(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* prl, const xspan_t* prs, double fang, double tang);
EXP_API void	mgc_draw_sector_raw(visual_t mgc, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* prl, const xspan_t* prs, double fang, double tang);

/*
@FUNCTION mgc_draw_polygon: draw polygon in mgc canvas using milimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xpoint_t* ppt: the point struct array using float member.
@INPUT int n: the point entity count.
@RETURN void: none.
*/
EXP_API void	mgc_draw_polygon(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, int n);
EXP_API void	mgc_draw_polygon_raw(visual_t mgc, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, int n);

/*
@FUNCTION mgc_draw_equilagon: draw equal polygon using milimeter coordinate
@INPUT canvas_t canv: the canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const xpoint_t* ppt: the center point using float member.
@INPUT const xspan_t* pxn: the radius.
@INPUT int n: the edge count.
@RETURN void: none.
*/
EXP_API void	mgc_draw_equilagon(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* pxn, int n);
EXP_API void	mgc_draw_equilagon_raw(visual_t mgc, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* pxn, int n);

/*
@FUNCTION mgc_multi_line: draw multiple base line in mgc canvas using millimeter coordinate, the line separated by line height of font and face.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xface_t* pxa: the face struct.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@RETURN void: none.
*/
EXP_API void	mgc_multi_line(canvas_t canv, const xfont_t* pxf, const xface_t* pxa, const xpen_t* pxp, const xrect_t* pxr);
EXP_API void	mgc_multi_line_raw(visual_t mgc, const xfont_t* pxf, const xface_t* pxa, const xpen_t* pxp, const xrect_t* pxr);

/*
@FUNCTION mgc_draw_path: draw path in canvas using milimeter coordinate.
@INPUT canvas_t canv: the canvas object.
@INPUT const xpen_t* pxp: the pen struct.
@INPUT const xbrush_t* pxb: the brush struct.
@INPUT const tchar_t* aa: the action stack.
@INPUT const xpoint_t* pa: the points stack.
@INPUT int n: the points stack size.
@RETURN void: none.
*/
EXP_API void	mgc_draw_path(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int n);
EXP_API void	mgc_draw_path_raw(visual_t mgc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int n);

/*
@FUNCTION mgc_draw_text: draw text in mgc canvas using millimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xface_t* pxa: the face struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT const tchar_t* txt: the text token.
@INPUT int len: the text length in characters, -1 indicate the text is terminated by zero.
@RETURN void: none.
*/
EXP_API void	mgc_draw_text(canvas_t canv, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, const tchar_t* txt, int len);
EXP_API void	mgc_draw_text_raw(visual_t mgc, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, const tchar_t* txt, int len);
/*
@FUNCTION mgc_text_out: output text in mgc canvas using millimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xpoint* ppt: the start point struct using float member.
@INPUT const tchar_t* txt: the text token.
@INPUT int len: the text length in characters, -1 indicate the text is terminated by zero.
@RETURN void: none.
*/
EXP_API void	mgc_text_out(canvas_t canv, const xfont_t* pxf, const xpoint_t* ppt, const tchar_t* txt, int len);
EXP_API void	mgc_text_out_raw(visual_t mgc, const xfont_t* pxf, const xpoint_t* ppt, const tchar_t* txt, int len);

/*
@FUNCTION mgc_text_size: calc the text suitable size in mgc canvas using millimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT cont xfont_t* pxf: the font struct.
@INPUT cont tchar_t* txt: the text token.
@INPUT int len: the text length in characters, -1 indicate zero character terminated.
@OUTPUT xsize_t* pxs: the size struct for returning float member.
@RETURN void: none.
*/
EXP_API void	mgc_text_size(canvas_t canv, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs);
EXP_API void	mgc_text_size_raw(visual_t mgc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs);

/*
@FUNCTION mgc_text_metric: calc the image size in mgc canvas using millimeter coordinate.
@INPUT canvas_t canv: the canvas mgc object.
@INPUT cont ximage_t* pxi: the image struct.
@OUTPUT xsize_t* pxs: the size struct for returning float member.
@RETURN void: none.
*/
EXP_API void	mgc_text_metric(canvas_t canv, const xfont_t* pxf, xsize_t* pxs);
EXP_API void	mgc_text_metric_raw(visual_t mgc, const xfont_t* pxf, xsize_t* pxs);

EXP_API void	mgc_text_rect(canvas_t canv, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* pxr);
EXP_API void	mgc_text_rect_raw(visual_t mgc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* pxr);

EXP_API void	mgc_text_indicate_raw(visual_t mgc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* str, int len, const xrect_t* pxr, xrect_t*pa, int n);
EXP_API void	mgc_text_indicate(canvas_t canv, const xfont_t* pxf, const xface_t* pxa, const tchar_t* str, int len, const xrect_t* pxr, xrect_t*pa, int n);

EXP_API float	mgc_pixel_metric(canvas_t canv, bool_t horz);
EXP_API float	mgc_pixel_metric_raw(visual_t mgc, bool_t horz);

/*
@FUNCTION mgc_color_out: output color sequence in mgc canvas using millimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT bool_t horz: nonzero for horizon drawing, zero for vertical drawing.
@INPUT const tchar_t* rgbstr: the rgb tokens, every rgb token separated by ';'.
@INPUT int len: the text length in characters, -1 indicate the text is terminated by zero.
@RETURN void: none.
*/
EXP_API void	mgc_color_out(canvas_t canv, const xrect_t* pxr, bool_t horz, const tchar_t* rgbstr, int len);
EXP_API void	mgc_color_out_raw(visual_t mgc, const xrect_t* pxr, bool_t horz, const tchar_t* rgbstr, int len);

EXP_API void 	mgc_gradient_rect_raw(visual_t mgc, const xcolor_t *clr_brim, const xcolor_t *clr_core, const tchar_t *gradient, const xrect_t *pxr);
EXP_API void	mgc_alphablend_rect_raw(visual_t mgc, const xcolor_t* pxc, const xrect_t* pxr, int opacity);
/*
@FUNCTION mgc_draw_image: draw image in mgc canvas using millimeter coordinate.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT const ximage_t* pxi: the image struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@RETURN void: none.
*/
EXP_API void	mgc_draw_image(canvas_t canv, const ximage_t* pxi, const xrect_t* pxr);
EXP_API void	mgc_draw_image_raw(visual_t mgc, const ximage_t* pxi, const xrect_t* pxr);


#ifdef	__cplusplus
}
#endif


#endif /*_MGCGDI_H*/