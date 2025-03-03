﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdi canvas document

	@module	gdicanv.h | interface file

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

#ifndef _GDICANV_H
#define _GDICANV_H

#include "../xdcdef.h"

#if defined(XDU_SUPPORT_CONTEXT)

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION create_display_canvas: create a display context canvas.
@INPUT res_dc_t rdc: the device context resource handle.
@RETURN canvas_t: if succeeds return canvas object, fails return NULL.
*/
EXP_API canvas_t create_display_canvas(visual_t rdc);

/*
@FUNCTION destroy_display_canvas: destroy the display context canvas.
@INPUT canvas_t canv: the canvas object.
@RETURN void: none.
*/
EXP_API void	destroy_display_canvas(canvas_t canv);

/*
@FUNCTION get_canvas_visual: get the visual object.
@INPUT canvas_t canv: the svg canvas object.
@RETURN visual_t: return the visual object if exists, otherwise return NULL.
*/
EXP_API visual_t get_canvas_visual(canvas_t canv);

/*
@FUNCTION set_canvas_ratio: set the canvas horizon and vertical ratio.
@INPUT canvas_t canv: the canvas object.
@INPUT float htpermm: the horizon points per millimeter.
@INPUT float vtpermm: the vertical points per millimeter.
@RETURN void: none.
*/
EXP_API void	set_canvas_ratio(canvas_t canv, float htpermm, float vtpermm);

/*
@FUNCTION get_canvas_horz_size: get the canvas horizon size in millimeter.
@INPUT canvas_t canv: the canvas object.
@RETURN float: return the canvas horizon size.
*/
EXP_API float	get_canvas_horz_size(canvas_t canv);

/*
@FUNCTION get_canvas_horz_size: get the canvas vertical size in millimeter.
@INPUT canvas_t canv: the canvas object.
@RETURN float: return the canvas vertical size.
*/
EXP_API float	get_canvas_vert_size(canvas_t canv);

/*
@FUNCTION set_canvas_horz_feed: set the canvas horizon feed in millimeter, the feed span is not drawable.
@INPUT canvas_t canv: the canvas object.
@INPUT float cx: the feed value.
@RETURN void: none.
*/
EXP_API void	set_canvas_horz_feed(canvas_t canv, float cx);

/*
@FUNCTION get_canvas_horz_feed: get the canvas horizon feed in millimeter, the feed span is not drawable.
@INPUT canvas_t canv: the canvas object.
@RETURN float: return the canvas horizon feed.
*/
EXP_API float	get_canvas_horz_feed(canvas_t canv);

/*
@FUNCTION set_canvas_vert_feed: set the canvas vertical feed in millimeter, the feed span is not drawable.
@INPUT canvas_t canv: the canvas object.
@INPUT float cx: the feed value.
@RETURN void: none.
*/
EXP_API void	set_canvas_vert_feed(canvas_t canv, float cy);

/*
@FUNCTION get_canvas_vert_feed: get the canvas vertical feed in millimeter, the feed span is not drawable.
@INPUT canvas_t canv: the canvas object.
@RETURN float: return the canvas vertical feed.
*/
EXP_API float	get_canvas_vert_feed(canvas_t canv);

/*
@FUNCTION begin_canvas_paint: begin canvas painting and return a memory context for drawing buffer.
@INPUT canvas_t canv: the canvas object.
@INPUT visual_t rdc: the display or printer context resource handle.
@INPUT int width: the client width in points.
@INPUT int height: the client height in points.
@RETURN visual_t: if succeeds return memory context resource handle, fails return NULL.
*/
EXP_API visual_t begin_canvas_paint(canvas_t canv, visual_t rdc, int width, int height);

/*
@FUNCTION end_canvas_paint: end canvas painting and free drawing buffer.
@INPUT canvas_t canv: the canvas object.
@INPUT visual_t rdc: the display or printer context resource handle.
@INPUT const xrect_t: the client rectangle for rendering context from buffer.
@RETURN void: none.
*/
EXP_API void	end_canvas_paint(canvas_t canv, visual_t rdc, const xrect_t* pxr);

#ifdef XDU_SUPPORT_CONTEXT_PRINTER
/*
@FUNCTION create_printer_canvas: create a printer context canvas.
@INPUT res_dc_t rdc: the display context resource handle.
@RETURN canvas_t: if succeeds return canvas object, fails return NULL.
*/
EXP_API canvas_t create_printer_canvas(visual_t rdc);

/*
@FUNCTION destroy_printer_canvas: destroy the printer context canvas.
@INPUT canvas_t canv: the canvas object.
@RETURN void: none.
*/
EXP_API void	destroy_printer_canvas(canvas_t canv);

#endif //XDU_SUPPORT_CONTEXT_PRINTER

/*
@FUNCTION pt_to_tm: mapping points to millimeter in canvas.
@INPUT canvas_t canv: the canvas object.
@INPUT int pt: the points value.
@INPUT bool_t horz: nonzero fro horizon mapping, zero for vertical mapping.
@RETURN float: return the value in millimeter.
*/
EXP_API float pt_to_tm(canvas_t canv, int pt, bool_t horz);

/*
@FUNCTION tm_to_pt: mapping millimeter to points in canvas.
@INPUT canvas_t canv: the canvas object.
@INPUT float tm: the millimeter value.
@INPUT bool_t horz: nonzero fro horizon mapping, zero for vertical mapping.
@RETURN float: return the value in points.
*/
EXP_API int tm_to_pt(canvas_t canv, float tm, bool_t horz);

/*
@FUNCTION rect_tm_to_pt: mapping rectangle points to millimeter in canvas.
@INPUT canvas_t canv: the canvas object.
@INOUTPUT xrect_t* pxr: the rect struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void rect_tm_to_pt(canvas_t canv, xrect_t* pxr);

/*
@FUNCTION rect_pt_to_tm: mapping rectangle millimeter to points in canvas.
@INPUT canvas_t canv: the canvas object.
@INOUTPUT xrect_t* pxr: the rect struct for inputing float member and outputing integer member.
@RETURN void: none.
*/
EXP_API void rect_pt_to_tm(canvas_t canv, xrect_t* pxr);

/*
@FUNCTION size_tm_to_pt: mapping size points to millimeter in canvas.
@INPUT canvas_t canv: the canvas object.
@INOUTPUT xsize_t* pxs: the size struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void size_tm_to_pt(canvas_t canv, xsize_t* pxs);

/*
@FUNCTION size_pt_to_tm: mapping size points to millimeter in canvas.
@INPUT canvas_t canv: the canvas object.
@INOUTPUT xsize_t* pxs: the size struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void size_pt_to_tm(canvas_t canv, xsize_t* pxs);

/*
@FUNCTION point_tm_to_pt: mapping point points to millimeter in canvas.
@INPUT canvas_t canv: the canvas object.
@INOUTPUT xpoint_t* ppt: the point struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void point_tm_to_pt(canvas_t canv, xpoint_t* ppt);

/*
@FUNCTION point_pt_to_tm: mapping point points to millimeter in canvas.
@INPUT canvas_t canv: the canvas object.
@INOUTPUT xpoint_t* ppt: the point struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void point_pt_to_tm(canvas_t canv, xpoint_t* ppt);

/*
@FUNCTION span_tm_to_pt: mapping span points to millimeter in canvas.
@INPUT canvas_t canv: the canvas object.
@INOUTPUT xspan_t* pxs: the span struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void span_tm_to_pt(canvas_t canv, xspan_t* pxs);

/*
@FUNCTION span_pt_to_tm: mapping span points to millimeter in canvas.
@INPUT canvas_t canv: the canvas object.
@INOUTPUT xspan_t* pxs: the span struct for inputing integer member and outputing float member.
@RETURN void: none.
*/
EXP_API void span_pt_to_tm(canvas_t canv, xspan_t* pxs);

#ifdef	__cplusplus
}
#endif

#endif /*XDU_SUPPORT_CONTEXT*/

#endif /*GDICANV_H*/