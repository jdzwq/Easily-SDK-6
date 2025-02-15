/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc mgc canvas document

	@module	mgccanv.h | interface file

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

#ifndef _MGCCANV_H
#define _MGCCANV_H

#include "../xdldef.h"

#if defined(XDL_SUPPORT_MGC)

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION create_mgc_canvas: create a mgc canvas.
@INPUT visual_t view: the visual object.
@RETURN canvas_t: if succeeds return canvas object, fails return NULL.
*/
EXP_API canvas_t create_mgc_canvas(visual_t view);

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
@FUNCTION mgc_pt_per_in: get points per inch in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT bool_t horz: nonzero fro horizon mapping, zero for vertical mapping.
@RETURN float: return the value in millimeter.
*/
EXP_API float mgc_pt_per_in(canvas_t canv, bool_t horz);

/*
@FUNCTION mgc_pt_per_mm: get points per millimeter in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT bool_t horz: nonzero fro horizon mapping, zero for vertical mapping.
@RETURN float: return the value in millimeter.
*/
EXP_API float mgc_pt_per_mm(canvas_t canv, bool_t horz);

/*
@FUNCTION mgc_pt_to_tm: mapping points to millimeter in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT int pt: the points value.
@INPUT bool_t horz: nonzero fro horizon mapping, zero for vertical mapping.
@RETURN float: return the value in millimeter.
*/
EXP_API float mgc_pt_to_tm(canvas_t canv, int pt, bool_t horz);

/*
@FUNCTION mgc_tm_to_pt: mapping millimeter to points in mgc canvas.
@INPUT canvas_t canv: the mgc canvas object.
@INPUT float tm: the millimeter value.
@INPUT bool_t horz: nonzero fro horizon mapping, zero for vertical mapping.
@RETURN float: return the value in points.
*/
EXP_API int mgc_tm_to_pt(canvas_t canv, float tm, bool_t horz);

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


#ifdef	__cplusplus
}
#endif

#endif /*XDL_SUPPORT_VIEW*/

#endif /*MGCCANV_H*/