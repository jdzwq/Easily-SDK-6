﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc canvas interface document

	@module	gdiinf.h | interface file

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

#ifndef _GDIFACE_H
#define _GDIFACE_H

#include "../xdcdef.h"

#if defined(XDU_SUPPORT_CONTEXT)

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION create_canvas_interface: create canvas interface.
@INPUT canvas_t canv: the canvas object.
@RETURN if_canvas_t*: if succeeds return canvas interface struct, fails return NULL.
*/
EXP_API void get_canvas_interface(canvas_t canv, drawing_interface* pif);

/*
@FUNCTION create_visual_interface: create view interface.
@INPUT visual_t ctx: the context object.
@RETURN if_viewING_t*: if succeeds return view interface struct, fails return NULL.
*/
EXP_API void get_visual_interface(visual_t visu, drawing_interface* piv);

LOC_API void	get_visual_measure(visual_t view, measure_interface* pim);

LOC_API void	get_canvas_measure(canvas_t canv, measure_interface* pim);

#ifdef	__cplusplus
}
#endif

#endif /*XDU_SUPPORT_CONTEXT*/

#endif /*_GDIFACE_H*/