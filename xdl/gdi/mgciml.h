/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc mgc interface document

	@module	mgcinf.h | interface file

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

#ifndef _MGCIML_H
#define _MGCIML_H

#include "../xdldef.h"

#if defined(XDL_SUPPORT_MGC)

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION create_mgc_interface: create mgc canvas interface.
@INPUT canvas_t canv: the mgc canvas object.
@RETURN drawing_interface*: if succeeds return mgc canvas interface struct, fails return NULL.
*/
EXP_API void mgc_get_canvas_interface(canvas_t canv, drawing_interface* pif);

/*
@FUNCTION create_visual_interface: create mgc view interface.
@INPUT visual_t view: the context object.
@RETURN if_viewING_t*: if succeeds return view interface struct, fails return NULL.
*/
EXP_API void mgc_get_visual_interface(visual_t visu, drawing_interface* pif);

LOC_API void	mgc_get_visual_measure(visual_t view, measure_interface* pim);

LOC_API void	mgc_get_canvas_measure(canvas_t canv, measure_interface* pim);

#ifdef	__cplusplus
}
#endif

#endif /*XDL_SUPPORT_MGC*/

#endif /*MGCIML_H*/