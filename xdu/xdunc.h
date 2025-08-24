/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc window nc document

	@module	widgetnc.h | interface file

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

#ifndef _XDUNC_H
#define _XDUNC_H

#include "xdudef.h"

#ifdef XDU_SUPPORT_WIDGET_NC

LOC_API int _widget_nc_hint_test(widget_t wt, const xpoint_t* pxp);

LOC_API int _widget_nc_calc_scroll(widget_t wt, bool_t horz, const xpoint_t* pxp);

LOC_API void _widget_nc_draw_frame(widget_t wt, visual_t dc, const xrect_t* prt);

LOC_API void _widget_nc_draw_scroll(widget_t wt, visual_t dc, bool_t horz, const xrect_t* prt);

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#endif

#endif /*_XDUNC_H*/