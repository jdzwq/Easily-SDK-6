/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu utility document

	@module	xduutil.h | interface file

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

#ifndef _XDUUTIL_H
#define _XDUUTIL_H

#include "xdudef.h"

#ifdef	__cplusplus
extern "C" {
#endif

EXP_API void default_widget_color_mode(color_mod_t* pclrs);

EXP_API void default_widget_xfont(xfont_t* pxf);

EXP_API void default_widget_xface(xface_t* pxa);

EXP_API void default_textor_xfont(xfont_t* pxf);

EXP_API void default_textor_xface(xface_t* pxa);

#ifdef	__cplusplus
}
#endif

#endif