﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc menu document

	@module	menuview.h | interface file

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

#ifndef _MENUVIEW_H
#define _MENUVIEW_H

#include "../xdldef.h"



typedef enum{
	MENU_HINT_NONE,
	MENU_HINT_ITEM,
}MENU_HINT_CODE;

#ifdef	__cplusplus
extern "C" {
#endif

	EXP_API float calc_menu_height(const measure_interface* pif, link_t_ptr ptr);

	EXP_API float calc_menu_width(const measure_interface* pif, link_t_ptr ptr);

	EXP_API void calc_menu_item_rect(const measure_interface* pif, link_t_ptr ptr, link_t_ptr ilk, xrect_t* pxr);

	EXP_API int	calc_menu_hint(const measure_interface* pif, const xpoint_t* ppt, link_t_ptr ptr, link_t_ptr* pilk);

	EXP_API void draw_menu(const drawing_interface* pcanv, link_t_ptr ptr);

#ifdef	__cplusplus
}
#endif


#endif	/*_MENUVIEW_H*/