﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc fire editor document

	@module	xdcfire.h | interface file

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

#ifndef _EDITOR_H
#define _EDITOR_H

#include "../xdcdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION fireedit_create: create a editbox editor.
@INPUT res_win_t widget: the owner widget.
@INPUT const xrect_t* pxr: the widget rect.
@RETURN res_win_t: return the editor resource handle.
*/
EXP_API res_win_t fireedit_create(res_win_t widget, const xrect_t* pxr);

/*
@FUNCTION firecheck_create: create a checkbox editor.
@INPUT res_win_t widget: the owner widget.
@INPUT const xrect_t* pxr: the widget rect.
@RETURN res_win_t: return the editor resource handle.
*/
EXP_API res_win_t firecheck_create(res_win_t widget, const xrect_t* pxr);

/*
@FUNCTION firedate_create: create a datebox editor.
@INPUT res_win_t widget: the owner widget.
@INPUT const xrect_t* pxr: the widget rect.
@RETURN res_win_t: return the editor resource handle.
*/
EXP_API res_win_t firedate_create(res_win_t widget, const xrect_t* pxr);

/*
@FUNCTION firetime_create: create a timebox editor.
@INPUT res_win_t widget: the owner widget.
@INPUT const xrect_t* pxr: the widget rect.
@RETURN res_win_t: return the editor resource handle.
*/
EXP_API res_win_t firetime_create(res_win_t widget, const xrect_t* pxr);

/*
@FUNCTION firenum_create: create a numbox editor.
@INPUT res_win_t widget: the owner widget.
@INPUT const xrect_t* pxr: the widget rect.
@RETURN res_win_t: return the editor resource handle.
*/
EXP_API res_win_t firenum_create(res_win_t widget, const xrect_t* pxr);

/*
@FUNCTION firelist_create: create a listbox editor.
@INPUT res_win_t widget: the owner widget.
@INPUT const xrect_t* pxr: the widget rect.
@INPUT link_t_ptr data: the string table link component.
@RETURN res_win_t: return the editor resource handle.
*/
EXP_API res_win_t firelist_create(res_win_t widget, const xrect_t* pxr, link_t_ptr data);

/*
@FUNCTION firelist_get_data: get listbox string table.
@INPUT res_win_t widget: the owner widget.
@RETURN link_t_ptr: return the string table link component.
*/
EXP_API link_t_ptr firelist_get_data(res_win_t widget);

/*
@FUNCTION firelist_get_item: get listbox current selected string entity.
@INPUT res_win_t widget: the owner widget.
@RETURN link_t_ptr: return the string entity link component.
*/
EXP_API link_t_ptr firelist_get_item(res_win_t widget);

/*
@FUNCTION firegrid_create: create a dropgrid editor.
@INPUT res_win_t widget: the owner widget.
@INPUT const xrect_t* pxr: the widget rect.
@INPUT link_t_ptr data: the grid document link component.
@RETURN res_win_t: return the editor resource handle.
*/
EXP_API res_win_t firegrid_create(res_win_t widget, const xrect_t* pxr, link_t_ptr data);

/*
@FUNCTION firegrid_get_data: get dropgrid grid document.
@INPUT res_win_t widget: the owner widget.
@RETURN link_t_ptr: return the grid document link component.
*/
EXP_API link_t_ptr firegrid_get_data(res_win_t widget);

/*
@FUNCTION firegrid_get_item: get dropgrid current selected row.
@INPUT res_win_t widget: the owner widget.
@RETURN link_t_ptr: return the row link component.
*/
EXP_API link_t_ptr firegrid_get_item(res_win_t widget);

/*
@FUNCTION firewords_create: create a wordsbox editor.
@INPUT res_win_t widget: the owner widget.
@INPUT const xrect_t* pxr: the widget rect.
@INPUT link_t_ptr data: the words table link component.
@RETURN res_win_t: return the editor resource handle.
*/
EXP_API res_win_t firewords_create(res_win_t widget, const xrect_t* pxr, link_t_ptr data);

/*
@FUNCTION firewords_get_data: get wordsbox words table.
@INPUT res_win_t widget: the owner widget.
@RETURN link_t_ptr: return the words table link component.
*/
EXP_API link_t_ptr firewords_get_data(res_win_t widget);

/*
@FUNCTION firewords_get_item: get wordsbox current selected item.
@INPUT res_win_t widget: the owner widget.
@RETURN link_t_ptr: return the words item link component.
*/
EXP_API link_t_ptr firewords_get_item(res_win_t widget);

#ifdef	__cplusplus
}
#endif

#endif /*XDCFIRE_H*/
