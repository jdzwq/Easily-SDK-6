﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc menu utility document

	@module	xdcmenu.h | interface file

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

#ifndef _MENU_H
#define _MENU_H

#include "../xdcdef.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION textor_menu: create a text operation menu.
@INPUT res_win_t widget: the owner widget.
@INPUT const xpoint_t* ppt: the based position.
@INPUT int lay: the layout mode, it can be WS_LAYOUT_LEFTTOP, WS_LAYOUT_RIGHTTOP, WS_LAYOUT_LEFTBOTTOM, WS_LAYOUT_RIGHTBOTTOM.
@RETURN void: none.
*/
EXP_API void textor_menu(res_win_t widget, const xpoint_t* ppt, int lay);

/*
@FUNCTION fontname_menu: create a font name select menu.
@INPUT res_win_t widget: the owner widget.
@INPUT dword_t idc: the menu control id.
@INPUT const xpoint_t* ppt: the based position.
@INPUT int lay: the layout mode, it can be WS_LAYOUT_LEFTTOP, WS_LAYOUT_RIGHTTOP, WS_LAYOUT_LEFTBOTTOM, WS_LAYOUT_RIGHTBOTTOM.
@RETURN void: none.
*/
EXP_API void fontname_menu(res_win_t widget, dword_t idc, const xpoint_t* ppt, int lay);

/*
@FUNCTION fontname_menu_item: get font name by menu iid.
@INPUT int iid: the menu item iid.
@OUTPUT tchar_t* buf: the string buffer.
@INPUT int max: the string buffer size in characters.
@RETURN void: none.
*/
EXP_API void fontname_menu_item(int iid, tchar_t* buf, int max);

/*
@FUNCTION fontsize_menu: create a font size menu.
@INPUT res_win_t widget: the owner widget.
@INPUT dword_t idc: the menu control id.
@INPUT const xpoint_t* ppt: the based position.
@INPUT int lay: the layout mode, it can be WS_LAYOUT_LEFTTOP, WS_LAYOUT_RIGHTTOP, WS_LAYOUT_LEFTBOTTOM, WS_LAYOUT_RIGHTBOTTOM.
@RETURN void: none.
*/
EXP_API void fontsize_menu(res_win_t widget, dword_t idc, const xpoint_t* ppt, int lay);

/*
@FUNCTION fontsize_menu_item: get font size by menu iid.
@INPUT int iid: the menu item iid.
@OUTPUT tchar_t* buf: the string buffer.
@INPUT int max: the string buffer size in characters.
@RETURN void: none.
*/
EXP_API void fontsize_menu_item(int iid, tchar_t* buf, int max);

/*
@FUNCTION fontstyle_menu: create a font style menu.
@INPUT res_win_t widget: the owner widget.
@INPUT dword_t idc: the menu control id.
@INPUT const xpoint_t* ppt: the based position.
@INPUT int lay: the layout mode, it can be WS_LAYOUT_LEFTTOP, WS_LAYOUT_RIGHTTOP, WS_LAYOUT_LEFTBOTTOM, WS_LAYOUT_RIGHTBOTTOM.
@RETURN void: none.
*/
EXP_API void fontstyle_menu(res_win_t widget, dword_t idc, const xpoint_t* ppt, int lay);

/*
@FUNCTION fontstyle_menu_item: get font style by menu iid.
@INPUT int iid: the menu item iid.
@OUTPUT tchar_t* buf: the string buffer.
@INPUT int max: the string buffer size in characters.
@RETURN void: none.
*/
EXP_API void fontstyle_menu_item(int iid, tchar_t* buf, int max);

/*
@FUNCTION fontweight_menu: create a font weight menu.
@INPUT res_win_t widget: the owner widget.
@INPUT dword_t idc: the menu control id.
@INPUT const xpoint_t* ppt: the based position.
@INPUT int lay: the layout mode, it can be WS_LAYOUT_LEFTTOP, WS_LAYOUT_RIGHTTOP, WS_LAYOUT_LEFTBOTTOM, WS_LAYOUT_RIGHTBOTTOM.
@RETURN void: none.
*/
EXP_API void fontweight_menu(res_win_t widget, dword_t idc, const xpoint_t* ppt, int lay);

/*
@FUNCTION fontweight_menu_item: get font weight by menu iid.
@INPUT int iid: the menu item iid.
@OUTPUT tchar_t* buf: the string buffer.
@INPUT int max: the string buffer size in characters.
@RETURN void: none.
*/
EXP_API void fontweight_menu_item(int iid, tchar_t* buf, int max);

/*
@FUNCTION color_menu: create a color menu.
@INPUT res_win_t widget: the owner widget.
@INPUT dword_t idc: the menu control id.
@INPUT const xpoint_t* ppt: the based position.
@INPUT int lay: the layout mode, it can be WS_LAYOUT_LEFTTOP, WS_LAYOUT_RIGHTTOP, WS_LAYOUT_LEFTBOTTOM, WS_LAYOUT_RIGHTBOTTOM.
@RETURN void: none.
*/
EXP_API void color_menu(res_win_t widget, dword_t idc, const xpoint_t* ppt, int lay);

/*
@FUNCTION color_menu_item: get color by menu iid.
@INPUT int iid: the menu item iid.
@OUTPUT tchar_t* buf: the string buffer.
@INPUT int max: the string buffer size in characters.
@RETURN void: none.
*/
EXP_API void color_menu_item(int iid, tchar_t* buf, int max);

/*
@FUNCTION shape_menu: create a shape menu.
@INPUT res_win_t widget: the owner widget.
@INPUT dword_t idc: the menu control id.
@INPUT const xpoint_t* ppt: the based position.
@INPUT int lay: the layout mode, it can be WS_LAYOUT_LEFTTOP, WS_LAYOUT_RIGHTTOP, WS_LAYOUT_LEFTBOTTOM, WS_LAYOUT_RIGHTBOTTOM.
@RETURN void: none.
*/
EXP_API void shape_menu(res_win_t widget, dword_t idc, const xpoint_t* ppt, int lay);

/*
@FUNCTION shape_menu_item: get shape by menu iid.
@INPUT int iid: the menu item iid.
@OUTPUT tchar_t* buf: the string buffer.
@INPUT int max: the string buffer size in characters.
@RETURN void: none.
*/
EXP_API void shape_menu_item(int iid, tchar_t* buf, int max);

/*
@FUNCTION track_popup_menu: create a menu widget by menu document.
@INPUT res_win_t widget: the owner widget.
@INPUT dword_t idc: the menu control id.
@INPUT link_t_ptr menu: the menu document.
@INPUT const xpoint_t* ppt: the based position.
@INPUT int lay: the layout mode, it can be WS_LAYOUT_LEFTTOP, WS_LAYOUT_RIGHTTOP, WS_LAYOUT_LEFTBOTTOM, WS_LAYOUT_RIGHTBOTTOM.
@RETURN void: none.
*/
EXP_API void track_popup_menu(res_win_t widget, dword_t idc, link_t_ptr menu, const xpoint_t* ppt, int lay);

#ifdef	__cplusplus
}
#endif

#endif /*XDCMENU_H*/
