﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc texting document

	@module	coding.h | interface file

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

#ifndef _TEXTING_H
#define _TEXTING_H

#include "../xdldef.h"


#ifdef	__cplusplus
extern "C" {
#endif

/*
@FUNCTION calc_text_rect: calc the text suitable rectangle in canvas using millimeter coordinate.
@INPUT drawing_interface* pif: the canvas interface.
@INPUT cont xfont_t* pxf: the font struct.
@INPUT cont xface_t* pxa: the face struct.
@INPUT cont tchar_t* txt: the text token.
@INPUT int len: the text length in characters, -1 indicate zero character terminated.
@OUTPUT xrect_t* pxr: the rect struct for returning float member.
@RETURN void: none.
*/
EXP_API void	calc_text_rect(const drawing_interface* pif, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* pxr);

/*
@FUNCTION draw_var_text: draw string object in canvas using millimeter coordinate.
@INPUT drawing_interface* pif: the canvas interface.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xface_t* pxa: the face struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT string_t var: the string object.
@RETURN void: none.
*/
EXP_API void	draw_var_text(const drawing_interface* pif, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, string_t var);

/*
@FUNCTION draw_tag_text: draw tag document in canvas using millimeter coordinate.
@INPUT drawing_interface* pif: the canvas interface.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xface_t* pxa: the face struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT link_t_ptr tag: the tag document.
@INPUT int page: the page will be drawed, the page index is 1-based.
@RETURN void: none.
*/
EXP_API void	draw_tag_text(const drawing_interface* pif, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, link_t_ptr tag, int page);

/*
@FUNCTION calc_tag_pages: calc tag document pages in canvas using millimeter coordinate.
@INPUT drawing_interface* pif: the canvas interface.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xface_t* pxa: the face struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT link_t_ptr tag: the tag document.
@RETURN int: return total pages.
*/
EXP_API int		calc_tag_pages(const drawing_interface* pif, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, link_t_ptr memo);

/*
@FUNCTION draw_memo_text: draw memo document in canvas using millimeter coordinate.
@INPUT drawing_interface* pif: the canvas interface.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xface_t* pxa: the face struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT link_t_ptr memo: the memo document.
@INPUT int page: the page will be drawed, the page index is 1-based.
@RETURN void: none.
*/
EXP_API void draw_memo_text(const drawing_interface* pif, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, link_t_ptr memo, int page);

/*
@FUNCTION calc_memo_pages: calc memo document pages in canvas using millimeter coordinate.
@INPUT drawing_interface* pif: the canvas interface.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xface_t* pxa: the face struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT link_t_ptr memo: the memo document.
@RETURN int: return total pages.
*/
EXP_API int		calc_memo_pages(const drawing_interface* pif, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, link_t_ptr memo);

/*
@FUNCTION draw_rich_text: draw rich document in canvas using millimeter coordinate.
@@INPUT drawing_interface* pif: the canvas interface.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xface_t* pxa: the face struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT link_t_ptr rich: the rich document.
@INPUT int page: the page will be drawed, the page index is 1-based.
@RETURN void: none.
*/
EXP_API void	draw_rich_text(const drawing_interface* pif, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, link_t_ptr rich, int page);

/*
@FUNCTION calc_rich_pages: calc rich document pages in canvas using millimeter coordinate.
@INPUT drawing_interface* pif: the canvas interface.
@INPUT const xfont_t* pxf: the font struct.
@INPUT const xface_t* pxa: the face struct.
@INPUT const xrect_t* pxr: the rect struct using float member.
@INPUT link_t_ptr rich: the rich document.
@RETURN int: return total pages.
*/
EXP_API int		calc_rich_pages(const drawing_interface* pif, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, link_t_ptr rich);


#ifdef	__cplusplus
}
#endif


#endif /*SHAPING_H*/