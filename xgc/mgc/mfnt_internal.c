/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc memory font document

	@module	mfnt_internal.c | implement file

	@devnote 张文权 2021.01 - 2021.12 v6.0
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

#include "mfnt.h"
#include "mpix.h"

#include "../xgcobj.h"

typedef struct _font_internal_t{
	handle_head head;

	const glyph_info_t* a_font_glyph;
	const glyph_info_t* c_font_glyph;

}font_internal_t;

static font_t create_font(const xfont_t* pxf)
{
	font_internal_t* pfnt;

	pfnt = (font_internal_t*)xmem_alloc(sizeof(font_internal_t));
	pfnt->head.tag = _HANDLE_FONT;

	pfnt->a_font_glyph = find_glyph_info(CHARSET_ASCII, pxf);
	pfnt->c_font_glyph = find_glyph_info(CHARSET_GB2312, pxf);

	return &(pfnt->head);
}

static void destroy_font(font_t fnt)
{
	font_internal_t* pfnt = (font_internal_t*)fnt;

	XDK_ASSERT(fnt && fnt->tag == _HANDLE_FONT);

	xmem_free(pfnt);
}

static void get_font_info(font_t fnt, xfont_t* pxf)
{
	font_internal_t* pfnt = (font_internal_t*)fnt;

	XDK_ASSERT(fnt && fnt->tag == _HANDLE_FONT);

	xfont_from_glyph_info(pxf, pfnt->c_font_glyph);
}

static void get_font_metrix(font_t fnt, const tchar_t* str, font_metrix_t* pmetrix)
{
	font_internal_t* pfnt = (font_internal_t*)fnt;
	glyph_metrix_t gm = { 0 };

	XDK_ASSERT(fnt && fnt->tag == _HANDLE_FONT);

	if(str && is_ascii(str[0]))
		get_glyph_metrix(pfnt->a_font_glyph, str, &gm);
	else
		get_glyph_metrix(pfnt->c_font_glyph, str, &gm);

	if(pmetrix)
	{
		pmetrix->width = gm.width;
		pmetrix->height = gm.height;
	}
}

static void get_char_size(font_t fnt, const tchar_t *str, xsize_t* pse)
{
	font_internal_t* pfnt = (font_internal_t*)fnt;
	glyph_metrix_t gm = { 0 };

	XDK_ASSERT(fnt && fnt->tag == _HANDLE_FONT);

	if(str && is_ascii(str[0]))
		get_glyph_metrix(pfnt->a_font_glyph, str, &gm);
	else
		get_glyph_metrix(pfnt->c_font_glyph, str, &gm);

	if (pse)
	{
		pse->w = gm.width;
		pse->h = gm.height;
	}
}

static int get_char_pixmap(font_t fnt, const tchar_t* str, mem_pixmap_ptr ppixmap)
{
	font_internal_t* pfnt = (font_internal_t*)fnt;

	XDK_ASSERT(fnt && fnt->tag == _HANDLE_FONT);

	if(str && is_ascii(str[0]))
		return get_glyph_pixmap(pfnt->a_font_glyph, str, ppixmap->data);
	else
		return get_glyph_pixmap(pfnt->c_font_glyph, str, ppixmap->data);
}

/*****************************************************************************************************************/

mem_font_t font_Internal = {
	create_font,
	destroy_font,
	get_font_info,
	get_font_metrix,
	get_char_size,
	get_char_pixmap,
};

