/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc utility document

	@module	xduutil.c | implement file

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

#include "xduutil.h"

void default_widget_color_mode(color_mod_t* pclrs)
{
	parse_xcolor(&(pclrs->clr_bkg), GDI_ATTR_RGB_WHITE);
	parse_xcolor(&(pclrs->clr_frg), GDI_ATTR_RGB_BLACK);
	parse_xcolor(&(pclrs->clr_txt), GDI_ATTR_RGB_BLACK);
	parse_xcolor(&(pclrs->clr_msk), GDI_ATTR_RGB_WHITE);
	parse_xcolor(&(pclrs->clr_ico), GDI_ATTR_RGB_GRAY);
}

void default_widget_xfont(xfont_t* pxf)
{
	default_xfont(pxf);
	
	xscpy(pxf->size, GDI_ATTR_FONT_SIZE_SYSTEM);
	xscpy(pxf->family, SYSTEM_FONTNAME);
}

void default_widget_xface(xface_t* pxa)
{
	default_xface(pxa);
	
	xscpy(pxa->text_color, GDI_ATTR_RGB_DARKBLACK);
	xscpy(pxa->line_height, DEF_GDI_SYSTEM_LINE_HEIGHT);
	xscpy(pxa->text_wrap, _T(""));
}

void default_textor_xfont(xfont_t* pxf)
{
	default_xfont(pxf);
	
	xscpy(pxf->size,GDI_ATTR_FONT_SIZE_TEXT);
	xscpy(pxf->family, SYSTEM_FONTNAME);
}

void default_textor_xface(xface_t* pxa)
{
	default_xface(pxa);
	
	xscpy(pxa->text_color, GDI_ATTR_RGB_BLACK);
	xscpy(pxa->line_height, DEF_GDI_TEXT_LINE_HEIGHT);
	xscpy(pxa->text_wrap, GDI_ATTR_TEXT_WRAP_LINEBREAK);
}