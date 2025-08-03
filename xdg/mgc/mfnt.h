/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc memory font document

	@module	mfnt.h | interface file

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

#ifndef _MFNT_H
#define _MFNT_H

#include "mdef.h"
#include "mpix.h"

typedef struct _font_metrix_t {
	int width;		/* Maximum advance width of any character */
	int height;		/* Height of the font, Always equal to (baseline+descent) */
	int ascent;		/* The ascent (height above the baseline) of the font */
	int descent;	/* The descent (height below the baseline) of the font */
	int maxascent;	/* Maximum height of any character above the baseline */
	int maxdescent; /* Maximum height of any character below the baseline */
}font_metrix_t;

typedef struct _mem_font_t* mem_font_ptr;

typedef struct _mem_font_t{
	font_t(*createFont)(const xfont_t* pxf);
	void(*destroyFont)(font_t fnt);
	void(*getFontInfo)(font_t fnt, xfont_t* pxf);
	void(*getFontMetrix)(font_t fnt, const tchar_t* pch, font_metrix_t* pmetrix);
	void(*getCharSize)(font_t fnt, const tchar_t *pch, xsize_t* pse);
	int(*getCharPixmap)(font_t fnt, const tchar_t* pch, mem_pixmap_ptr ppixmap);
} mem_font_t;

extern mem_font_t font_Internal;

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	__cplusplus
}
#endif

#endif /*_MDEV_H*/
