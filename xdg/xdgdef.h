/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc defination document

	@module	xdgdef.h | interface file

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


#ifndef _XGCDEF_H
#define	_XGCDEF_H

#include <xdk.h>

//#define XGC_USE_GB2312_GLYPH

/*driver type*/
#define _DRIVER_MONOCHROME	0x31
#define _DRIVER_GRAYSCALE	0x32
#define _DRIVER_COLOR555	0x33
#define _DRIVER_COLOR888	0x34
#define _DRIVER_COLOR8888	0x35
typedef struct _handle_head	 *driver_t;

/*device type*/
#define _DEVICE_BITMAP		0x3A
#define _DEVICE_PIXMAP		0x3B
typedef struct _handle_head	 *device_t;

/*visual type*/
#define _VISUAL_DISPLAY		0x40
#define _VISUAL_PRINTER		0x41
#define _VISUAL_SCRIPT		0x42
#define _VISUAL_MEMORY		0x43
typedef struct _handle_head	 *visual_t;

/*canvas type*/
#define _CANVAS_DISPLAY		0x4A
#define _CANVAS_PRINTER		0x4B
typedef struct _handle_head *canvas_t;

#define _HANDLE_GLYPH		0x50
typedef struct _handle_head	*glyph_t;

#define _HANDLE_FONTSET		0x51
typedef struct _handle_head	 *fontset_t;

#define _HANDLE_BITMAP		0x52
typedef struct _handle_head	 *bitmap_t;

typedef enum{ 
	NONE_BREAK = 0, 
	WORD_BREAK = 1, 
	LINE_BREAK = 2
}WRAPMODE;

#define UNIT_PT				_T("pt")
#define UNIT_PX				_T("px")
#define UNIT_MM				_T("mm")

#define ZERO_WIDTH				0.0f
#define ZERO_HEIGHT				0.0f

#define PAPER_A4_WIDTH			210.0f
#define PAPER_A4_HEIGHT			297.0f

#define PAPER_A5_WIDTH			148.0f
#define PAPER_A5_HEIGHT			210.0f

#define PAPER_LETTER_WIDTH		210.0f
#define PAPER_LETTER_HEIGHT		280.0f

#define PAPER_MIN_WIDTH			2.6f
#define PAPER_MIN_HEIGHT		2.6f

#define PAPER_MAX_WIDTH			280.0f
#define PAPER_MAX_HEIGHT		558.7f

#define DEF_PAPER_WIDTH			PAPER_A4_WIDTH
#define DEF_PAPER_HEIGHT		PAPER_A4_HEIGHT

#include "gob/gobdef.h"
#include "gob/gobattr.h"
#include "inf/drwinf.h"

#endif	/* _XGCDEF_H */

