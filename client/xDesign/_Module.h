/***********************************************************************
	Easily xDesign v3.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, China ZheJiang HangZhou JianDe, Mail: powersuite@hotmaol.com

	@doc xDesign interface document

	@module	xDesign interface file

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

#pragma once

#include <xdk.h>
#include <xdn.h>
#include <xdg.h>
#include <xdu.h>
#include <xdl.h>
#include <xdb.h>
#include <xdc.h>

extern widget_t		g_hMain;
extern tchar_t		g_szRunPath[PATH_LEN + 1];
extern LINKPTR		g_imagelist;

typedef struct _FACE_STYLE{
	tchar_t title[10];
	tchar_t bkg[CLR_LEN + 1];
	tchar_t frg[CLR_LEN + 1];
	tchar_t txt[CLR_LEN + 1];
	tchar_t msk[CLR_LEN + 1];
	tchar_t ico[CLR_LEN + 1];
}FACE_STYLE;

#define FACE_COUNT	6

static FACE_STYLE g_face[FACE_COUNT] = {
	{ _T("太空黑"), GDI_ATTR_RGB_SLATEBLACK, GDI_ATTR_RGB_DARKSLATE, GDI_ATTR_RGB_LIGHTSLATE, GDI_ATTR_RGB_SOFTWHITE, GDI_ATTR_RGB_LIGHTGREEN },
	{ _T("春天绿"), GDI_ATTR_RGB_LIGHTGREEN, GDI_ATTR_RGB_DARKGREEN, GDI_ATTR_RGB_MONOBLACK, GDI_ATTR_RGB_SOFTWHITE, GDI_ATTR_RGB_GREEN },
	{ _T("土豪金"), GDI_ATTR_RGB_SOFTYELLOW, GDI_ATTR_RGB_SNOWWHITE, GDI_ATTR_RGB_MONOBLACK, GDI_ATTR_RGB_SOFTWHITE, GDI_ATTR_RGB_SLATEGRAY },
	{ _T("喜庆红"), GDI_ATTR_RGB_LIGHTRED, GDI_ATTR_RGB_LIGHTCYAN, GDI_ATTR_RGB_MONOBLACK, GDI_ATTR_RGB_SOFTWHITE, GDI_ATTR_RGB_SLATEGRAY },
	{ _T("淡雅青"), GDI_ATTR_RGB_LIGHTPURPLE, GDI_ATTR_RGB_SOFTSLATE, GDI_ATTR_RGB_MONOBLACK, GDI_ATTR_RGB_SOFTWHITE, GDI_ATTR_RGB_LIGHTBLACK },
	{ _T("经典白"), GDI_ATTR_RGB_WHITE, GDI_ATTR_RGB_DARKGRAY, GDI_ATTR_RGB_BLACK, GDI_ATTR_RGB_WHITE, GDI_ATTR_RGB_DARKGRAY }
};

extern int g_indFace;

#define PERFERENCE_FACE		_T("FACE")

#define COLOR_TABLE_SIZE	17

static tchar_t COLOR_TABLE[COLOR_TABLE_SIZE][CLR_LEN + 1] = {
	GDI_ATTR_RGB_WHITE,
	GDI_ATTR_RGB_GRAY,
	GDI_ATTR_RGB_RED,
	GDI_ATTR_RGB_PURPLE,
	GDI_ATTR_RGB_GREEN,
	GDI_ATTR_RGB_BLUE,
	GDI_ATTR_RGB_CYAN,
	GDI_ATTR_RGB_YELLOW,
	GDI_ATTR_RGB_BLACK,
	GDI_ATTR_RGB_SOFTWHITE,
	GDI_ATTR_RGB_SOFTGRAY,
	GDI_ATTR_RGB_SOFTPURPLE,
	GDI_ATTR_RGB_SOFTGREEN,
	GDI_ATTR_RGB_SOFTBLUE,
	GDI_ATTR_RGB_SOFTCYAN,
	GDI_ATTR_RGB_SOFTYELLOW,
	GDI_ATTR_RGB_SOFTBLACK
};

void	SavePreference(const tchar_t* sec, const tchar_t* key, const tchar_t* val);

void	LoadPreference(const tchar_t* sec, const tchar_t* key, tchar_t* val);

int		ShowMsg( dword_t mid, const tchar_t* text);

int		DoInput(const tchar_t* title, tchar_t* buf, int max);