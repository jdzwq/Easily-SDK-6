/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu windows definition document

	@module	_xdu_win.h | windows interface file

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

#ifndef _XDU_WIN32_H
#define _XDU_WIN32_H

#define XDU_SUPPORT_SHELL
#define XDU_SUPPORT_CLIPBOARD

#define XDU_SUPPORT_CONTEXT_BITMAP
#define XDU_SUPPORT_CONTEXT_PRINTER
//#define XDU_SUPPORT_CONTEXT_OPENGL
#define XDU_SUPPORT_CONTEXT_GDI
#define XDU_SUPPORT_CONTEXT

#define XDU_SUPPORT_WIDGET
//#define XDU_SUPPORT_WIDGET_NC

#if defined(WINCE)
#undef XDU_SUPPORT_CONTEXT_BITMAP_THUMB
#undef XDU_SUPPORT_CONTEXT_PRINTER
#undef XDU_SUPPORT_WIDGET_NC
#undef XDU_SUPPORT_WIDGET_REGION
#undef XDU_SUPPORT_SHELL
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif

#define _WIN32_WINNT    0x0600

#ifdef WINVER
#undef WINVER
#endif

#if defined(WINCE) 
#define WINVER			_WIN32_WCE 
#else
#define WINVER			0x0501
#endif

#ifndef OEMRESOURCE 
#define OEMRESOURCE 
#endif

#ifndef STRICT
#define STRICT
#endif

#include <stdio.h>
#include <tchar.h>
#include <math.h>
#include <time.h>

#ifdef XDU_SUPPORT_CONTEXT
#include <ole2.h>
#include <olectl.h>
#endif
#ifdef XDU_SUPPORT_WIDGET
#include <commctrl.h>
#endif
#ifdef XDU_SUPPORT_SHELL
#include <ShellAPI.h>
#include <ShlObj.h>
#endif


#ifdef XDU_SUPPORT_CONTEXT_OPENGL
#include <gl/GL.h>
#include <gl/GLU.h>
#endif

#ifndef uid_t
typedef unsigned int	uid_t;
#endif

#ifdef XDU_SUPPORT_WIDGET
typedef struct _win32_widget_t{
	handle_head head;

	uid_t uid;
	HWND self;
	HWND parent;
	HWND owner;
	HACCEL accel;
	
	dword_t style;
	int mode;
	int result;
	int retcode;

	scroll_t hs;
	scroll_t vs;
	color_mod_t clrs;
}win32_widget_t;

typedef COLORREF	pixel_t;
#endif

#ifdef XDU_SUPPORT_CONTEXT

//global fonstset cache
extern fontset_t g_fontset;

typedef struct _win32_context_t{
	handle_head head;

	HDC context;
	union
	{
		HBITMAP bitmap;
		HWND window;
	}device;
	int type;

	fontset_t fontset;
}win32_context_t;

typedef struct _win32_fontset_t{
	handle_head head;

    void* font_object;
}win32_fontset_t;

#ifdef XDU_SUPPORT_CONTEXT_BITMAP
typedef struct _win32_bitmap_t{
	handle_head head;

	HBITMAP bitmap;
}win32_bitmap_t;
#endif

#ifdef XDU_SUPPORT_CONTEXT_OPENGL
typedef struct _win32_glrc_t{
	handle_head head;

	HGLRC glrc;
}win32_glrc_t;

#endif
#endif

#ifdef XDU_SUPPORT_CLIPBOARD

/*clipboard format*/
#define CB_FORMAT_MBS		CF_TEXT
#define CB_FORMAT_UCS		CF_UNICODETEXT
#define CB_FORMAT_DIB		CF_DIB

#ifdef _UNICODE
#define DEF_CB_FORMAT		CB_FORMAT_UCS
#else
#define DEF_CB_FORMAT		CB_FORMAT_MBS
#endif
#endif

#ifdef XDU_SUPPORT_WIDGET
#define WM_EASYMSG_MIN		WM_USER + 10
#define WM_EASYMSG_MAX		WM_USER  + 100
#endif

#define SYSTEM_FONTNAME     _T("Microsoft YaHei")
//#define SYSTEM_FONTNAME     _T("SimSun")

#endif //_XDU_WIN32_H