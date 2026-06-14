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

#ifndef _XDU_WINDOWS_H
#define _XDU_WINDOWS_H

#define XDU_SUPPORT_SHELL
#define XDU_SUPPORT_CLIPBOARD
#define XDU_SUPPORT_WIDGET

#define XDU_SUPPORT_CONTEXT
#define XDU_SUPPORT_CONTEXT_BITMAP
#define XDU_SUPPORT_CONTEXT_PRINTER

#ifndef uid_t
typedef unsigned int	uid_t;
#endif

#ifndef pixel_t
typedef COLORREF		pixel_t;
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

#endif //_XDU_WINDOWS_H