/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu linux definition document

	@module	_xdu_linux.h | linux interface file

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

#ifndef _XDU_LINUX_H
#define _XDU_LINUX_H

#define XDU_SUPPORT_CONTEXT
#define XDU_SUPPORT_CONTEXT_BITMAP
#define XDU_SUPPORT_WIDGET
#define XDU_SUPPORT_CLIPBOARD
#define XDU_SUPPORT_SHELL

#ifdef XDU_SUPPORT_CLIPBOARD
/*clipboard format*/
#define CB_FORMAT_MBS		1
#define CB_FORMAT_UCS		13
#define CB_FORMAT_DIB		8

#ifdef _UNICODE
#define DEF_CB_FORMAT		CB_FORMAT_UCS
#else
#define DEF_CB_FORMAT		CB_FORMAT_MBS
#endif
#endif //XDU_SUPPORT_CLIPBOARD

#define SYSTEM_FONTNAME     _T("Simsun")

#include "wayland/_wayland_test.h"

#endif //_XDU_LINUX_H