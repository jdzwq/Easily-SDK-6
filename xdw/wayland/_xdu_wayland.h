/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc xdu linux definition document

	@module	_xdu_wayland.h | wayland interface file

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

#ifndef _XDU_WAYLAND_H
#define _XDU_WAYLAND_H


#define XDU_SUPPORT_SHELL
#define XDU_SUPPORT_CONTEXT
#define XDU_SUPPORT_CONTEXT_BITMAP
#define XDU_SUPPORT_CONTEXT_GDI

//#define XDU_SUPPORT_CLIPBOARD
#define XDU_SUPPORT_WIDGET

#ifdef XDU_SUPPORT_CONTEXT
#include <wayland-client.h>
#include "xdg-shell-client-protocol.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT

extern struct wl_display* g_disp;
extern struct wl_registry* g_regs;
extern struct wl_compositor* g_comp;
extern struct wl_shm* g_shm;
extern struct xdg_wm_base* g_base;

#endif

#define SYSTEM_FONTNAME     _T("Simsun")

#endif //_XDU_WAYLAND_H