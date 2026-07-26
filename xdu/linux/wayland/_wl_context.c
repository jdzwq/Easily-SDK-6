/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc context document

	@module	wl_context.c | wayland implement file

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

#include "_if_wayland.h"


int wlContextStartup(void)
{
	if(!WaylandConnect()) return -1;

	//WaylandGdiInit();

	return 0;
}

void wlContextCleanup(void)
{
	//WaylsndGdiUninit();

	WaylandDisconnect();
}

visual_t wlCreateDisplayContext(widget_t wt)
{
    wayland_widget_t* pxw = TypePtrFromHead(wayland_widget_t, wt);
    wayland_context_t* ctx = NULL;

	return NULL;
}

visual_t wlCreateCompatibleContext(visual_t rdc, int cx, int cy)
{
    return NULL;
}

void wlDestroyContext(visual_t dc)
{
	NOP;
}

void wlGetDeviceCaps(visual_t rdc, dev_cap_t* pcap)
{
    NOP;
}

void wlRenderContext(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth)
{
    NOP;
}
