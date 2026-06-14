/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc context document

	@module	if_context.c | linux implement file

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

#include "../xduloc.h"

#if defined(_X11)
#include "X11/_if_x11.h"
#elif defined(_WAYLAND)
#include "wayland/_if_wayland.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT

int _context_startup(void)
{
#if defined(_X11)
	return xlContextStartup();
#elif defined(_WAYLAND)
	return wlContextStartup();
#endif
}

void _context_cleanup(void)
{
#if defined(_X11)
	xlContextCleanup();
#elif defined(_WAYLAND)
	wlContextCleanup();
#endif
}

visual_t _create_display_context(widget_t wt)
{
#if defined(_X11)
	return xlCreateDisplayContext(wt);
#elif defined(_WAYLAND)
	return wlCreateDisplayContext(wt);
#endif
}

visual_t _create_compatible_context(visual_t rdc, int cx, int cy)
{
#if defined(_X11)
	return xlCreateCompatibleContext(rdc, cx, cy);
#elif defined(_WAYLAND)
	return wlCreateCompatibleContext(rdc, cx, cy);
#endif
}

void _destroy_context(visual_t rdc)
{
#if defined(_X11)
	xlDestroyContext(rdc);
#elif defined(_WAYLAND)
	wlDestroyContext(rdc);
#endif
}

void _get_device_caps(visual_t rdc, dev_cap_t* pcap)
{
#if defined(_X11)
	xlGetDeviceCaps(rdc, pcap);
#elif defined(_WAYLAND)
	wlGetDeviceCaps(rdc, pcap);
#endif
}

void _render_context(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth)
{
#if defined(_X11)
	xlRenderContext(src, srcx, srcy, dst, dstx, dsty, dstw, dsth);
#elif defined(_WAYLAND)
	wlRenderContext(src, srcx, srcy, dst, dstx, dsty, dstw, dsth);
#endif
}

float _pixel_metric(visual_t rdc)
{
	return LOGMMPERPT;
}

float _font_metric(visual_t rdc, const tchar_t* xf_size)
{
	const tchar_t* tk;
	int len;
	float pt, pm = 0.0f;

	tk = xsistr(xf_size, _T("px"));
	if(tk)
	{
		pt = xsntof(xf_size, (int)(tk - xf_size));
		font_metric_by_px(pt, &pm, NULL);
	}
	else
	{
		pt = xstof(xf_size);
		font_metric_by_pt(pt, &pm, NULL);
	}

	return pm;
}

#endif //XDU_SUPPORT_CONTEXT
