/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc device context document

	@module	if_context_win.c | windows implement file

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

#if defined(_WCE)
#include "wince/_if_wince.h"
#elif defined(_W32)
#include "win32/_if_win32.h"
#endif

#ifdef XDU_SUPPORT_CONTEXT

int _context_startup(void)
{
#if defined(WINCE)
	return wceContextStartup();
#elif defined(WIN32)
	return winContextStartup();
#endif
}

void _context_cleanup(void)
{
#if defined(WINCE)
	wceContextCleanup();
#elif defined(WIN32)
	winContextCleanup();
#endif
}

visual_t _create_display_context(widget_t wt)
{
#if defined(WINCE)
	return wceCreateDisplayContext(wt);
#elif defined(WIN32)
	return winCreateDisplayContext(wt);
#endif
}

visual_t _create_compatible_context(visual_t rdc, int cx, int cy)
{
#if defined(WINCE)
	return wceCreateCompatibleContext(rdc, cx, cy);
#elif defined(WIN32)
	return winCreateCompatibleContext(rdc, cx, cy);
#endif
}

void _destroy_context(visual_t rdc)
{
#if defined(WINCE)
	wceDestroyContext(rdc);
#elif defined(WIN32)
	winDestroyContext(rdc);
#endif
}

void _get_device_caps(visual_t rdc, dev_cap_t* pcap)
{
#if defined(WINCE)
	wceGetDeviceCaps(rdc, pcap);
#elif defined(WIN32)
	winGetDeviceCaps(rdc, pcap);
#endif
}

void _render_context(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth)
{
#if defined(WINCE)
	wceRenderContext(src, srcx, srcy, dst, dstx, dsty, dstw, dsth);
#elif defined(WIN32)
	winRenderContext(src, srcx, srcy, dst, dstx, dsty, dstw, dsth);
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
