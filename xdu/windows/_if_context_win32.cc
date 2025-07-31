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

#ifdef XDU_SUPPORT_CONTEXT

#ifndef WINCE
#include <Lm.h>
#pragma comment(lib,"Netapi32.lib")
#endif

int _context_version(void)
{
	int nVer;

#ifdef WINCE
	nVer = 4;
#else
	WKSTA_INFO_100 *pbuf = NULL;
	nVer = 5;
	if (NERR_Success == NetWkstaGetInfo(NULL, 100, (LPBYTE *)&pbuf))
	{
		nVer = pbuf->wki100_ver_major;
	}

	if (pbuf)
	{
		NetApiBufferFree(pbuf);
	}
#endif

	return nVer;
}

int _context_startup()
{
	int nVer;

#ifdef WINCE
	nVer = 4;
#else
	WKSTA_INFO_100 *pbuf = NULL;
	nVer = 5;
	if (NERR_Success == NetWkstaGetInfo(NULL, 100, (LPBYTE *)&pbuf))
	{
		nVer = pbuf->wki100_ver_major;
	}

	if (pbuf)
	{
		NetApiBufferFree(pbuf);
	}
#endif

#ifdef XDU_SUPPORT_CONTEXT_GDI
	_gdi_init(nVer);
#endif

#ifdef XDU_SUPPORT_CONTEXT_GDIPLUS
	_gdiplus_init(nVer);
#endif

#ifdef XDU_SUPPORT_CONTEXT_CAIRO
	_cairo_init(nVer);
#endif

	return nVer;
}

void _context_cleanup(void)
{
#ifdef XDU_SUPPORT_CONTEXT_GDI
	_gdi_uninit();
#endif

#ifdef XDU_SUPPORT_CONTEXT_GDIPLUS
	_gdiplus_uninit();
#endif

#ifdef XDU_SUPPORT_CONTEXT_CAIRO
	_cairo_uninit();
#endif
}

visual_t _create_display_context(widget_t wt)
{
	win32_widget_t* pws = (win32_widget_t*)wt;
	win32_context_t* ctx = NULL;

	ctx = (win32_context_t*)xmem_alloc_handle(sizeof(win32_context_t));
	ctx->head.tag = _VISUAL_DISPLAY;

	if (pws && IsWindow(pws->self))
	{
		ctx->device.window = pws->self;
		ctx->context = GetWindowDC(pws->self);
		ctx->type = CONTEXT_WIDGET;
	}
	else
	{
#ifdef WINCE
		ctx->context = CreateDC(_T("DISPLAY"), NULL, NULL, NULL);
#else
		ctx->context = CreateIC(_T("DISPLAY"), NULL, NULL, NULL);
#endif
		ctx->type = CONTEXT_SCREEN;
	}

	return (visual_t)&(ctx->head);
}

visual_t _create_compatible_context(visual_t rdc, int cx, int cy)
{
	win32_context_t* org = (win32_context_t*)rdc;
	win32_context_t* ctx = NULL;
	HBITMAP bmp;

	ctx = (win32_context_t*)xmem_alloc_handle(sizeof(win32_context_t));
	ctx->head.tag = _VISUAL_DISPLAY;

	ctx->context = CreateCompatibleDC(org->context);
	if (ctx->context)
		SetBkMode(ctx->context, TRANSPARENT);

	bmp = CreateCompatibleBitmap(org->context, cx, cy);

	ctx->device.bitmap = (HBITMAP)SelectObject(ctx->context, (HGDIOBJ)bmp);
	ctx->type = CONTEXT_MEMORY;

	return (visual_t)&(ctx->head);
}

void _destroy_context(visual_t rdc)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HBITMAP bmp;

	switch (ctx->type)
	{
	case CONTEXT_WIDGET:
		ReleaseDC(ctx->device.window, ctx->context);
		break;
	case CONTEXT_MEMORY:
		bmp = (HBITMAP)SelectObject(ctx->context, (HGDIOBJ)ctx->device.bitmap);
		DeleteObject(bmp);

		DeleteDC(ctx->context);
		break;
	case CONTEXT_SCREEN:
		DeleteDC(ctx->context);
		break;
	case CONTEXT_PRINTER:
		DeleteDC(ctx->context);
		break;
	}

	//xmem_free_handle((xhand_t)rdc);
}

void _get_device_caps(visual_t rdc, dev_cap_t* pcap)
{
	win32_context_t* ctx = (win32_context_t*)rdc;

	pcap->horz_res = GetDeviceCaps(ctx->context, HORZRES);
	pcap->vert_res = GetDeviceCaps(ctx->context, VERTRES);

	pcap->horz_pixels = GetDeviceCaps(ctx->context, LOGPIXELSX);
	pcap->vert_pixels = GetDeviceCaps(ctx->context, LOGPIXELSY);

	pcap->horz_size = GetDeviceCaps(ctx->context, PHYSICALWIDTH);
	pcap->vert_size = GetDeviceCaps(ctx->context, PHYSICALHEIGHT);

	pcap->horz_feed = GetDeviceCaps(ctx->context, PHYSICALOFFSETX);
	pcap->vert_feed = GetDeviceCaps(ctx->context, PHYSICALOFFSETY);
}

void _render_context(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth)
{
	win32_context_t* src_ctx = (win32_context_t*)src;
	win32_context_t* dst_ctx = (win32_context_t*)dst;

	BitBlt(dst_ctx->context, dstx, dsty, dstw, dsth, src_ctx->context, srcx, srcy, SRCCOPY);
}

/*******************************************************************************************************************/
#ifdef WINCE
static int MulDiv(int a, int b, int c)
{
	return (int)((float)a * (float)b / (float)c);
}
#endif

float _pixel_metric(visual_t rdc)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (rdc)? (HDC)(ctx->context) : GetDC(NULL);
	float fp;

	fp = (float)((float)GetDeviceCaps(hDC, HORZSIZE) / (float)GetDeviceCaps(hDC, HORZRES));
	
	if (!rdc)
		ReleaseDC(NULL, hDC);

	return fp;
}

float _font_metric(visual_t rdc, const xfont_t* pxf)
{
	float pt = xstof(pxf->size);
	float pm = 0.0f;

	font_metric_by_pt(pt, &pm, NULL);

	return pm;
}

#endif //XDU_SUPPORT_CONTEXT
