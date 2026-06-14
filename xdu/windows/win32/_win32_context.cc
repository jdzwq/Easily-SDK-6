/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc device context document

	@module	if_context_win32.c | windows implement file

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

#include "_if_win32.h"

#include <Lm.h>
#pragma comment(lib,"Netapi32.lib")

static int _context_version(void)
{
	int nVer;

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

	return nVer;
}

int winContextStartup()
{
	int nVer;

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

	winGdiInit(nVer);

	return nVer;
}

void winContextCleanup(void)
{
	winGdiUnInit();
}

visual_t winCreateDisplayContext(widget_t wt)
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
		ctx->context = CreateIC(_T("DISPLAY"), NULL, NULL, NULL);
		ctx->type = CONTEXT_SCREEN;
	}

	ctx->fontset = g_fontset;

	return (visual_t)&(ctx->head);
}

visual_t winCreateCompatibleContext(visual_t rdc, int cx, int cy)
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

	ctx->fontset = g_fontset;

	return (visual_t)&(ctx->head);
}

void winDestroyContext(visual_t rdc)
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

	xmem_free_handle((xhand_t)ctx);
}

void winGetDeviceCaps(visual_t rdc, dev_cap_t* pcap)
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

void winRenderContext(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth)
{
	win32_context_t* src_ctx = (win32_context_t*)src;
	win32_context_t* dst_ctx = (win32_context_t*)dst;

	BitBlt(dst_ctx->context, dstx, dsty, dstw, dsth, src_ctx->context, srcx, srcy, SRCCOPY);
}

/*******************************************************************************************************************/

float _pixel_metric(visual_t rdc)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (rdc)? (HDC)(ctx->context) : GetDC(NULL);
	float fp;

	fp = MMPERINCH / (float)GetDeviceCaps(hDC, LOGPIXELSX);

	if (!rdc)
		ReleaseDC(NULL, hDC);

	return fp;
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

