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

#include "_if_wince.h"


int wceContextVersion(void)
{
	int nVer;

	nVer = 4;

	return nVer;
}

int wceContextStartup()
{
	int nVer;

	nVer = 4;

	wceGdiInit(nVer);

	return nVer;
}

void wceContextCleanup(void)
{
	wceGdiUnInit();
}

visual_t wceCreateDisplayContext(widget_t wt)
{
	wince_widget_t* pws = (wince_widget_t*)wt;
	wince_context_t* ctx = NULL;

	ctx = (wince_context_t*)xmem_alloc_handle(sizeof(wince_context_t));
	ctx->head.tag = _VISUAL_DISPLAY;

	if (pws && IsWindow(pws->self))
	{
		ctx->device.window = pws->self;
		ctx->context = GetWindowDC(pws->self);
		ctx->type = CONTEXT_WIDGET;
	}
	else
	{
		ctx->context = CreateDC(_T("DISPLAY"), NULL, NULL, NULL);
		ctx->type = CONTEXT_SCREEN;
	}

	ctx->fontset = g_fontset;

	return (visual_t)&(ctx->head);
}

visual_t wceCreateCompatibleContext(visual_t rdc, int cx, int cy)
{
	wince_context_t* org = (wince_context_t*)rdc;
	wince_context_t* ctx = NULL;
	HBITMAP bmp;

	ctx = (wince_context_t*)xmem_alloc_handle(sizeof(wince_context_t));
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

void wceDestroyContext(visual_t rdc)
{
	wince_context_t* ctx = (wince_context_t*)rdc;
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

void wceGetDeviceCaps(visual_t rdc, dev_cap_t* pcap)
{
	wince_context_t* ctx = (wince_context_t*)rdc;

	pcap->horz_res = GetDeviceCaps(ctx->context, HORZRES);
	pcap->vert_res = GetDeviceCaps(ctx->context, VERTRES);

	pcap->horz_pixels = GetDeviceCaps(ctx->context, LOGPIXELSX);
	pcap->vert_pixels = GetDeviceCaps(ctx->context, LOGPIXELSY);

	pcap->horz_size = GetDeviceCaps(ctx->context, PHYSICALWIDTH);
	pcap->vert_size = GetDeviceCaps(ctx->context, PHYSICALHEIGHT);

	pcap->horz_feed = GetDeviceCaps(ctx->context, PHYSICALOFFSETX);
	pcap->vert_feed = GetDeviceCaps(ctx->context, PHYSICALOFFSETY);
}

void wceRenderContext(visual_t src, int srcx, int srcy, visual_t dst, int dstx, int dsty, int dstw, int dsth)
{
	wince_context_t* src_ctx = (wince_context_t*)src;
	wince_context_t* dst_ctx = (wince_context_t*)dst;

	BitBlt(dst_ctx->context, dstx, dsty, dstw, dsth, src_ctx->context, srcx, srcy, SRCCOPY);
}

/*******************************************************************************************************************/

static int MulDiv(int a, int b, int c)
{
	return (int)((float)a * (float)b / (float)c);
}

float _pixel_metric(visual_t rdc)
{
	wince_context_t* ctx = (wince_context_t*)rdc;
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

