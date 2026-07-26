/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdi document

	@module	wl_gdi.c | GDI wayland implement file

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

fontset_t g_fontset = NULL;


static void DPtoLP(visual_t rdc, xpoint_t* pt,int n)
{
	int i;
	for(i = 0;i<n;i++)
	{
		pt[i].x = pt[i].x;
		pt[i].y = pt[i].y;
	}
}

static void _adjust_rect(xrect_t* prt, int src_width, int src_height, const tchar_t* horz_align, const tchar_t* vert_align)
{
	if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0 && xscmp(vert_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		NOP;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		prt->y += (prt->h - src_height);
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		prt->x += (prt->w - src_width);
	}
	else if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		prt->x += (prt->w - src_width);
		prt->y += (prt->h - src_height);
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		prt->y += (prt->h - src_height) / 2;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		prt->x += (prt->w - src_width);
		prt->y += (prt->h - src_height) / 2;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		prt->x += (prt->w - src_width) / 2;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		prt->x += (prt->w - src_width) / 2;
		prt->y += (prt->h - src_height);
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		prt->x += (prt->w - src_width) / 2;
		prt->y += (prt->h - src_height) / 2;
	}

	prt->w = (prt->w < src_width) ? prt->w : src_width;
	prt->h = (prt->h < src_height) ? prt->h : src_height;
}

static void _calc_point(const xpoint_t* pt, int r, double a, xpoint_t* pp)
{
	pp->x = pt->x + (int)((float)r * cos(a));
	pp->y = pt->y + (int)((float)r * sin(a));
}

static void calc_penmode(const xpen_t* pxp, int* fs, int* ds)
{
	*fs = xsisnil(pxp->size) ? 1 : xstol(pxp->size);

	if (compare_text(pxp->style, -1, GDI_ATTR_STROKE_STYLE_DASH, -1, 1) == 0)
		*ds = DOT_DASH;
	else if (compare_text(pxp->style, -1, GDI_ATTR_STROKE_STYLE_DASHDASH, -1, 1) == 0)
		*ds = DOT_DASHDASH;
	else if (compare_text(pxp->style, -1, GDI_ATTR_STROKE_STYLE_DASHDASHDASH, -1, 1) == 0)
		*ds = DOT_DASHDASHDASH;
	else
		*ds = DOT_SOLID;
}

/************************************************************************************************/

void wlGdiInit(int osv)
{
	xfont_t xf;

	default_xfont(&xf);
	g_fontset = wlGdiCreateFontset(&xf);
}

void wlGdiUnInit(void)
{
	if(g_fontset) wlGdiDestroyFontset(g_fontset);

	g_fontset = NULL;
}

void wlGdiSetXFont(visual_t rdc, const xfont_t* pxf)
{
	NOP;
}

void wlGdiGetXFont(visual_t rdc, xfont_t* pxf)
{
	NOP;
}

void wlGdiGetPoint(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt)
{
	NOP;
}

void wlGdiSetPoint(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt)
{
	NOP;
}

void wlGdiDrawPoints(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n)
{
	NOP;
}

void wlGdiDrawLine(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2)
{
	NOP;
}

void wlGdiDrawPolyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n)
{
	NOP;
}

void wlGdiDrawArc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t closewise, bool_t largearc)
{
    NOP;
}

void wlGdiDrawBezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
	NOP;
}

void wlGdiDrawCurve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn)
{
   NOP;
}

void wlGdiDrawPath(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn)
{
	NOP;
}

void wlGdiDrawRect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
	NOP;
}

void wlGdiDrawTriangle(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const tchar_t* orient)
{
	NOP;
}

void wlGdiDrawRound(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs)
{
	NOP;
}

void wlGdiDrawEllipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
	NOP;
}

void wlGdiDrawPie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct)
{
	NOP;
}

void wlGdiDrawPolygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n)
{
	NOP;
}

void wlGdiDrawSector(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* prl, const xspan_t* prs, double arcf, double arct)
{
	NOP;
}

void wlGdiDrawText(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len)
{
	NOP;
}

void wlGdiTextOut(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len)
{
	NOP;
}

void wlGdiTextRect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt)
{
	NOP;
}

void wlGdiTextSize(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
	NOP;
}

void wlGdiGradientRect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt)
{
	NOP;
}

void wlGdiAlphablendRect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity)
{
	NOP;
}

void wlGdiInvertRect(visual_t rdc, const xrect_t* prt)
{
	NOP;
}

void wlGdiExcludeRect(visual_t rdc, const xrect_t* pxr)
{
	NOP;
}

void wlGdiInclipRect(visual_t rdc, const xrect_t* pxr)
{
	NOP;
}

void wlGdiDrawImage(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt)
{
    NOP;
}

void wlGdiDrawBitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt)
{
	NOP;
}

void wlGdiFontSize(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
	NOP;
}

fontset_t wlGdiGetFontset(visual_t rdc)
{
	return NULL;
}

fontset_t wlGdiCreateFontset(const xfont_t* pxf)
{
	return NULL;
}

void wlGdiDestroyFontset(fontset_t ft)
{
	NOP;
}

void wlGdiWordSize(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs)
{
	NOP;
}

