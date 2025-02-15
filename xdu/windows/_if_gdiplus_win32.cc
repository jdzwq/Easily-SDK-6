﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdiplus document

	@module	if_gdiplus_win.c | windows implement file

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
#include "../xduutil.h"

#if defined(XDU_SUPPORT_CONTEXT_GDIPLUS)

static LOGFONT lf_gdiplus = { 0 };

#ifndef ULONG_PTR
#define ULONG_PTR ULONG
#endif

#include <gdiplus.h>

#pragma comment(lib,"gdiplus.lib")

using namespace Gdiplus;

GdiplusStartupInput	g_input = NULL;
ULONG_PTR			g_token = NULL;


static void _adjust_rect(RECT* pRect, int src_width, int src_height, const tchar_t* horz_align, const tchar_t* vert_align)
{
	xrect_t xr;

	xr.x = pRect->left;
	xr.y = pRect->top;
	xr.w = pRect->right - pRect->left;
	xr.h = pRect->bottom - pRect->top;

	pt_adjust_rect(&xr, src_width, src_height, horz_align, vert_align);

	pRect->left = xr.x;
	pRect->top = xr.y;
	pRect->right = xr.x + xr.w;
	pRect->bottom = xr.y + xr.h;
}

/************************************************************************************************/

static Pen* create_pen(const xpen_t* pxp)
{
	xcolor_t pen_color = {0};
	short sp;

	if (is_null(pxp->color))
		parse_xcolor(&pen_color, GDI_ATTR_RGB_GRAY);
	else
		parse_xcolor(&pen_color,pxp->color);

	if (is_null(pxp->size))
		sp = 1;
	else
		sp = xstol(pxp->size);

	Pen* pp = new Pen(Color(pen_color.r,pen_color.g,pen_color.b),(REAL)sp);

	if(xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASH) == 0)
		pp->SetDashStyle(DashStyleDot);
	else if(xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
		pp->SetDashStyle(DashStyleDash);

	return pp;
}

static Brush* create_brush(const xbrush_t* pxb, const xrect_t* pxr, GraphicsPath* pgp)
{
	xcolor_t brush_color = {0};
	xcolor_t linear_color = { 0 };
	short opacity;

	if (is_null(pxb->color))
		parse_xcolor(&brush_color, GDI_ATTR_RGB_SOFTWHITE);
	else
		parse_xcolor(&brush_color,pxb->color);

	if (is_null(pxb->opacity))
		opacity = 255;
	else
		opacity = xstol(pxb->opacity);

	if (xscmp(pxb->style, GDI_ATTR_FILL_STYLE_GRADIENT) == 0)
	{
		if (is_null(pxb->linear))
		{
			parse_xcolor(&linear_color, pxb->color);
			lighten_xcolor(&linear_color, 20);
		}
		else
		{
			parse_xcolor(&linear_color, pxb->linear);
		}

		if (pgp)
		{
			PathGradientBrush* pb = new PathGradientBrush(pgp);
			pb->SetCenterColor(Color(opacity, brush_color.r, brush_color.g, brush_color.b));
			Color clr(Color(opacity, linear_color.r, linear_color.g, linear_color.b));
			int n = 1;
			pb->SetSurroundColors(&clr, &n);

			return (Brush*)pb;
		}
		else if (pxr)
		{
			if (xscmp(pxb->gradient, GDI_ATTR_GRADIENT_HORZ) == 0)
				return 	new LinearGradientBrush(Rect(pxr->x, pxr->y, pxr->w, pxr->h), Color(opacity, brush_color.r, brush_color.g, brush_color.b), Color(opacity, linear_color.r, linear_color.g, linear_color.b), LinearGradientModeHorizontal);
			else if (xscmp(pxb->gradient, GDI_ATTR_GRADIENT_VERT) == 0)
				return 	new LinearGradientBrush(Rect(pxr->x, pxr->y, pxr->w, pxr->h), Color(opacity, brush_color.r, brush_color.g, brush_color.b), Color(opacity, linear_color.r, linear_color.g, linear_color.b), LinearGradientModeVertical);
			else
			{
				GraphicsPath gp;
				gp.AddRectangle(Rect(pxr->x, pxr->y, pxr->w, pxr->h));

				PathGradientBrush* pb = new PathGradientBrush(&gp);
				pb->SetCenterColor(Color(opacity, brush_color.r, brush_color.g, brush_color.b));
				Color clr(Color(opacity, linear_color.r, linear_color.g, linear_color.b));
				int n = 1;
				pb->SetSurroundColors(&clr, &n);

				return (Brush*)pb;
			}
		}
	}
	else if (xscmp(pxb->style, GDI_ATTR_FILL_STYLE_HATCH) == 0)
	{
		return new HatchBrush(HatchStyleCross, Color((BYTE)opacity, brush_color.r, brush_color.g, brush_color.b), Color(255, linear_color.r, linear_color.g, linear_color.b));
	}
	else
	{
		return new SolidBrush(Color((BYTE)opacity, brush_color.r, brush_color.g, brush_color.b));
	}

	return NULL;
}

static Font* create_font(const xfont_t* pxf)
{
	FontStyle fs;

	if (xstol(pxf->weight) > 500)
		fs = FontStyleBold;
	else
		fs = FontStyleRegular;

	if(xscmp(pxf->style,GDI_ATTR_FONT_STYLE_ITALIC) == 0)
	{
		if (xstol(pxf->weight) > 500)
			fs = FontStyleBoldItalic;
		else
			fs = FontStyleItalic;
	}
	
	if(xscmp(pxf->decorate,GDI_ATTR_FONT_DECORATE_UNDERLINE) == 0)
	{
		fs = FontStyleUnderline;
	}else if(xscmp(pxf->decorate,GDI_ATTR_FONT_DECORATE_STRIKOUT) == 0)
	{
		fs = FontStyleStrikeout;
	}

	tchar_t face[32];

	if (is_null(pxf->family))
	{
		xscpy(face, lf_gdiplus.lfFaceName);
	}else
	{
		xscpy(face, pxf->family);
	}

	FontFamily ff(face);
	BYTE fx = (BYTE)xstol(pxf->size);

	return new Font(&ff,fx,fs,UnitPoint);
}

static StringFormat* create_face(const xface_t* pxa)
{
	StringFormat* psf = new StringFormat;

	if (xscmp(pxa->line_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		psf->SetLineAlignment(StringAlignmentNear);
	}
	else if (xscmp(pxa->line_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		psf->SetLineAlignment(StringAlignmentFar);
	}
	else
	{
		psf->SetLineAlignment(StringAlignmentCenter);
	}

	if (xscmp(pxa->text_align, GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		psf->SetAlignment(StringAlignmentCenter);
	}
	else if (xscmp(pxa->text_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		psf->SetAlignment(StringAlignmentFar);
	}
	else
	{
		psf->SetAlignment(StringAlignmentNear);
	}

	if (is_null(pxa->text_wrap))
		psf->SetFormatFlags(StringFormatFlagsNoWrap);

	return psf;
}

static GraphicsPath* create_path(HDC hDC, const tchar_t* aa, const xpoint_t* pa)
{
	POINT pt_m = { 0 };
	POINT pt_p = { 0 };
	POINT pt_i = { 0 };
	POINT pt[4] = { 0 };
	RECT rt;

	int rx, ry;
	int sweep, sflag, lflag;
	xpoint_t xp[3];
	double arcf, arct;
	POINT pk = { 0 };
	int n = 0;
	REAL fdeg, tdeg;

	if (!aa)
		return NULL;

	GraphicsPath* path = new GraphicsPath;

	while (*aa)
	{
		if (*aa == _T('M') || *aa == _T('m'))
		{
			pt_m.x = pa[0].x;
			pt_m.y = pa[0].y;

			pt_p.x = pt_m.x;
			pt_p.y = pt_m.y;

			n = 1;
		}
		else if (*aa == _T('L'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pa[0].x;
			pt[1].y = pa[0].y;

			pt_p.x = pt[1].x;
			pt_p.y = pt[1].y;
			pt_i.x = 2 * pt[1].x - pt[0].x;
			pt_i.y = 2 * pt[1].y - pt[0].y;

			DPtoLP(hDC, pt, 2);
			path->AddLine(pt[0].x, pt[0].y, pt[1].x, pt[1].y);
			n = 1;
		}
		else if (*aa == _T('l'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_p.x + pa[0].x;
			pt[1].y = pt_p.y + pa[0].y;

			pt_p.x = pt[1].x;
			pt_p.y = pt[1].y;
			pt_i.x = 2 * pt[1].x - pt[0].x;
			pt_i.y = 2 * pt[1].y - pt[0].y;

			DPtoLP(hDC, pt, 2);
			path->AddLine(pt[0].x, pt[0].y, pt[1].x, pt[1].y);
			n = 1;
		}
		else if (*aa == _T('Q'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pa[0].x;
			pt[1].y = pa[0].y;
			pt[2].x = pa[1].x;
			pt[2].y = pa[1].y;

			pt_p.x = pt[2].x;
			pt_p.y = pt[2].y;
			pt_i.x = 2 * pt[2].x - pt[1].x;
			pt_i.y = 2 * pt[2].y - pt[1].y;

			DPtoLP(hDC, pt, 3);
			path->AddBezier(pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y);
			n = 2;
		}
		else if (*aa == _T('q'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_m.x + pa[0].x;
			pt[1].y = pt_m.y + pa[0].y;
			pt[2].x = pt_m.x + pa[1].x;
			pt[2].y = pt_m.y + pa[1].y;

			pt_p.x = pt[2].x;
			pt_p.y = pt[2].y;
			pt_i.x = 2 * pt[2].x - pt[1].x;
			pt_i.y = 2 * pt[2].y - pt[1].y;

			DPtoLP(hDC, pt, 3);
			path->AddBezier(pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y);
			n = 2;
		}
		else if (*aa == _T('T'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_i.x;
			pt[1].y = pt_i.y;
			pt[2].x = pa[0].x;
			pt[2].y = pa[0].y;

			pt_p.x = pt[2].x;
			pt_p.y = pt[2].y;
			pt_i.x = 2 * pt[2].x - pt[1].x;
			pt_i.y = 2 * pt[2].y - pt[1].y;

			DPtoLP(hDC, pt, 3);
			path->AddBezier(pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y);
			n = 1;
		}
		else if (*aa == _T('t'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_i.x;
			pt[1].y = pt_i.y;
			pt[2].x = pt_p.x + pa[0].x;
			pt[2].y = pt_p.y + pa[0].y;

			pt_p.x = pt[2].x;
			pt_p.y = pt[2].y;
			pt_i.x = 2 * pt[2].x - pt[1].x;
			pt_i.y = 2 * pt[2].y - pt[1].y;

			DPtoLP(hDC, pt, 3);
			path->AddBezier(pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y);
			n = 1;
		}
		else if (*aa == _T('C'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pa[0].x;
			pt[1].y = pa[0].y;
			pt[2].x = pa[1].x;
			pt[2].y = pa[1].y;
			pt[3].x = pa[2].x;
			pt[3].y = pa[2].y;

			pt_p.x = pt[3].x;
			pt_p.y = pt[3].y;
			pt_i.x = 2 * pt[3].x - pt[2].x;
			pt_i.y = 2 * pt[3].y - pt[2].y;

			DPtoLP(hDC, pt, 4);
			path->AddBezier(pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);
			n = 3;
		}
		else if (*aa == _T('c'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_p.x + pa[0].x;
			pt[1].y = pt_p.y + pa[0].y;
			pt[2].x = pt_p.x + pa[1].x;
			pt[2].y = pt_p.y + pa[1].y;
			pt[3].x = pt_p.x + pa[2].x;
			pt[3].y = pt_p.y + pa[2].y;

			pt_p.x = pt[3].x;
			pt_p.y = pt[3].y;
			pt_i.x = 2 * pt[3].x - pt[2].x;
			pt_i.y = 2 * pt[3].y - pt[2].y;

			DPtoLP(hDC, pt, 4);
			path->AddBezier(pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);
			n = 3;
		}
		else if (*aa == _T('S'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_i.x;
			pt[1].y = pt_i.y;
			pt[2].x = pa[0].x;
			pt[2].y = pa[0].y;
			pt[3].x = pa[1].x;
			pt[3].y = pa[1].y;

			pt_p.x = pt[3].x;
			pt_p.y = pt[3].y;
			pt_i.x = 2 * pt[2].x - pt[1].x;
			pt_i.y = 2 * pt[2].y - pt[1].y;

			DPtoLP(hDC, pt, 4);
			path->AddBezier(pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);
			n = 2;
		}
		else if (*aa == _T('s'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_i.x;
			pt[1].y = pt_i.y;
			pt[2].x = pt_p.x + pa[0].x;
			pt[2].y = pt_p.y + pa[0].y;
			pt[3].x = pt_p.x + pa[1].x;
			pt[3].y = pt_p.y + pa[1].y;

			pt_p.x = pt[2].x;
			pt_p.y = pt[2].y;
			pt_i.x = 2 * pt[2].x - pt[1].x;
			pt_i.y = 2 * pt[2].y - pt[1].y;

			DPtoLP(hDC, pt, 4);
			path->AddBezier(pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);
			n = 2;
		}
		else if (*aa == _T('A'))
		{
			sflag = pa[0].x;
			lflag = pa[0].y;
			rx = pa[1].x;
			ry = pa[1].y;
			
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pa[2].x;
			pt[1].y = pa[2].y;

			pt_p.x = pt[1].x;
			pt_p.y = pt[1].y;
			pt_i.x = 2 * pt[1].x - pt[0].x;
			pt_i.y = 2 * pt[1].y - pt[0].y;

			xp[0].x = pt[0].x;
			xp[0].y = pt[0].y;
			xp[1].x = pt[1].x;
			xp[1].y = pt[1].y;

			sweep = pt_calc_radian(sflag, lflag, rx, ry, &xp[0], &xp[1], &xp[2], &arcf, &arct);

			//the from angle
			fdeg = (sweep == sflag) ? arcf / XPI * 180 : arct / XPI * 180;
			fdeg = 360 - fdeg;

			//the to angle
			tdeg = (sweep == sflag) ? arct / XPI * 180 : arcf / XPI * 180;
			tdeg = 360 - tdeg;

			//the sweep angle
			tdeg = tdeg - fdeg;
			fdeg = (int)fdeg % 360;

			pk.x = xp[2].x;
			pk.y = xp[2].y;

			rt.left = pk.x - rx;
			rt.right = pk.x + rx;
			rt.top = pk.y - ry;
			rt.bottom = pk.y + ry;

			DPtoLP(hDC, (LPPOINT)&rt, 2);
			path->AddArc(rt.left, rt.top, 2 * rx, 2 * ry, fdeg, tdeg);
			n = 3;
		}
		else if (*aa == _T('Z') || *aa == _T('z'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_m.x;
			pt[1].y = pt_m.y;

			DPtoLP(hDC, pt, 2);
			path->AddLine(pt[0].x, pt[0].y, pt[1].x, pt[1].y);

			break;
		}

		aa++;
		pa += n;
	}

	return path;
}


void _gdiplus_init(int osv)
{
	NONCLIENTMETRICS ncm = { 0 };

	ncm.cbSize = sizeof(ncm);

	SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICS), (PVOID)&ncm, 0);

	CopyMemory((void*)&lf_gdiplus, (void*)&ncm.lfCaptionFont, sizeof(LOGFONT));

	if (!g_token)
	{
		GdiplusStartup(&g_token, &g_input, NULL);
	}
}

void _gdiplus_uninit(void)
{
	if (g_token)
	{
		GdiplusShutdown(g_token);
		g_token = NULL;
	}
}

void _gdiplus_set_point(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	COLORREF clr;

	clr = RGB(pxc->r, pxc->g, pxc->b);

	SetPixel(hDC, ppt->x, ppt->y, clr);
}

void _gdiplus_get_point(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	COLORREF clr;

	clr = GetPixel(hDC, ppt->x, ppt->y);

	pxc->r = GetRValue(clr);
	pxc->g = GetGValue(clr);
	pxc->b = GetBValue(clr);
}

void _gdiplus_draw_points(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n)
{

}

void _gdiplus_draw_line(visual_t rdc,const xpen_t* pxp, const xpoint_t*ppt1, const xpoint_t* ppt2)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	POINT pt[2];
	pt[0].x = ppt1->x;
	pt[0].y = ppt1->y;
	pt[1].x = ppt2->x;
	pt[1].y = ppt2->y;

	DPtoLP(hDC,pt,2);

	Pen* pp = create_pen(pxp);

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);

	if (pxp && (pxp->adorn.feed || pxp->adorn.size))
	{
		xcolor_t xc_gray;

		parse_xcolor(&xc_gray, pxp->color);
		lighten_xcolor(&xc_gray, -10);

		Pen pen(Color(xc_gray.r, xc_gray.g, xc_gray.b), (REAL)pxp->adorn.size);

		gh.SetSmoothingMode(SmoothingModeAntiAlias);
		gh.DrawLine(&pen, pt[0].x + pxp->adorn.feed, pt[0].y + pxp->adorn.feed, pt[1].x + pxp->adorn.feed, pt[1].y + pxp->adorn.feed);
	}

	gh.SetSmoothingMode(SmoothingModeAntiAlias);
	gh.DrawLine(pp,pt[0].x,pt[0].y,pt[1].x,pt[1].y);
	delete pp;
}

void _gdiplus_draw_polyline(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int n)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	GraphicsPath path;
	POINT pt[2];

	for (int i = 0; i<n - 1; i++)
	{
		pt[0].x = ppt[i].x;
		pt[0].y = ppt[i].y;
		pt[1].x = ppt[i + 1].x;
		pt[1].y = ppt[i + 1].y;

		DPtoLP(hDC, pt, 2);

		path.AddLine(pt[0].x, pt[0].y, pt[1].x, pt[1].y);
	}

	Pen* pp = create_pen(pxp);

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

	if (pxp && (pxp->adorn.feed || pxp->adorn.size))
	{
		GraphicsPath* adron = path.Clone();

		Region region(&path);
		gh.ExcludeClip(&region);

		Matrix M;
		M.Translate(pxp->adorn.feed, pxp->adorn.feed);

		adron->Transform(&M);

		xcolor_t xc_gray;

		parse_xcolor(&xc_gray, pxp->color);
		lighten_xcolor(&xc_gray, -10);

		Pen pen(Color(xc_gray.r, xc_gray.g, xc_gray.b), (REAL)pxp->adorn.size);

		gh.DrawPath(&pen, adron);

		gh.ResetClip();

		delete adron;
	}

	gh.DrawPath(pp, &path);

	delete pp;
}

void _gdiplus_draw_arc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t sflag, bool_t lflag)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	POINT pt[4] = { 0 };

	pt[0].x = ppt1->x;
	pt[0].y = ppt1->y;
	pt[1].x = ppt2->x;
	pt[1].y = ppt2->y;
	pt[2].x = pxs->w;
	pt[2].y = pxs->h;

	DPtoLP(hDC, pt, 3);

	double fang, tang;
	xpoint_t xp[3] = { 0 };
	int rx, ry;

	xp[0].x = pt[0].x;
	xp[0].y = pt[0].y;
	xp[1].x = pt[1].x;
	xp[1].y = pt[1].y;
	rx = pt[2].x;
	ry = pt[2].y;

	pt_calc_radian(sflag, lflag, rx, ry, &xp[0], &xp[1], &xp[2], &fang, &tang);

	float fdeg, sdeg;

	radian_to_degree(fang, tang, &fdeg, &sdeg);

	/*fdeg = fang / XPI * 180;
	if (fdeg < 0)
		fdeg = 0 - fdeg;
	else
		fdeg = 360 - fdeg;

	tdeg = 0 - tang / XPI * 180;*/

	Rect rf(xp[2].x - rx, xp[2].y - ry, 2 * rx, 2 * ry);

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);
	gh.SetSmoothingMode(SmoothingModeHighQuality);

	if (pxp && (pxp->adorn.feed || pxp->adorn.size))
	{
		xcolor_t xc_gray;

		parse_xcolor(&xc_gray, pxp->color);
		lighten_xcolor(&xc_gray, -10);

		Pen pen(Color(xc_gray.r, xc_gray.g, xc_gray.b), (REAL)pxp->adorn.size);

		Rect rf2 = rf;
		rf2.X += pxp->adorn.feed;
		rf2.Y += pxp->adorn.feed;
		gh.SetCompositingQuality(CompositingQualityGammaCorrected);

		gh.DrawArc(&pen, rf2, fdeg, sdeg);
	}

	if (!is_null_xpen(pxp))
	{
		Pen* pp = create_pen(pxp);

		gh.SetCompositingQuality(CompositingQualityGammaCorrected);
		gh.DrawArc(pp, rf, fdeg, sdeg);

		delete pp;
	}
}

void _gdiplus_draw_bezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	POINT pt[4];
	pt[0].x = ppt1->x;
	pt[0].y = ppt1->y;
	pt[1].x = ppt2->x;
	pt[1].y = ppt2->y;
	pt[2].x = ppt3->x;
	pt[2].y = ppt3->y;
	pt[3].x = ppt4->x;
	pt[3].y = ppt4->y;

	DPtoLP(hDC, pt, 4);

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

	Pen* pp = (Pen*)create_pen(pxp);
	gh.SetCompositingQuality(CompositingQualityGammaCorrected);
	gh.DrawBezier(pp, pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);

	delete pp;
}

void _gdiplus_draw_curve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int n)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	Point* pa = new Point[n];
	POINT pi;

	for (int i = 0; i < n; i++)
	{
		pi.x = ppt[i].x;
		pi.y = ppt[i].y;

		DPtoLP(hDC, &pi, 1);

		pa[i].X = pi.x;
		pa[i].Y = pi.y;
	}

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

	Pen* pp = (Pen*)create_pen(pxp);
	gh.SetCompositingQuality(CompositingQualityGammaCorrected);
	gh.DrawCurve(pp, pa, n);

	delete[]pa;

	delete pp;
}

void _gdiplus_draw_rect(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	POINT pt[2];
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(hDC, pt, 2);

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);

	if (pxb && (pxb->shadow.offx || pxb->shadow.offy))
	{
		Region region(Rect(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y));
		gh.ExcludeClip(&region);

		xcolor_t xc_near, xc_far;
		parse_xcolor(&xc_near, pxb->color);
		memcpy((void*)&xc_far, (void*)&xc_near, sizeof(xcolor_t));
		lighten_xcolor(&xc_far, -10);

		LinearGradientBrush brush(Rect(pt[0].x + pxb->shadow.offx, pt[0].y + pxb->shadow.offy, pt[1].x - pt[0].x, pt[1].y - pt[0].y), Color(255, xc_near.r, xc_near.g, xc_near.b), Color(255, xc_far.r, xc_far.g, xc_far.b), LinearGradientModeForwardDiagonal);

		gh.FillRectangle(&brush, Rect(pt[0].x + pxb->shadow.offx, pt[0].y + pxb->shadow.offy, pt[1].x - pt[0].x, pt[1].y - pt[0].y));

		gh.ResetClip();
	}

	if (pxp && (pxp->adorn.feed || pxp->adorn.size))
	{
		Region region(Rect(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y));
		gh.ExcludeClip(&region);

		xcolor_t xc_gray;

		parse_xcolor(&xc_gray, pxp->color);
		lighten_xcolor(&xc_gray, -10);

		Pen pen(Color(xc_gray.r, xc_gray.g, xc_gray.b), (REAL)pxp->adorn.size);

		gh.SetSmoothingMode(SmoothingModeAntiAlias);
		gh.DrawRectangle(&pen, Rect(pt[0].x + pxp->adorn.feed, pt[0].y + pxp->adorn.feed, pt[1].x - pt[0].x, pt[1].y - pt[0].y));

		gh.ResetClip();
	}

	if (!is_null_xbrush(pxb))
	{
		Brush* pb = (Brush*)create_brush(pxb, prt, NULL);
		gh.FillRectangle(pb, Rect(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y));

		delete pb;
	}

	if (!is_null_xpen(pxp))
	{
		Pen* pp = (Pen*)create_pen(pxp);
		gh.SetSmoothingMode(SmoothingModeAntiAlias);
		gh.DrawRectangle(pp, Rect(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y));

		delete pp;
	}
}

void _gdiplus_draw_round(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt, const xsize_t* pxs)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	int rx, ry;

	if (pxs)
	{
		rx = pxs->w;
		ry = pxs->h;
	}
	else
	{
		rx = (prt->w) / 10;
		if (rx < 1)
			rx = 1;
		else if (rx > 6)
			rx = 6;

		ry = (prt->h) / 10;
		if (ry < 1)
			ry = 1;
		else if (ry > 6)
			ry = 6;
	}

	POINT pt[2];
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(hDC, pt, 2);

	Rect rf(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);

	GraphicsPath path;

	path.AddArc(rf.X, rf.Y, 2 * rx, 2 * ry, 180, 90);
	path.AddLine(rf.X + rx, rf.Y, rf.X + rf.Width - rx, rf.Y);
	path.AddArc(rf.X + rf.Width - 2 * rx, rf.Y, 2 * rx, 2 * ry, 270, 90);
	path.AddLine(rf.X + rf.Width, rf.Y + ry, rf.X + rf.Width, rf.Y + rf.Height - ry);
	path.AddArc(rf.X + rf.Width - 2 * rx, rf.Y + rf.Height - 2 * ry, 2 * rx, 2 * ry, 0, 90);
	path.AddLine(rf.X + rf.Width - rx, rf.Y + rf.Height, rf.X + rx, rf.Y + rf.Height);
	path.AddArc(rf.X, rf.Y + rf.Height - 2 * rx, 2 * rx, 2 * ry, 90, 90);
	path.AddLine(rf.X, rf.Y + rf.Height - rx, rf.X, rf.Y + ry);

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);
	gh.SetSmoothingMode(SmoothingModeHighQuality);

	if (pxb && (pxb->shadow.offx || pxb->shadow.offy))
	{
		GraphicsPath* shadow = path.Clone();

		Region region(&path);
		gh.ExcludeClip(&region);

		Matrix M;
		M.Translate(pxb->shadow.offx, pxb->shadow.offy);

		shadow->Transform(&M);

		xcolor_t xc_near, xc_far;
		parse_xcolor(&xc_near, pxb->color);
		memcpy((void*)&xc_far, (void*)&xc_near, sizeof(xcolor_t));
		lighten_xcolor(&xc_far, -10);

		LinearGradientBrush brush(Rect(pt[0].x + pxb->shadow.offx, pt[0].y + pxb->shadow.offy, pt[1].x - pt[0].x, pt[1].y - pt[0].y), Color(255, xc_near.r, xc_near.g, xc_near.b), Color(255, xc_far.r, xc_far.g, xc_far.b), LinearGradientModeForwardDiagonal);

		gh.FillPath(&brush, shadow);

		gh.ResetClip();

		delete shadow;
	}

	if (pxp && (pxp->adorn.feed || pxp->adorn.size))
	{
		GraphicsPath* adron = path.Clone();

		Region region(&path);
		gh.ExcludeClip(&region);

		Matrix M;
		M.Translate(pxp->adorn.feed, pxp->adorn.feed);

		adron->Transform(&M);

		xcolor_t xc_gray;

		parse_xcolor(&xc_gray, pxp->color);
		lighten_xcolor(&xc_gray, -10);

		Pen pen(Color(xc_gray.r, xc_gray.g, xc_gray.b), (REAL)pxp->adorn.size);

		gh.SetSmoothingMode(SmoothingModeAntiAlias);
		gh.DrawPath(&pen, adron);

		gh.ResetClip();

		delete adron;
	}

	if (!is_null_xbrush(pxb))
	{
		Brush* pb = create_brush(pxb, prt, &path);
		gh.FillPath(pb, &path);

		delete pb;
	}

	if (!is_null_xpen(pxp))
	{
		Pen* pp = create_pen(pxp);
		gh.DrawPath(pp, &path);

		delete pp;
	}
}

void _gdiplus_draw_ellipse(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	POINT pt[2];
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(hDC, pt, 2);

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

	if (pxb && (pxb->shadow.offx || pxb->shadow.offy))
	{
		xcolor_t xc_near, xc_far;
		parse_xcolor(&xc_near, pxb->color);
		memcpy((void*)&xc_far, (void*)&xc_near, sizeof(xcolor_t));
		lighten_xcolor(&xc_far, -10);

		LinearGradientBrush brush(Rect(pt[0].x + pxb->shadow.offx, pt[0].y + pxb->shadow.offy, pt[1].x - pt[0].x, pt[1].y - pt[0].y), Color(255, xc_near.r, xc_near.g, xc_near.b), Color(255, xc_far.r, xc_far.g, xc_far.b), LinearGradientModeForwardDiagonal);

		gh.FillEllipse(&brush, Rect(pt[0].x + pxb->shadow.offx, pt[0].y + pxb->shadow.offy, pt[1].x - pt[0].x, pt[1].y - pt[0].y));
	}

	if (pxp && (pxp->adorn.feed || pxp->adorn.size))
	{
		xcolor_t xc_gray;

		parse_xcolor(&xc_gray, pxp->color);
		lighten_xcolor(&xc_gray, -10);

		Pen pen(Color(xc_gray.r, xc_gray.g, xc_gray.b), (REAL)pxp->adorn.size);

		gh.DrawEllipse(&pen, Rect(pt[0].x + pxp->adorn.feed, pt[0].y + pxp->adorn.feed, pt[1].x - pt[0].x, pt[1].y - pt[0].y));
	}

	if (!is_null_xbrush(pxb))
	{
		Brush* pb = (Brush*)create_brush(pxb, prt, NULL);
		gh.FillEllipse(pb, Rect(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y));

		delete pb;
	}

	if (!is_null_xpen(pxp))
	{
		Pen* pp = (Pen*)create_pen(pxp);
		gh.DrawEllipse(pp, Rect(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y));

		delete pp;
	}
}

void _gdiplus_draw_pie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt, double fang, double tang)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	POINT pt[2];
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(hDC, pt, 2);

	Rect rf(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);

	REAL fdeg, tdeg;

	//the from angle
	fdeg = fang / XPI * 180;
	fdeg = 360 - fdeg;

	//the to angle
	tdeg = tang / XPI * 180;
	tdeg = 360 - tdeg;

	//the sweep angle
	tdeg = tdeg - fdeg;
	fdeg = (int)fdeg % 360;

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);
	gh.SetSmoothingMode(SmoothingModeHighQuality);

	if (pxb && (pxb->shadow.offx || pxb->shadow.offy))
	{
		xcolor_t xc_near, xc_far;
		parse_xcolor(&xc_near, pxb->color);
		memcpy((void*)&xc_far, (void*)&xc_near, sizeof(xcolor_t));
		lighten_xcolor(&xc_far, -10);

		LinearGradientBrush brush(Rect(pt[0].x + pxb->shadow.offx, pt[0].y + pxb->shadow.offy, pt[1].x - pt[0].x, pt[1].y - pt[0].y), Color(255, xc_near.r, xc_near.g, xc_near.b), Color(255, xc_far.r, xc_far.g, xc_far.b), LinearGradientModeForwardDiagonal);

		gh.FillPie(&brush, Rect(pt[0].x + pxb->shadow.offx, pt[0].y + pxb->shadow.offy, pt[1].x - pt[0].x, pt[1].y - pt[0].y), fdeg, tdeg);
	}

	if (pxp && (pxp->adorn.feed || pxp->adorn.size))
	{
		xcolor_t xc_gray;

		parse_xcolor(&xc_gray, pxp->color);
		lighten_xcolor(&xc_gray, -10);

		Pen pen(Color(xc_gray.r, xc_gray.g, xc_gray.b), (REAL)pxp->adorn.size);

		gh.SetCompositingQuality(CompositingQualityGammaCorrected);
		gh.DrawPie(&pen, Rect(pt[0].x + pxp->adorn.feed, pt[0].y + pxp->adorn.feed, pt[1].x - pt[0].x, pt[1].y - pt[0].y), fdeg, tdeg);
	}

	if (!is_null_xbrush(pxb))
	{
		GraphicsPath gp;
		
		gp.AddPie(rf, fdeg, tdeg);

		Brush* pb = create_brush(pxb, NULL, &gp);

		gh.FillPie(pb, rf, fdeg, tdeg);

		delete pb;
	}

	if (!is_null_xpen(pxp))
	{
		Pen* pp = create_pen(pxp);

		gh.SetCompositingQuality(CompositingQualityGammaCorrected);
		gh.DrawPie(pp, rf, fdeg, tdeg);

		delete pp;
	}
}

void _gdiplus_draw_polygon(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, int n)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	GraphicsPath path;
	POINT pt[2];

	for (int i = 0; i<n - 1; i++)
	{
		pt[0].x = ppt[i].x;
		pt[0].y = ppt[i].y;
		pt[1].x = ppt[i + 1].x;
		pt[1].y = ppt[i + 1].y;

		DPtoLP(hDC, pt, 2);

		path.AddLine(pt[0].x, pt[0].y, pt[1].x, pt[1].y);
	}

	if (n > 1)
	{
		pt[0].x = ppt[0].x;
		pt[0].y = ppt[0].y;
		pt[1].x = ppt[1].x;
		pt[1].y = ppt[1].y;

		DPtoLP(hDC, pt, 2);

		path.AddLine(pt[0].x, pt[0].y, pt[1].x, pt[1].y);
	}

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

	if (pxb && (pxb->shadow.offx || pxb->shadow.offy))
	{
		GraphicsPath* shadow = path.Clone();

		Region region(&path);
		gh.ExcludeClip(&region);

		Matrix M;
		M.Translate(pxb->shadow.offx, pxb->shadow.offy);

		shadow->Transform(&M);

		xcolor_t xc_near, xc_far;
		parse_xcolor(&xc_near, pxb->color);
		memcpy((void*)&xc_far, (void*)&xc_near, sizeof(xcolor_t));
		lighten_xcolor(&xc_far, -10);

		PathGradientBrush brush(shadow);
		Color clr[3] = { Color(0, 0, 0, 0), Color(255, xc_near.r, xc_near.g, xc_near.b), Color(255, xc_far.r, xc_far.g, xc_far.b) };
		REAL pos[3] = { 0.0F, 0.1F, 1.0F };
		brush.SetInterpolationColors(clr, pos, 3);

		gh.FillPath(&brush, shadow);

		gh.ResetClip();

		delete shadow;
	}

	if (pxp && (pxp->adorn.feed || pxp->adorn.size))
	{
		GraphicsPath* adron = path.Clone();

		Region region(&path);
		gh.ExcludeClip(&region);

		Matrix M;
		M.Translate(pxp->adorn.feed, pxp->adorn.feed);

		adron->Transform(&M);

		xcolor_t xc_gray;

		parse_xcolor(&xc_gray, pxp->color);
		lighten_xcolor(&xc_gray, -10);

		Pen pen(Color(xc_gray.r, xc_gray.g, xc_gray.b), (REAL)pxp->adorn.size);

		gh.DrawPath(&pen, adron);

		gh.ResetClip();

		delete adron;
	}

	if (!is_null_xbrush(pxb))
	{
		Brush* pb = create_brush(pxb, NULL, &path);
		gh.FillPath(pb, &path);

		delete pb;
	}

	if (!is_null_xpen(pxp))
	{
		Pen* pp = create_pen(pxp);
		gh.DrawPath(pp, &path);

		delete pp;
	}
}

void _gdiplus_draw_path(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	GraphicsPath* path = create_path(hDC, aa, pa);

	if (!path)
		return;

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

	if (pxb && (pxb->shadow.offx || pxb->shadow.offy))
	{
		GraphicsPath* shadow = path->Clone();

		Region region(path);
		gh.ExcludeClip(&region);

		Matrix M;
		M.Translate(pxb->shadow.offx, pxb->shadow.offy);

		shadow->Transform(&M);

		xcolor_t xc_near, xc_far;
		parse_xcolor(&xc_near, pxb->color);
		memcpy((void*)&xc_far, (void*)&xc_near, sizeof(xcolor_t));
		lighten_xcolor(&xc_far, -10);

		PathGradientBrush brush(shadow);
		Color clr[3] = { Color(0, 0, 0, 0), Color(255, xc_near.r, xc_near.g, xc_near.b), Color(255, xc_far.r, xc_far.g, xc_far.b) };
		REAL pos[3] = { 0.0F, 0.1F, 1.0F };
		brush.SetInterpolationColors(clr, pos, 3);

		gh.FillPath(&brush, shadow);

		gh.ResetClip();

		delete shadow;
	}

	if (pxp && (pxp->adorn.feed || pxp->adorn.size))
	{
		GraphicsPath* adron = path->Clone();

		Region region(path);
		gh.ExcludeClip(&region);

		Matrix M;
		M.Translate(pxp->adorn.feed, pxp->adorn.feed);

		adron->Transform(&M);

		xcolor_t xc_gray;

		parse_xcolor(&xc_gray, pxp->color);
		lighten_xcolor(&xc_gray, -10);

		Pen pen(Color(xc_gray.r, xc_gray.g, xc_gray.b), (REAL)pxp->adorn.size);

		gh.DrawPath(&pen, adron);

		gh.ResetClip();

		delete adron;
	}

	if (!is_null_xbrush(pxb))
	{
		Brush* pb = create_brush(pxb, NULL, path);
		gh.FillPath(pb, path);

		delete pb;
	}

	if (!is_null_xpen(pxp))
	{
		Pen* pp = create_pen(pxp);
		gh.DrawPath(pp, path);

		delete pp;
	}

	delete path;
}

void _gdiplus_draw_text(visual_t rdc,const xfont_t* pxf,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	Font* pf = create_font(pxf);

	StringFormat* ps = create_face(pxa);

	xcolor_t text_color = {0};
	parse_xcolor(&text_color,pxf->color);

	Brush* pb = new SolidBrush(Color(text_color.r,text_color.g,text_color.b));

	POINT pt[2];
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(hDC,pt,2);

	RectF rf((REAL)pt[0].x,(REAL)pt[0].y,(REAL)(pt[1].x - pt[0].x),(REAL)(pt[1].y - pt[0].y));

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);

	if (len < 0 && txt)
		len = xslen(txt);

	gh.DrawString(txt,len,pf,rf,ps,pb);

	delete pb;
	delete pf;
	delete ps;
}

void _gdiplus_text_out(visual_t rdc, const xfont_t* pxf, const xpoint_t* ppt, const tchar_t* txt, int len)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	HFONT hFont, orgFont;
	COLORREF clr, orgClr;
	int fs;
	LOGFONT lf;
	xcolor_t xc;

	CopyMemory((void*)&lf, (void*)&lf_gdiplus, sizeof(LOGFONT));

	fs = xstol(pxf->size);

	parse_xcolor(&xc, pxf->color);

	lf.lfHeight = -MulDiv(fs, GetDeviceCaps(hDC, LOGPIXELSY), 72);
	lf.lfWeight = xstol(pxf->weight);

	if (xscmp(pxf->style, GDI_ATTR_FONT_STYLE_ITALIC) == 0)
	{
		lf.lfItalic = 1;
	}
	
	if (xscmp(pxf->decorate, GDI_ATTR_FONT_DECORATE_UNDERLINE) == 0)
	{
		lf.lfUnderline = 1;
	}
	else if (xscmp(pxf->decorate, GDI_ATTR_FONT_DECORATE_STRIKOUT) == 0)
	{
		lf.lfStrikeOut = 1;
	}

	if (!is_null(pxf->family))
	{
		xscpy(lf.lfFaceName, pxf->family);
	}

	hFont = CreateFontIndirect(&lf);

	orgFont = (HFONT)SelectObject(hDC, hFont);

	if (len < 0 && txt)
		len = xslen(txt);

	clr = RGB(xc.r, xc.g, xc.b);
	orgClr = SetTextColor(hDC, clr);

	TextOut(hDC, ppt->x, ppt->y, txt, len);

	SetTextColor(hDC, orgClr);
	hFont = (HFONT)SelectObject(hDC, orgFont);
	DeleteObject(hFont);
}

void _gdiplus_text_rect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* pxr)
{
	win32_context_t* ctx = (win32_context_t*)rdc;

	BOOL bRef = 0;
	HDC hDC;

	if (!rdc)
	{
		bRef = 1;
		hDC = GetDC(NULL);
	}
	else
	{
		hDC = (HDC)(ctx->context);
	}

	POINT pt[2];
	pt[0].x = pxr->x;
	pt[0].y = pxr->y;
	pt[1].x = pxr->x + pxr->w;
	pt[1].y = pxr->y + pxr->h;

	DPtoLP(hDC, pt, 2);

	RectF rf((REAL)pt[0].x, (REAL)pt[0].y, (REAL)(pt[1].x - pt[0].x), (REAL)(pt[1].y - pt[0].y));

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);

	Font* pf = create_font(pxf);
	StringFormat* ps = create_face(pxa);

	RectF rfOut;
	gh.MeasureString((wchar_t*)txt, len, pf, rf, ps, &rfOut);

	/*FontFamily ff;
	GraphicsPath path;

	pf->GetFamily(&ff);

	path.AddString(txt, len, &ff, pf->GetStyle(), pf->GetSize(), PointF(0, 0), ps);

	path.GetBounds(&rfOut);
	*/

	pt[0].x = (int)(rfOut.GetLeft());
	pt[0].y = (int)(rfOut.GetTop());
	pt[1].x = (int)(rfOut.GetRight());
	pt[1].y = (int)(rfOut.GetBottom());

	LPtoDP(hDC, pt, 2);

	pxr->x = pt[0].x;
	pxr->y = pt[0].y;
	pxr->w = pt[1].x - pt[0].x;
	pxr->h = pt[1].y - pt[0].y;

	delete pf;
	delete ps;

	if (bRef)
		ReleaseDC(NULL, hDC);
}

void _gdiplus_text_size(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
	win32_context_t* ctx = (win32_context_t*)rdc;

	BOOL bRef = 0;
	HDC hDC;

	if (!rdc)
	{
		bRef = 1;
		hDC = GetDC(NULL);
	}
	else
	{
		hDC = (HDC)(ctx->context);
	}

	LOGFONT lf;
	HFONT hFont, orgFont;
	SIZE si;
	int fs;

	CopyMemory((void*)&lf, (void*)&lf_gdiplus, sizeof(LOGFONT));

	fs = xstol(pxf->size);

	lf.lfHeight = -MulDiv(fs, GetDeviceCaps(hDC, LOGPIXELSY), 72);
	lf.lfWeight = xstol(pxf->weight);

	if (xscmp(pxf->style, GDI_ATTR_FONT_STYLE_ITALIC) == 0)
	{
		lf.lfItalic = 1;
	}
	
	if (xscmp(pxf->decorate, GDI_ATTR_FONT_DECORATE_UNDERLINE) == 0)
	{
		lf.lfUnderline = 1;
	}
	else if (xscmp(pxf->decorate, GDI_ATTR_FONT_DECORATE_STRIKOUT) == 0)
	{
		lf.lfStrikeOut = 1;
	}

	if (!is_null(pxf->family))
	{
		xscpy(lf.lfFaceName, pxf->family);
	}

	hFont = CreateFontIndirect(&lf);

	orgFont = (HFONT)SelectObject(hDC, hFont);

	if (len < 0)
		len = (txt) ? xslen(txt) : 0;

	GetTextExtentPoint32(hDC, txt, len, &si);

	hFont = (HFONT)SelectObject(hDC, orgFont);
	DeleteObject(hFont);

	if (bRef)
		ReleaseDC(NULL, hDC);

	pxs->w = si.cx;
	pxs->h = si.cy;
}

void _gdiplus_text_metric(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
	win32_context_t* ctx = (win32_context_t*)rdc;

	BOOL bRef = 0;
	HDC hDC;

	if (!rdc)
	{
		bRef = 1;
		hDC = GetDC(NULL);
	}
	else
	{
		hDC = (HDC)(ctx->context);
	}

	LOGFONT lf;
	HFONT hFont, orgFont;
	int fs;
	TEXTMETRIC tm = { 0 };

	CopyMemory((void*)&lf, (void*)&lf_gdiplus, sizeof(LOGFONT));

	fs = xstol(pxf->size);

	lf.lfHeight = -MulDiv(fs, GetDeviceCaps(hDC, LOGPIXELSY), 72);
	lf.lfWeight = xstol(pxf->weight);

	if (xscmp(pxf->style, GDI_ATTR_FONT_STYLE_ITALIC) == 0)
	{
		lf.lfItalic = 1;
	}
	
	if (xscmp(pxf->decorate, GDI_ATTR_FONT_DECORATE_UNDERLINE) == 0)
	{
		lf.lfUnderline = 1;
	}
	else if (xscmp(pxf->decorate, GDI_ATTR_FONT_DECORATE_STRIKOUT) == 0)
	{
		lf.lfStrikeOut = 1;
	}

	if (!is_null(pxf->family))
	{
		xscpy(lf.lfFaceName, pxf->family);
	}

	hFont = CreateFontIndirect(&lf);
	orgFont = (HFONT)SelectObject(hDC, hFont);

	GetTextMetrics(hDC, &tm);

	hFont = (HFONT)SelectObject(hDC, orgFont);
	DeleteObject(hFont);

	if (bRef)
		ReleaseDC(NULL, hDC);

	//pxs->w = tm.tmAveCharWidth;
	pxs->h = tm.tmHeight;
	pxs->w = tm.tmMaxCharWidth;
}

void _gdiplus_draw_image(visual_t rdc,bitmap_t bmp,const xcolor_t* clr,const xrect_t* prt)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb = (win32_bitmap_t*)bmp;

	Image* pi = new Bitmap((HBITMAP)(pwb->bitmap), (HPALETTE)GetStockObject(DEFAULT_PALETTE));
	if (!pi)
		return;

	int srcw = pi->GetWidth();
	int srch = pi->GetHeight();

	ImageAttributes iab;

	if (clr)
	{
		xcolor_t xc_high;

		parse_xcolor(&xc_high, GDI_ATTR_RGB_WHITE);

		iab.SetColorKey(Color(clr->r, clr->g, clr->b), Color(xc_high.r, xc_high.g, xc_high.b));
	}

	RECT rt;
	rt.left = prt->x;
	rt.top = prt->y;
	rt.right = prt->x + prt->w;
	rt.bottom = prt->y + prt->h;

	_adjust_rect(&rt, srcw, srch, GDI_ATTR_TEXT_ALIGN_CENTER, GDI_ATTR_TEXT_ALIGN_CENTER);

	DPtoLP(hDC,(LPPOINT)&rt,2);

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);

	gh.DrawImage(pi,Rect(rt.left,rt.top,rt.right - rt.left,rt.bottom - rt.top),0,0,srcw,srch,UnitPixel,&iab);

	delete pi;
}

void _gdiplus_draw_bitmap(visual_t rdc, bitmap_t bmp, const xpoint_t* ppt)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	win32_bitmap_t* pwb = (win32_bitmap_t*)bmp;

	Image* pi = new Bitmap((HBITMAP)pwb->bitmap, (HPALETTE)GetStockObject(DEFAULT_PALETTE));
	if (!pi)
		return;

	int srcw = pi->GetWidth();
	int srch = pi->GetHeight();

	ImageAttributes iab;
	iab.SetColorKey(Color(250, 250, 250), Color(255, 255, 255));

	POINT pt;
	pt.x = ppt->x;
	pt.y = ppt->y;

	DPtoLP(hDC, (LPPOINT)&pt, 1);

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);

	gh.DrawImage(pi, pt.x, pt.y, 0, 0, srcw, srch, UnitPixel);

	delete pi;
}

void _gdiplus_alphablend_rect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	xbrush_t xb;

	POINT pt[2];
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(hDC, pt, 2);

	default_xbrush(&xb);
	format_xcolor(pxc, xb.color);
	xsprintf(xb.opacity, _T("%d"), opacity);

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);

	Brush* pb = (Brush*)create_brush(&xb, prt, NULL);
	gh.FillRectangle(pb, Rect(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y));

	delete pb;
}

void _gdiplus_gradient_rect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);
	bitmap_t bmp;
	win32_bitmap_t* pwb;

	POINT pt[2];
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(hDC, pt, 2);

	bmp = _create_gradient_bitmap(rdc, clr_brim, clr_core, pt[1].x - pt[0].x, pt[1].y - pt[0].y, gradient);
	if (!bmp)
		return;

	pwb = (win32_bitmap_t*)bmp;

	Bitmap* pbm = new Bitmap(pwb->bitmap, (HPALETTE)GetStockObject(DEFAULT_PALETTE));

	_destroy_bitmap(bmp);

	Brush* pb = new TextureBrush(pbm, Rect(0, 0, pt[1].x - pt[0].x, pt[1].y - pt[0].y));
	delete pbm;

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);

	gh.FillRectangle(pb, Rect(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y));

	delete pb;
}

void _gdiplus_exclude_rect(visual_t rdc, const xrect_t* pxr)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	ExcludeClipRect(hDC, pxr->x, pxr->y, pxr->x + pxr->w, pxr->y + pxr->h);
}

void _gdiplus_fill_region(visual_t rdc, const xbrush_t* pxb, res_rgn_t rgn)
{
	win32_context_t* ctx = (win32_context_t*)rdc;
	HDC hDC = (HDC)(ctx->context);

	Region gn(rgn);

	Brush* pb = create_brush(pxb, NULL, NULL);

	Gdiplus::Graphics gh(hDC);

	gh.SetPageUnit(UnitPixel);

	gh.FillRegion(pb, &gn);

	delete pb;
}


#endif //XDU_SUPPORT_CONTEXT_GRAPHICPLUS
