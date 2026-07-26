/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdiplus document

	@module	if_gdi_win32.c | windows implement file

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

//global fonstset cache
fontset_t g_fontset = NULL;

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

	if (pxp && !xsisnil(pxp->color))
		parse_xcolor(&pen_color,pxp->color);
	else
		parse_xcolor(&pen_color, GDI_ATTR_RGB_GRAY);
		
	if (pxp && !xsisnil(pxp->size))
		sp = xstol(pxp->size);
	else
		sp = 1;	

	Pen* pp = new Pen(Color(pen_color.r,pen_color.g,pen_color.b),(REAL)sp);

	if(pxp && xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASH) == 0)
		pp->SetDashStyle(DashStyleDot);
	else if(pxp && xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
		pp->SetDashStyle(DashStyleDash);

	return pp;
}

static Brush* create_brush(const xbrush_t* pxb, const xrect_t* pxr, GraphicsPath* pgp)
{
	xcolor_t brush_color = {0};
	xcolor_t linear_color = { 0 };
	short opacity;

	if (pxb && !xsisnil(pxb->color))
		parse_xcolor(&brush_color,pxb->color);
	else
		parse_xcolor(&brush_color, GDI_ATTR_RGB_SOFTWHITE);

	if (pxb && !xsisnil(pxb->opacity))
		opacity = xstol(pxb->opacity);
	else
		opacity = 255;

	if (pxb && xscmp(pxb->style, GDI_ATTR_FILL_STYLE_GRADIENT) == 0)
	{
		if (xsisnil(pxb->linear))
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
	else if (pxb && xscmp(pxb->style, GDI_ATTR_FILL_STYLE_HATCH) == 0)
	{
		return new HatchBrush(HatchStyleCross, Color((BYTE)opacity, brush_color.r, brush_color.g, brush_color.b), Color(255, linear_color.r, linear_color.g, linear_color.b));
	}
	else
	{
		return new SolidBrush(Color((BYTE)opacity, brush_color.r, brush_color.g, brush_color.b));
	}

	return NULL;
}

static HFONT create_font(HDC hDC, const xfont_t* pxf)
{
	LOGFONT lf;
	NONCLIENTMETRICS ncm = { 0 };
	ncm.cbSize = sizeof(ncm);
	SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICS), (PVOID)&ncm, 0);

	CopyMemory((void*)&lf, (void*)&ncm.lfCaptionFont, sizeof(LOGFONT));

	float px;
	font_metric_by_pt(xstol(pxf->size), NULL, &px);
	lf.lfHeight = -px;
	lf.lfWeight = xstol(pxf->weight);

	if (xscmp(pxf->style, GDI_ATTR_FONT_STYLE_ITALIC) == 0)
	{
		lf.lfItalic = 1;
	}
	else if (xscmp(pxf->style, GDI_ATTR_FONT_DECORATE_UNDERLINE) == 0)
	{
		lf.lfUnderline = 1;
	}
	else if (xscmp(pxf->style, GDI_ATTR_FONT_DECORATE_STRIKOUT) == 0)
	{
		lf.lfStrikeOut = 1;
	}else
	{
		lf.lfItalic = lf.lfUnderline = lf.lfStrikeOut = 0;
	}

	if (!xsisnil(pxf->family))
	{
		xscpy(lf.lfFaceName, pxf->family);
	}else
	{
		xscpy(lf.lfFaceName, SYSTEM_FONTNAME);
	}

	return CreateFontIndirect(&lf);
}

static StringFormat* create_face(const xface_t* pxa)
{
	StringFormat* psf = new StringFormat;

	if (pxa && xscmp(pxa->line_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		psf->SetLineAlignment(StringAlignmentNear);
	}
	else if (pxa && xscmp(pxa->line_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		psf->SetLineAlignment(StringAlignmentFar);
	}
	else
	{
		psf->SetLineAlignment(StringAlignmentCenter);
	}

	if (pxa && xscmp(pxa->text_align, GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		psf->SetAlignment(StringAlignmentCenter);
	}
	else if (pxa && xscmp(pxa->text_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		psf->SetAlignment(StringAlignmentFar);
	}
	else
	{
		psf->SetAlignment(StringAlignmentNear);
	}

	if(!pxa)
		psf->SetFormatFlags(StringFormatFlagsNoWrap);
	else if (pxa && xsisnil(pxa->text_wrap))
		psf->SetFormatFlags(StringFormatFlagsNoWrap);

	return psf;
}

static GraphicsPath* create_path(HDC hDC, const tchar_t* aa, const xpoint_t* pa, int pn)
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

	while (*aa && pn)
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
		pn -= n;
	}

	return path;
}


void winGdiInit(int osv)
{
	if (!g_token)
	{
		GdiplusStartup(&g_token, &g_input, NULL);
	}

	xfont_t xf;
	default_xfont(&xf);

	g_fontset = winGdiCreateFontset(&xf);
}

void winGdiUnInit(void)
{
	if(g_fontset)
	{
		winGdiDestroyFontset(g_fontset);
		g_fontset = NULL;
	}

	if (g_token)
	{
		GdiplusShutdown(g_token);
		g_token = NULL;
	}
}

void winGdiSetXFont(visual_t rdc, const xfont_t* pxf)
{
	win32_context_t* ctx = (rdc)? TypePtrFromHead(win32_context_t, rdc) : NULL;
	win32_fontset_t* fnt = (rdc)? TypePtrFromHead(win32_fontset_t, ctx->fontset) : TypePtrFromHead(win32_fontset_t, g_fontset);

	LOGFONT lf_new, lf_org = {0};

	GetObject((HGDIOBJ)(fnt->font_object), sizeof(LOGFONT), (void*)&lf_org);
	xmem_copy((void*)&lf_new, (void*)&lf_org, sizeof(LOGFONT));

	float px;
	font_metric_by_pt(xstof(pxf->size), NULL, &px);
	lf_new.lfHeight = -px;
	lf_new.lfWeight = xstol(pxf->weight);

	if (xscmp(pxf->style, GDI_ATTR_FONT_STYLE_ITALIC) == 0)
	{
		lf_new.lfItalic = 1;
	}
	else if (xscmp(pxf->style, GDI_ATTR_FONT_DECORATE_UNDERLINE) == 0)
	{
		lf_new.lfUnderline = 1;
	}
	else if (xscmp(pxf->style, GDI_ATTR_FONT_DECORATE_STRIKOUT) == 0)
	{
		lf_new.lfStrikeOut = 1;
	}else
	{
		lf_new.lfItalic = lf_new.lfUnderline = lf_new.lfStrikeOut = 0;
	}

	if (!xsisnil(pxf->family))
	{
		xscpy(lf_new.lfFaceName, pxf->family);
	}

	if(xscmp(lf_new.lfFaceName,lf_org.lfFaceName) == 0
		&& lf_new.lfHeight == lf_org.lfHeight
		&& lf_new.lfWeight == lf_org.lfWeight
		&& lf_new.lfItalic == lf_org.lfItalic
		&& lf_new.lfUnderline == lf_org.lfUnderline
		&& lf_new.lfStrikeOut == lf_org.lfStrikeOut)
	{
		return;
	}

	DeleteObject((HFONT)fnt->font_object);
	fnt->font_object = (void*)CreateFontIndirect(&lf_new);
}

void winGdiGetXFont(visual_t rdc, xfont_t* pxf)
{
	win32_context_t* ctx = (rdc)? TypePtrFromHead(win32_context_t, rdc) : NULL;
	win32_fontset_t* fnt = (rdc)? TypePtrFromHead(win32_fontset_t, ctx->fontset) : TypePtrFromHead(win32_fontset_t, g_fontset);

	LOGFONT lf = {0};
	GetObject((HGDIOBJ)(fnt->font_object), sizeof(LOGFONT), (void*)&lf);
	if(lf.lfHeight < 0) lf.lfHeight = 0 - lf.lfHeight;

	float pt;
	font_metric_by_px((float)lf.lfHeight, &pt, NULL);
	ftoxs(pt, pxf->size, INT_LEN);

	ltoxs(lf.lfWeight, pxf->weight, INT_LEN);

	if(lf.lfItalic)
	{
		xscpy(pxf->style, GDI_ATTR_FONT_STYLE_ITALIC);
	}else if(lf.lfUnderline)
	{
		xscpy(pxf->style, GDI_ATTR_FONT_DECORATE_UNDERLINE);
	}else if(lf.lfStrikeOut)
	{
		xscpy(pxf->style, GDI_ATTR_FONT_DECORATE_STRIKOUT);
	}else
	{
		xscpy(pxf->style, GDI_ATTR_FONT_DECORATE_NORMAL);
	}

	xscpy(pxf->family, lf.lfFaceName);
}

void winGdiSetPoint(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	HDC hDC = (HDC)(ctx->context);
	COLORREF clr;

	clr = RGB(pxc->r, pxc->g, pxc->b);

	SetPixel(hDC, ppt->x, ppt->y, clr);
}

void winGdiGetPoint(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	HDC hDC = (HDC)(ctx->context);
	COLORREF clr;

	clr = GetPixel(hDC, ppt->x, ppt->y);

	pxc->r = GetRValue(clr);
	pxc->g = GetGValue(clr);
	pxc->b = GetBValue(clr);
}

void winGdiDrawPoints(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n)
{
	NOP;
}

void winGdiDrawLine(visual_t rdc,const xpen_t* pxp, const xpoint_t*ppt1, const xpoint_t* ppt2)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	HDC hDC = (HDC)(ctx->context);

	POINT pt[2];
	pt[0].x = ppt1->x;
	pt[0].y = ppt1->y;
	pt[1].x = ppt2->x;
	pt[1].y = ppt2->y;

	DPtoLP(hDC,pt,2);

	Pen* pp = create_pen(pxp);

	Gdiplus::Graphics gh(hDC);
	gh.SetSmoothingMode(SmoothingModeAntiAlias);
	gh.DrawLine(pp,pt[0].x,pt[0].y,pt[1].x,pt[1].y);
	delete pp;
}

void winGdiDrawPolyline(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int n)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
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
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

	gh.DrawPath(pp, &path);

	delete pp;
}

void winGdiDrawArc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t clockwise, bool_t largearc)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
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

	pt_calc_radian(clockwise, largearc, rx, ry, &xp[0], &xp[1], &xp[2], &fang, &tang);

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
	gh.SetSmoothingMode(SmoothingModeHighQuality);

	Pen* pp = create_pen(pxp);

	gh.SetCompositingQuality(CompositingQualityGammaCorrected);
	gh.DrawArc(pp, rf, fdeg, sdeg);

	delete pp;
}

void winGdiDrawBezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
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
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

	Pen* pp = (Pen*)create_pen(pxp);
	gh.SetCompositingQuality(CompositingQualityGammaCorrected);
	gh.DrawBezier(pp, pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);

	delete pp;
}

void winGdiDrawCurve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int n)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
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
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

	Pen* pp = (Pen*)create_pen(pxp);
	gh.SetCompositingQuality(CompositingQualityGammaCorrected);
	gh.DrawCurve(pp, pa, n);

	delete[]pa;

	delete pp;
}

void winGdiDrawRect(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	HDC hDC = (HDC)(ctx->context);

	POINT pt[2];
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(hDC, pt, 2);

	Gdiplus::Graphics gh(hDC);

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

void winGdiDrawRound(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt, const xsize_t* pxs)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
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
	gh.SetSmoothingMode(SmoothingModeHighQuality);

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

void winGdiDrawEllipse(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	HDC hDC = (HDC)(ctx->context);

	POINT pt[2];
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(hDC, pt, 2);

	Gdiplus::Graphics gh(hDC);
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

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

void winGdiDrawPie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt, double fang, double tang)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
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
	gh.SetSmoothingMode(SmoothingModeHighQuality);

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

void winGdiDrawPolygon(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, int n)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
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
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

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

void winGdiDrawPath(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	HDC hDC = (HDC)(ctx->context);

	GraphicsPath* path = create_path(hDC, aa, pa, pn);

	if (!path) return;

	Gdiplus::Graphics gh(hDC);
	gh.SetSmoothingMode(SmoothingModeAntiAlias);

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

void winGdiDrawText(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	win32_fontset_t* fnt = TypePtrFromHead(win32_fontset_t, ctx->fontset);
	HDC hDC = (HDC)(ctx->context);

	if (len < 0) len = xslen(txt);
	if(!len) return;

	RECT rt;
	rt.left = prt->x;
	rt.top = prt->y;
	rt.right = prt->x + prt->w;
	rt.bottom = prt->y + prt->h;

	DPtoLP(hDC, (LPPOINT)&rt, 2);

	DWORD dw = 0;
	if (pxa)
	{
		if (xscmp(pxa->line_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
			dw |= DT_TOP;
		else if (xscmp(pxa->line_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0)
			dw |= DT_BOTTOM;
		else
			dw |= DT_VCENTER;

		if (xscmp(pxa->text_align, GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
			dw |= DT_CENTER;
		else if (xscmp(pxa->text_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0)
			dw |= DT_RIGHT;
		else
			dw |= DT_LEFT;

		if (!xsisnil(pxa->text_wrap))
			dw |= DT_WORDBREAK;
		else
			dw |= DT_SINGLELINE;
	}
	else
	{
		dw = DT_LEFT | DT_VCENTER | DT_SINGLELINE;
	}

	HFONT hFont, orgFont;
	hFont = (HFONT)fnt->font_object;
	orgFont = (HFONT)SelectObject(hDC, hFont);

	COLORREF orgClr;
	if(pxa)
	{
		xcolor_t xc;
		parse_xcolor(&xc, pxa->text_color);
		orgClr = SetTextColor(hDC, RGB(xc.r, xc.g, xc.b));
	}

	rt.left += 1;
	rt.right -= 1;
	rt.top += 1;
	rt.bottom -= 1;
	DrawText(hDC, txt, len, &rt, dw);

	if(pxa)
	{
		SetTextColor(hDC, orgClr);
	}

	hFont = (HFONT)SelectObject(hDC, orgFont);
}

void winGdiTextOut(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	win32_fontset_t* fnt = TypePtrFromHead(win32_fontset_t, ctx->fontset);
	HDC hDC = (HDC)(ctx->context);
	
	HFONT hFont, orgFont;
	COLORREF clr, orgClr;
	xcolor_t xc;

	if (len < 0) len = xslen(txt);
	if(!len) return;

	hFont = (HFONT)fnt->font_object;
	orgFont = (HFONT)SelectObject(hDC, hFont);

	if (pxa)
	{
		parse_xcolor(&xc, pxa->text_color);
		clr = RGB(xc.r, xc.g, xc.b);
		orgClr = SetTextColor(hDC, clr);
	}

	TextOut(hDC, ppt->x, ppt->y, txt, len);

	if (pxa)
	{
		SetTextColor(hDC, orgClr);
	}

	hFont = (HFONT)SelectObject(hDC, orgFont);
}

void winGdiTextRect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt)
{
	win32_context_t* ctx = (rdc)? TypePtrFromHead(win32_context_t, rdc) : NULL;
	fontset_t fnt;

	int c, n = 0, total = 0;
	tchar_t pch[CHS_LEN + 1] = {0};
	xsize_t se;
	int w, h, maxw = 0;

	if(len < 0) len = xslen(txt);
	if(!len) return;

	if(pxf)
	{
		fnt = winGdiCreateFontset(pxf);
	}else
	{
		fnt = (rdc)? ctx->fontset : g_fontset;
	}

	if(!fnt) return;

	w = 0;
	h = 0;
	n = 0;
	while (n++ < len)
	{
		c = peek_word((txt + total), pch);
		total += c;

		winGdiWordSize(fnt, pch, c, &se);

		if (!h)
		{
			if (xsisnil(pxa->line_height))
				h = se.h;
			else
				h = (int)((float)se.h * xstof(pxa->line_height));
		}

		if (pxa && compare_text(pxa->text_wrap, -1, GDI_ATTR_TEXT_WRAP_WORDBREAK, -1, 1) == 0)
		{
			if (prt->w && (w + se.w > prt->w))
			{
				if (xsisnil(pxa->line_height))
					h += se.h;
				else
					h += (int)((float)se.h * xstof(pxa->line_height));

				w = 0;
				total -= c;
				n--;
			}
			else
			{
				w += se.w;
			}
		}
		else if (pxa && compare_text(pxa->text_wrap, -1, GDI_ATTR_TEXT_WRAP_LINEBREAK, -1, 1) == 0)
		{
			if (pch[0] == _T('\n'))
			{
				if (xsisnil(pxa->line_height))
					h += se.h;
				else
					h += (int)((float)se.h * xstof(pxa->line_height));

				w = 0;
			}
			else if (prt->w && (w + se.w > prt->w))
			{
				if (xsisnil(pxa->line_height))
					h += se.h;
				else
					h += (int)((float)se.h * xstof(pxa->line_height));

				w = 0;
				total -= xslen(pch);
				n--;
			}
			else
			{
				w += se.w;
			}
		}
		else
		{
			w += se.w;
		}

		if (maxw < w) maxw = w;
	}

	prt->h = h;
	if (!prt->w) prt->w = maxw;

	if(pxf)
	{
		winGdiDestroyFontset(fnt);
	}
}

void winGdiTextSize(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
	win32_context_t* ctx = (rdc)? TypePtrFromHead(win32_context_t, rdc) : NULL;
	win32_fontset_t* fnt = (rdc)? TypePtrFromHead(win32_fontset_t, ctx->fontset) : TypePtrFromHead(win32_fontset_t, g_fontset);
	HDC hDC = (ctx)? (HDC)(ctx->context) : GetDC(NULL);
	HFONT hFont, orgFont;
	SIZE si;

	if (len < 0) len = xslen(txt);
	if(!len)  return;

	if(pxf)
	{
		hFont = create_font(hDC, pxf);
	}else
	{
		hFont = (HFONT)fnt->font_object;
	}

	orgFont = (HFONT)SelectObject(hDC, hFont);

	GetTextExtentPoint32(hDC, txt, len, &si);

	hFont = (HFONT)SelectObject(hDC, orgFont);

	if(pxf) DeleteObject(hFont);

	if (!ctx) ReleaseDC(NULL, hDC);

	pxs->w = si.cx;
	pxs->h = si.cy;
}

void winGdiFontSize(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
	win32_context_t* ctx = (rdc)? TypePtrFromHead(win32_context_t, rdc) : NULL;
	win32_fontset_t* fnt = (rdc)? TypePtrFromHead(win32_fontset_t, ctx->fontset) : TypePtrFromHead(win32_fontset_t, g_fontset);
	
	HDC hDC = (ctx)? (HDC)(ctx->context) : GetDC(NULL);
	
	HFONT hFont, orgFont;
	TEXTMETRIC tm = { 0 };

	if(pxf)
	{
		hFont = create_font(hDC, pxf);
	}else
	{
		hFont = (HFONT)fnt->font_object;
	}

	orgFont = (HFONT)SelectObject(hDC, hFont);

	GetTextMetrics(hDC, &tm);

	hFont = (HFONT)SelectObject(hDC, orgFont);

	if(pxf) DeleteObject(hFont);

	if (!ctx) ReleaseDC(NULL, hDC);

	pxs->w = tm.tmAveCharWidth;
	pxs->h = tm.tmHeight;
}

/**************************************************************************************** */

void winGdiDrawImage(visual_t rdc,bitmap_t bmp,const xcolor_t* clr,const xrect_t* prt)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
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

	gh.DrawImage(pi,Rect(rt.left,rt.top,rt.right - rt.left,rt.bottom - rt.top),0,0,srcw,srch,UnitPixel,&iab);

	delete pi;
}

void winGdiDrawBitmap(visual_t rdc, bitmap_t bmp, const xpoint_t* ppt)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
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

	gh.DrawImage(pi, pt.x, pt.y, 0, 0, srcw, srch, UnitPixel);

	delete pi;
}

void winGdiAlphablendRect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
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

	Brush* pb = (Brush*)create_brush(&xb, prt, NULL);
	gh.FillRectangle(pb, Rect(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y));

	delete pb;
}

void winGdiGradientRect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	HDC hDC = (HDC)(ctx->context);
	bitmap_t bmp;
	win32_bitmap_t* pwb;

	POINT pt[2];
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(hDC, pt, 2);

	bmp = winCreateGradientBitmap(rdc, clr_brim, clr_core, pt[1].x - pt[0].x, pt[1].y - pt[0].y, gradient);
	if (!bmp)
		return;

	pwb = (win32_bitmap_t*)bmp;

	Bitmap* pbm = new Bitmap(pwb->bitmap, (HPALETTE)GetStockObject(DEFAULT_PALETTE));

	winDestroyBitmap(bmp);

	Brush* pb = new TextureBrush(pbm, Rect(0, 0, pt[1].x - pt[0].x, pt[1].y - pt[0].y));
	delete pbm;

	Gdiplus::Graphics gh(hDC);

	gh.FillRectangle(pb, Rect(pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y));

	delete pb;
}

void winGdiInvertRect(visual_t rdc, const xrect_t* pxr)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	HDC hDC = (HDC)(ctx->context);
	RECT rt;

	rt.left = pxr->x;
	rt.top = pxr->y;
	rt.right = pxr->x + pxr->w;
	rt.bottom = pxr->y + pxr->h;

	InvertRect(hDC, &rt);
}

void winGdiExcludeRect(visual_t rdc, const xrect_t* pxr)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	HDC hDC = (HDC)(ctx->context);

	ExcludeClipRect(hDC, pxr->x, pxr->y, pxr->x + pxr->w, pxr->y + pxr->h);
}

void winGdiInclipRect(visual_t rdc, const xrect_t* pxr)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);
	HDC hDC = (HDC)(ctx->context);

	Gdiplus::Graphics gh(hDC);

	gh.SetClip(Gdiplus::Rect(pxr->x, pxr->y, pxr->w, pxr->h));
}

/************************************************************************************ */
fontset_t winGdiGetFontset(visual_t rdc)
{
	win32_context_t* ctx = TypePtrFromHead(win32_context_t, rdc);

	return ctx->fontset;
}

fontset_t winGdiCreateFontset(const xfont_t* pxf)
{
	win32_fontset_t* fst;

	HDC hDC = GetDC(NULL);
	HFONT gdi_font = create_font(hDC, pxf);

	fst = (win32_fontset_t*)xmem_alloc_handle(sizeof(win32_fontset_t));
	fst->head.tag = _HANDLE_FONTSET;
	fst->font_object = (void*)gdi_font;

	ReleaseDC(NULL, hDC);

	return (fontset_t)&(fst->head);
}

void winGdiDestroyFontset(fontset_t ft)
{
	win32_fontset_t* fst = TypePtrFromHead(win32_fontset_t, ft);

	if(fst && fst->font_object) DeleteObject((HFONT)(fst->font_object));

	if(fst) xmem_free_handle(&(fst->head));
}

void winGdiWordSize(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs)
{
	win32_fontset_t* fst = TypePtrFromHead(win32_fontset_t, ft);
	HDC hDC;
	HFONT hFont, orgFont;
	SIZE si;

	hDC = GetDC(NULL);
	hFont = (HFONT)fst->font_object;

	orgFont = (HFONT)SelectObject(hDC, hFont);
	GetTextExtentPoint32(hDC, pch, chs, &si);
	hFont = (HFONT)SelectObject(hDC, orgFont);
	
	ReleaseDC(NULL, hDC);

	pxs->w = si.cx;
	pxs->h = si.cy;
}

