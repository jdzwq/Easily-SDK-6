/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdi document

	@module	xl_gdi.c | GDI X11 implement file

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

#include "_if_X11.h"

fontset_t g_fontset = NULL;


static tchar_t *x11_font_name[] = {_T("Fixed")};
static tchar_t *x11_font_weight[] = {_T("Regular"),_T("Medium"), _T("Bold")};
static tchar_t *x11_font_style[]  = {_T("Regular"), _T("Italic"), _T("Oblique")};
static tchar_t *x11_font_size[] = {_T("9"),_T("10"),_T("12"),_T("13"),_T("14"),_T("15"),_T("16"),_T("18"), _T("24") ,_T("26"), _T("36"), _T("42"), _T("54"), _T("63"), _T("72")};
static tchar_t x11_pattern[] = {_T("%s-%s-%s-%s")};
//font pattern <family>[-<style>][-<weight>][-<size>]
//font pattern eg: -misc-fixed-medium-r-normal--10-100-75-75-c-60-iso8859-1
//font pattern eg: -*-helvetica-*-*-*-*-12-*-*-*-*-*-*

#define default_fixed_pattern	_T("fixed")

static void format_font_pattern(const xfont_t* pxf, tchar_t* buf)
{
    const tchar_t* fs_name = NULL;
    const tchar_t* fs_style = NULL;
    const tchar_t* fs_weight = NULL;
	const tchar_t* fs_size = NULL;
    float pt, px = 0;
	int i;
    
    if(xsisnil((pxf->family)))
        fs_name = x11_font_name[0];
    else
        fs_name = pxf->family;

	xscpy(buf, fs_name);

	if(xscmp(pxf->style,GDI_ATTR_FONT_STYLE_ITALIC) == 0)
        fs_style = x11_font_style[1];
    else if(xscmp(pxf->style,GDI_ATTR_FONT_STYLE_OBLIQUE) == 0)
        fs_style = x11_font_style[2];
    else
        fs_style = NULL;

	if(fs_style)
	{
		xscat(buf, _T("-"));
		xscat(buf, fs_style);
	}
    
    if(xstol(pxf->weight) >= 700)
        fs_weight = x11_font_weight[2];
    else if(xstol(pxf->weight) >= 400)
        fs_weight = x11_font_weight[1];
    else
        fs_weight = NULL;

	if(fs_weight)
	{
		xscat(buf, _T("-"));
		xscat(buf, fs_weight);
	}

	if(!xsisnil(pxf->size))
	{
		pt = xstof(pxf->size);
		font_metric_by_pt(pt, NULL, &px);
    
		for(i = 0; i< 15; i++)
		{
			if((int)px <= xstol(x11_font_size[i]))
				break;
		}
		if(i == 15) i--;
	
		fs_size = x11_font_size[i];
	}else
	{
		fs_size = NULL;
	}

	if(fs_size)
	{
		xscat(buf, _T("-"));
		xscat(buf, fs_size);
	}
}

static void DPtoLP(visual_t rdc, XPoint* pt,int n)
{
	int i;
	for(i = 0;i<n;i++)
	{
		pt[i].x = pt[i].x;
		pt[i].y = pt[i].y;
	}
}

static void _adjust_rect(XRectangle* prt, int src_width, int src_height, const tchar_t* horz_align, const tchar_t* vert_align)
{
	if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0 && xscmp(vert_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		NOP;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		prt->y += (prt->height - src_height);
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		prt->x += (prt->width - src_width);
	}
	else if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		prt->x += (prt->width - src_width);
		prt->y += (prt->height - src_height);
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		prt->y += (prt->height - src_height) / 2;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		prt->x += (prt->width - src_width);
		prt->y += (prt->height - src_height) / 2;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		prt->x += (prt->width - src_width) / 2;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		prt->x += (prt->width - src_width) / 2;
		prt->y += (prt->height - src_height);
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		prt->x += (prt->width - src_width) / 2;
		prt->y += (prt->height - src_height) / 2;
	}

	prt->width = (prt->width < src_width) ? prt->width : src_width;
	prt->height = (prt->height < src_height) ? prt->height : src_height;
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

void xlGdiInit(int osv)
{
	xfont_t xf;

	default_xfont(&xf);
	g_fontset = xlGdiCreateFontset(&xf);
}

void xlGdiUnInit(void)
{
	if(g_fontset) xlGdiDestroyFontset(g_fontset);

	g_fontset = NULL;
}

void xlGdiSetXFont(visual_t rdc, const xfont_t* pxf)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);
	X11_fontset_t* fnt = (rdc)? TypePtrFromHead(X11_fontset_t, ctx->fontset) : NULL;
	XftFont* xft_font;
	char* family = NULL;
	double size = 0.0;
	int weight = 0;
	int slant;
	tchar_t style[20] = {0};

	if(!ctx) return;

	xft_font = (fnt)? (XftFont*)fnt->font_object : NULL;
	if(xft_font &&xft_font->pattern)
	{
		FcPatternGetString(xft_font->pattern, FC_FAMILY, 0, (FcChar8 **)&family);
		FcPatternGetDouble(xft_font->pattern, FC_SIZE, 0, &size);
		FcPatternGetInteger(xft_font->pattern, FC_WEIGHT, 0, &weight);
		FcPatternGetInteger(xft_font->pattern, FC_SLANT, 0, &slant);
		if(slant == FC_SLANT_ITALIC)
			xscpy(style, GDI_ATTR_FONT_STYLE_ITALIC);
		else if(slant == FC_SLANT_OBLIQUE)
			xscpy(style, GDI_ATTR_FONT_STYLE_OBLIQUE);
		else
			xscpy(style, GDI_ATTR_FONT_STYLE_REGULAR);
	}

	if(size == xstof(pxf->size) && weight == xstol(pxf->weight) && xsicmp(style, pxf->style) == 0 && (xsisnil(pxf->family) || xsicmp(family, pxf->family) == 0))
	{
		return;
	}

	if(g_fontset)
	{
		xlGdiDestroyFontset(g_fontset);
		g_fontset = NULL;
	}

    g_fontset = xlGdiCreateFontset(pxf);
	ctx->fontset = g_fontset;
}

void xlGdiGetXFont(visual_t rdc, xfont_t* pxf)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);
	X11_fontset_t* fnt = (rdc)? TypePtrFromHead(X11_fontset_t, ctx->fontset) : NULL;

	XftFont* xft_font;
	char* family = NULL;
	double size = 0.0;
	int weight = 0;
	int slant;

	if(!ctx) return;
	xft_font = (XftFont*)fnt->font_object;
	if(!xft_font->pattern) return;

	FcPatternGetString(xft_font->pattern, FC_FAMILY, 0, (FcChar8 **)&family);
	if(family) xscpy(pxf->family, family);

	FcPatternGetDouble(xft_font->pattern, FC_SIZE, 0, &size);
	ftoxs((float)size, pxf->size, NUM_LEN);

	FcPatternGetInteger(xft_font->pattern, FC_WEIGHT, 0, &weight);
	ltoxs(weight, pxf->weight, NUM_LEN);

	FcPatternGetInteger(xft_font->pattern, FC_SLANT, 0, &slant);
	if(slant == FC_SLANT_ITALIC)
		xscpy(pxf->style, GDI_ATTR_FONT_STYLE_ITALIC);
	else if(slant == FC_SLANT_OBLIQUE)
		xscpy(pxf->style, GDI_ATTR_FONT_STYLE_OBLIQUE);
	else
		xscpy(pxf->style, GDI_ATTR_FONT_STYLE_REGULAR);
}

void xlGdiGetPoint(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt)
{

}

void xlGdiSetPoint(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt)
{

}

void xlGdiDrawPoints(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	XColor ext, clr_pen = {0};
	XPoint* ppp;
	int i;

	ppp = (XPoint*)xmem_alloc(n * sizeof(XPoint));

	for(i=0;i<n;i++)
	{
		ppp[i].x = ppt[i].x;
		ppp[i].y = ppt[i].y;
	}

	DPtoLP(rdc,ppp,n);

	if(pxc)
	{
		clr_pen.red = XRGB(pxc->r);
		clr_pen.green = XRGB(pxc->g);
		clr_pen.blue = XRGB(pxc->b);

		XAllocColor(g_display, ctx->color, &clr_pen);
		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);
	}

	XDrawPoints(g_display, ctx->device, ctx->context, ppp, n, CoordModeOrigin);

	xmem_free(ppp);
}

void xlGdiDrawLine(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2)
{
    X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	xcolor_t xc = {0};
	int l_w, l_s;
	XColor ext, clr_pen = {0};
    
	XPoint pt[2];
	pt[0].x = ppt1->x;
	pt[0].y = ppt1->y;
	pt[1].x = ppt2->x;
	pt[1].y = ppt2->y;

	DPtoLP(rdc,pt,2);

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);

		clr_pen.red = XRGB(xc.r);
		clr_pen.green = XRGB(xc.g);
		clr_pen.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_pen);
		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);
	}else
	{
		l_w = 1;
		l_s = LineSolid;
	}

	XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapRound, JoinRound);

    XDrawLine(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x, pt[1].y);
}

void xlGdiDrawPolyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	xcolor_t xc = {0};
	int l_w, l_s;
	XColor ext, clr_pen = {0};
    
	XPoint* pa;
	int i;
	
	if(!n) return;

	pa = (XPoint*)xmem_alloc(n * sizeof(XPoint));
	for(i =0;i<n;i++)
	{
		pa[i].x = ppt[i].x;
		pa[i].y = ppt[i].y;
	}
	DPtoLP(rdc,pa,n);

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);

		clr_pen.red = XRGB(xc.r);
		clr_pen.green = XRGB(xc.g);
		clr_pen.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_pen);
		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);
	}else
	{
		l_w = 1;
		l_s = LineSolid;
	}

	XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapRound, JoinRound);

    XDrawLines(g_display, ctx->device, ctx->context, pa, n, CoordModeOrigin);

	xmem_free(pa);
}

void xlGdiDrawArc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t closewise, bool_t largearc)
{
    X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	xcolor_t xc = {0};
	int l_w, l_s;
	XColor ext, clr_brush = {0}, clr_pen = {0};

	XPoint pt[4] = {0};

	float fdeg, sdeg;
	int x, y, w, h;

	xpoint_t xp[3];
	double arcf, arct;
	int rx, ry;
    
	pt[0].x = ppt1->x;
	pt[0].y = ppt1->y;
	pt[1].x = ppt2->x;
	pt[1].y = ppt2->y;
	pt[2].x = pxs->w;
	pt[2].y = pxs->h;

	DPtoLP(rdc,pt,3);

	xp[0].x = pt[0].x;
	xp[0].y = pt[0].y;
	xp[1].x = pt[1].x;
	xp[1].y = pt[1].y;
	rx = pt[2].x;
	ry = pt[2].y;

	pt_calc_radian(closewise, largearc, rx, ry, &xp[0], &xp[1], &xp[2], &arcf, &arct);

	x = xp[2].x - rx;
	y = xp[2].y - ry;
	w = rx * 2;
	h = ry * 2;

	radian_to_degree(arcf, arct, &fdeg, &sdeg);
	//Positive angles indicate counterclockwise motion, and negative angles indicate clockwise motion
	fdeg = 360 - fdeg;
	sdeg = 0 - sdeg;
	
	fdeg *= 64;
	sdeg *= 64;

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);

		clr_pen.red = XRGB(xc.r);
		clr_pen.green = XRGB(xc.g);
		clr_pen.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_pen);
		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);
	}else
	{
		l_s = LineSolid;
		l_w = 1;
	}
	
	XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapNotLast, JoinMiter);
	
	XDrawArc(g_display, ctx->device, ctx->context, x, y, w, h, (int)fdeg, (int)sdeg);
}

void xlGdiDrawBezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
	int n, fs, ds;
	xpoint_t pt[3];
	xpoint_t *ppt;
	xcolor_t xc;

	calc_penmode(pxp, &fs, &ds);

	pt[0].x = ppt2->x, pt[0].y = ppt2->y;
	pt[1].x = ppt3->x, pt[1].y = ppt3->y;
	pt[2].x = ppt4->x, pt[2].y = ppt4->y;
	pt_screen_to_world(*ppt1, pt, 3);

	n = dot_curve3(fs, ds, &pt[0], &pt[1], &pt[2], NULL, MAX_LONG);
	ppt = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
	n = dot_curve3(fs, ds, &pt[0], &pt[1], &pt[2], ppt, n);

	pt_world_to_screen(*ppt1, ppt, n);

	parse_xcolor(&xc, pxp->color);

	xlGdiDrawPoints(rdc, &xc, ppt, n);

	xmem_free(ppt);
}

void xlGdiDrawCurve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn)
{
   int n, fs, ds;
	xpoint_t pt[3];
	xpoint_t *ppt_buf;
	xcolor_t xc;

	calc_penmode(pxp, &fs, &ds);

	if(pn == 4)
	{
		pt[0].x = ppt[1].x, pt[0].y = ppt[1].y;
		pt[1].x = ppt[2].x, pt[1].y = ppt[2].y;
		pt[2].x = ppt[3].x, pt[2].y = ppt[3].y;
		pt_screen_to_world(ppt[0], pt, 3);

		n = dot_curve3(fs, ds, &pt[0], &pt[1], &pt[2], NULL, MAX_LONG);
		ppt_buf = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
		n = dot_curve3(fs, ds, &pt[0], &pt[1], &pt[2], ppt_buf, n);
	}else if(pn == 3)
	{
		pt[0].x = ppt[1].x, pt[0].y = ppt[1].y;
		pt[1].x = ppt[2].x, pt[1].y = ppt[2].y;
		pt_screen_to_world(ppt[0], pt, 2);

		n = dot_curve2(fs, ds, &pt[0], &pt[1], NULL, MAX_LONG);
		ppt_buf = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
		n = dot_curve2(fs, ds, &pt[0], &pt[1], ppt_buf, n);
	}else
	{
		ppt_buf = NULL;
		n = 0;
	}

	if(!n) return;
	
	pt_world_to_screen(ppt[0], ppt_buf, n);

	parse_xcolor(&xc, pxp->color);
	xlGdiDrawPoints(rdc, &xc, ppt_buf, n);

	xmem_free(ppt_buf); 
}

void xlGdiDrawPath(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn)
{
	xpoint_t pt_m = { 0 };
	xpoint_t pt_p = { 0 };
	xpoint_t pt_i = { 0 };
	xpoint_t pt[4] = { 0 };

	int sflag, lflag;
	double arcf, arct;
	int n = 0;
	xsize_t xs;

	if (!aa)
		return;

	while (*aa || pn)
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

			xlGdiDrawLine(rdc, pxp, &pt[0], &pt[1]);
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

			xlGdiDrawLine(rdc, pxp, &pt[0], &pt[1]);
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

			xlGdiDrawCurve(rdc, pxp, pt, 3);
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

			xlGdiDrawCurve(rdc, pxp, pt, 3);
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

			xlGdiDrawCurve(rdc, pxp, pt, 3);
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

			xlGdiDrawCurve(rdc, pxp, pt, 3);
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

			xlGdiDrawBezier(rdc, pxp, &pt[0], &pt[1], &pt[2], &pt[3]);
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

			xlGdiDrawBezier(rdc, pxp, &pt[0], &pt[1], &pt[2], &pt[3]);
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

			xlGdiDrawBezier(rdc, pxp, &pt[0], &pt[1], &pt[2], &pt[3]);
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

			xlGdiDrawBezier(rdc, pxp, &pt[0], &pt[1], &pt[2], &pt[3]);
			n = 2;
		}
		else if (*aa == _T('A'))
		{
			sflag = pa[0].x;
			lflag = pa[0].y;
			xs.w = pa[1].x;
			xs.h = pa[1].y;
			
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pa[2].x;
			pt[1].y = pa[2].y;

			pt_p.x = pt[1].x;
			pt_p.y = pt[1].y;
			pt_i.x = 2 * pt[1].x - pt[0].x;
			pt_i.y = 2 * pt[1].y - pt[0].y;

			xlGdiDrawArc(rdc, pxp, &pt[0], &pt[1], &xs, sflag, lflag);
			n = 3;
		}
		else if (*aa == _T('Z') || *aa == _T('z'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_m.x;
			pt[1].y = pt_m.y;

			xlGdiDrawLine(rdc, pxp, &pt[0], &pt[1]);

			break;
		}

		aa++;
		pa += n;
		pn -= n;
	}
}

void xlGdiDrawRect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	xcolor_t xc = {0};
	int l_w, l_s;
	XColor ext, clr_brush = {0}, clr_pen = {0};

	XPoint pt[2];
    
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(rdc,pt,2);

	if(pxb)
	{
		parse_xcolor(&xc,pxb->color);

		clr_brush.red = XRGB(xc.r);
		clr_brush.green = XRGB(xc.g);
		clr_brush.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_brush);
		XSetForeground(g_display, ctx->context, clr_brush.pixel);
		XFreeColors(g_display, ctx->color, &(clr_brush.pixel), 1, 0);

		XSetFillRule(g_display, ctx->context, EvenOddRule);
		XSetFillStyle(g_display, ctx->context, FillOpaqueStippled);
    
		XFillRectangle(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);

		clr_pen.red = XRGB(xc.r);
		clr_pen.green = XRGB(xc.g);
		clr_pen.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_pen);
		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);

		XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapNotLast, JoinMiter);
		
		XDrawRectangle(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);
	}
}

void xlGdiDrawTriangle(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const tchar_t* orient)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	xpoint_t pt[3];

	if (compare_text(orient, -1, GDI_ATTR_ORIENT_TOP, -1, 1) == 0)
	{
		pt[0].x = pxr->x, pt[0].y = pxr->y + pxr->h;
		pt[1].x = pxr->x + pxr->w / 2, pt[1].y = pxr->y;
		pt[2].x = pxr->x + pxr->w, pt[2].y = pxr->y + pxr->h;
	}
	else if (compare_text(orient, -1, GDI_ATTR_ORIENT_RIGHT, -1, 1) == 0)
	{
		pt[0].x = pxr->x, pt[0].y = pxr->y;
		pt[1].x = pxr->x + pxr->w, pt[1].y = pxr->y + pxr->h / 2;
		pt[2].x = pxr->x, pt[2].y = pxr->y + pxr->h;
	}
	else if (compare_text(orient, -1, GDI_ATTR_ORIENT_BOTTOM, -1, 1) == 0)
	{
		pt[0].x = pxr->x, pt[0].y = pxr->y;
		pt[1].x = pxr->x + pxr->w, pt[1].y = pxr->y;
		pt[2].x = pxr->x + pxr->w / 2, pt[2].y = pxr->y + pxr->h;
	}
	else if (compare_text(orient, -1, GDI_ATTR_ORIENT_LEFT, -1, 1) == 0)
	{
		pt[0].x = pxr->x + pxr->w, pt[0].y = pxr->y;
		pt[1].x = pxr->x + pxr->w, pt[1].y = pxr->y + pxr->h;
		pt[2].x = pxr->x, pt[2].y = pxr->y + pxr->h / 2;
	}

	xlGdiDrawLine(rdc, pxp, &pt[0], &pt[1]);
	xlGdiDrawLine(rdc, pxp, &pt[1], &pt[2]);
	xlGdiDrawLine(rdc, pxp, &pt[2], &pt[0]);
}

void xlGdiDrawRound(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	tchar_t ta[10] = {0};
	xpoint_t pa[16];
	int rx, ry;

	if(!pxs)
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
	}else
	{
		rx = pxs->w;
		ry = pxs->h;
	}

	ta[0] = _T('M');
	pa[0].x = prt->x, pa[0].y = prt->y + ry;

	ta[1] = _T('A');
	pa[1].x = 1, pa[1].y = 0; //clockwise and small arc
	pa[2].x = rx, pa[2].y = ry;
	pa[3].x = prt->x + rx, pa[3].y = prt->y;
	
	ta[2] = _T('L');
	pa[4].x = prt->x + prt->w - rx, pa[4].y = prt->y;

	ta[3] = _T('A');
	pa[5].x = 1, pa[5].y = 0; //clockwise and small arc
	pa[6].x = rx, pa[6].y = ry;
	pa[7].x = prt->x + prt->w, pa[7].y = prt->y + ry;

	ta[4] = _T('L');
	pa[8].x = prt->x + prt->w, pa[8].y = prt->y + prt->h - ry;

	ta[5] = _T('A');
	pa[9].x = 1, pa[9].y = 0; //clockwise and small arc
	pa[10].x = rx, pa[10].y = ry;
	pa[11].x = prt->x + prt->w - rx, pa[11].y = prt->y + prt->h;

	ta[6] = _T('L');
	pa[12].x = prt->x + rx, pa[12].y = prt->y + prt->h;

	ta[7] = _T('A');
	pa[13].x = 1, pa[13].y = 0; //clockwise and small arc
	pa[14].x = rx, pa[14].y = ry;
	pa[15].x = prt->x, pa[15].y = prt->y + prt->h - ry;

	ta[8] = _T('Z');

	xlGdiDrawPath(rdc, pxp, pxb, ta, pa, 16);
}

void xlGdiDrawEllipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	xcolor_t xc = {0};
	int l_w, l_s;
	XColor ext, clr_brush = {0}, clr_pen = {0};

	XPoint pt[2];
    
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(rdc,pt,2);

	if(pxb)
	{
		parse_xcolor(&xc,pxb->color);

		clr_brush.red = XRGB(xc.r);
		clr_brush.green = XRGB(xc.g);
		clr_brush.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_brush);
		XSetForeground(g_display, ctx->context, clr_brush.pixel);
		XFreeColors(g_display, ctx->color, &(clr_brush.pixel), 1, 0);

		XSetFillRule(g_display, ctx->context, EvenOddRule);
		XSetFillStyle(g_display, ctx->context, FillOpaqueStippled);
    
		XFillArc(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y, 0, 360 * 64);
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);

		clr_pen.red = XRGB(xc.r);
		clr_pen.green = XRGB(xc.g);
		clr_pen.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_pen);
		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);

		XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapNotLast, JoinMiter);
		
		XDrawArc(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y, 0, 360 * 64);
	}
}

void xlGdiDrawPie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	xcolor_t xc = {0};
	int l_w, l_s;
	XColor ext, clr_brush = {0}, clr_pen = {0};

	XPoint pt[2];

	float fdeg, sdeg;
    
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(rdc,pt,2);

	radian_to_degree(arcf, arct, &fdeg, &sdeg);
	//Positive angles indicate counterclockwise motion, and negative angles indicate clockwise motion
	fdeg = 360 - fdeg;
	sdeg = 0 - sdeg;
	
	fdeg *= 64;
	sdeg *= 64;

	if(pxb)
	{
		parse_xcolor(&xc,pxb->color);

		clr_brush.red = XRGB(xc.r);
		clr_brush.green = XRGB(xc.g);
		clr_brush.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_brush);
		XSetForeground(g_display, ctx->context, clr_brush.pixel);
		XFreeColors(g_display, ctx->color, &(clr_brush.pixel), 1, 0);

		XSetFillRule(g_display, ctx->context, EvenOddRule);
		XSetFillStyle(g_display, ctx->context, FillOpaqueStippled);
    
		XFillArc(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y, (int)fdeg, (int)sdeg);
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);

		clr_pen.red = XRGB(xc.r);
		clr_pen.green = XRGB(xc.g);
		clr_pen.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_pen);
		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);

		XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapNotLast, JoinMiter);
		
		XDrawArc(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y, (int)fdeg, (int)sdeg);
	}
}

void xlGdiDrawPolygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n)
{
    X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	xcolor_t xc = {0};
	int l_w, l_s;
	XColor ext, clr_brush = {0}, clr_pen = {0};

	XPoint* pa;
	int i;

	pa = (XPoint*)xmem_alloc((n + 1) * sizeof(XPoint));
	for(i =0;i<n;i++)
	{
		pa[i].x = ppt[i].x;
		pa[i].y = ppt[i].y;
	}
	pa[n].x = ppt[0].x;
	pa[n].y = ppt[0].y;

	DPtoLP(rdc,pa,n + 1);

	if(pxb)
	{
		parse_xcolor(&xc,pxb->color);

		clr_brush.red = XRGB(xc.r);
		clr_brush.green = XRGB(xc.g);
		clr_brush.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_brush);
		XSetForeground(g_display, ctx->context, clr_brush.pixel);
		XFreeColors(g_display, ctx->color, &(clr_brush.pixel), 1, 0);

		XSetFillRule(g_display, ctx->context, EvenOddRule);
		XSetFillStyle(g_display, ctx->context, FillOpaqueStippled);
    
		XFillPolygon(g_display, ctx->device, ctx->context, pa, n + 1, Nonconvex, CoordModeOrigin);
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);

		clr_pen.red = XRGB(xc.r);
		clr_pen.green = XRGB(xc.g);
		clr_pen.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_pen);
		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);

		XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapNotLast, JoinMiter);
		
		XDrawLines(g_display, ctx->device, ctx->context, pa, n + 1, CoordModeOrigin);
	}

	xmem_free(pa);
}

void xlGdiDrawSector(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* prl, const xspan_t* prs, double arcf, double arct)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	xpoint_t pt[4] = { 0 };
	tchar_t ta[5] = { 0 };
	xpoint_t pa[8] = { 0 };
	int lflag;

	pt_calc_sector(ppt, prl->s, prs->s, arcf, arct, pt, 4);
	lflag = (arcf - arct > XPI || arct - arcf > XPI)? 1 : 0;

	ta[0] = _T('M');
	pa[0].x = pt[0].x, pa[0].y = pt[0].y;

	ta[1] = _T('A');
	pa[1].x = 1, pa[1].y = lflag; //clockwise and small arc
	pa[2].x = prl->s, pa[2].y = prl->s;
	pa[3].x = pt[1].x, pa[3].y = pt[1].y;
	
	ta[2] = _T('L');
	pa[4].x = pt[2].x, pa[4].y = pt[2].y;

	ta[3] = _T('A');
	pa[5].x = 0, pa[5].y = lflag; //clockwise and small arc
	pa[6].x = prs->s, pa[6].y = prs->s;
	pa[7].x = pt[3].x, pa[7].y = pt[3].y;

	ta[4] = _T('Z');

	xlGdiDrawPath(rdc, pxp, pxb, ta, pa, 8);
}

void xlGdiDrawText(visual_t rdc,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);
	X11_fontset_t* fst = TypePtrFromHead(X11_fontset_t, ctx->fontset);
	XftFont* xft_font;
	XftDraw* xft_draw;
	XftColor xft_color;
	XRenderColor render_color = { 0, 0, 0, 65535 };
	xcolor_t xc;

	XGlyphInfo exten = {0};

	XPoint pt[2];
	XRectangle rt;

	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;
	DPtoLP(rdc,pt,2);

	if(len < 0) len = xslen(txt);
	if(!len) return;

	xft_font = (XftFont*)fst->font_object;

	XftTextExtentsUtf8(g_display, xft_font, (const FcChar8*)txt, len, &exten);

	rt.x = prt->x;
	rt.y = prt->y;
	rt.width = prt->w;
	rt.height = prt->h;

	if(pxa)
		_adjust_rect(&rt, exten.width, exten.height, pxa->text_align,pxa->line_align);
	else
		_adjust_rect(&rt, exten.width, exten.height, GDI_ATTR_TEXT_ALIGN_NEAR, GDI_ATTR_TEXT_ALIGN_CENTER);
	
	pt[0].x = rt.x;
	pt[0].y = rt.y + rt.height;

	xft_draw = XftDrawCreate(g_display, ctx->device, ctx->visual, ctx->color);

	if(pxa)
	{
		parse_xcolor(&xc, pxa->text_color);
		render_color.red = XRGB(xc.r);
		render_color.green = XRGB(xc.g);
		render_color.blue = XRGB(xc.b);
	}
	XftColorAllocValue(g_display, ctx->visual, ctx->color, &render_color, &xft_color);

    XftDrawStringUtf8(xft_draw, &xft_color, xft_font, pt[0].x, pt[0].y, (XftChar8*)txt, len);

    XftDrawDestroy(xft_draw);
}

void xlGdiTextOut(visual_t rdc, const xface_t* pxa, const xpoint_t* ppt, const tchar_t* txt, int len)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);
	X11_fontset_t* fst = TypePtrFromHead(X11_fontset_t, ctx->fontset);
	XftFont* xft_font;
	XftDraw* xft_draw;
	XftColor xft_color;
	XRenderColor render_color = { 0, 0, 0, 65535 };
	xcolor_t xc;
	xsize_t xs = {0};

	XGlyphInfo exten = {0};

	XPoint pt;
	pt.x = ppt->x;
	pt.y = ppt->y;

	if(len < 0) len = xslen(txt);
	if(!len) return;

	pt.y += (int)fst->font_height;
	DPtoLP(rdc, &pt, 1);

	xft_font = (XftFont*)fst->font_object;

	xft_draw = XftDrawCreate(g_display, ctx->device, ctx->visual, ctx->color);

	if(pxa)
	{
		parse_xcolor(&xc, pxa->text_color);
		render_color.red = XRGB(xc.r);
		render_color.green = XRGB(xc.g);
		render_color.blue = XRGB(xc.b);
	}

	XftColorAllocValue(g_display, ctx->visual, ctx->color, &render_color, &xft_color);

    XftDrawStringUtf8(xft_draw, &xft_color, xft_font, pt.x, pt.y, (XftChar8*)txt, len);

    XftDrawDestroy(xft_draw);
}

void xlGdiTextRect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	int c, n = 0, total = 0;
	tchar_t pch[CHS_LEN + 1] = {0};
	xsize_t se;
	int w, h, maxw = 0;

	fontset_t fnt;

	if(len < 0) len = xslen(txt);
	if(!len) return;

	if(pxf)
	{
		fnt = xlGdiCreateFontset(pxf);
	}
	else
	{
		fnt = ctx->fontset;
	}

	if(!fnt) return;

	w = 0;
	h = 0;
	n = 0;
	while (n++ < len)
	{
		c = peek_word((txt + total), pch);
		total += c;

		xlGdiWordSize(fnt, pch, c, &se);

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
		xlGdiDestroyFontset(fnt);
	}
}

void xlGdiTextSize(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);
	X11_fontset_t* fst = TypePtrFromHead(X11_fontset_t, ctx->fontset);
	XftFont* xft_font;
	XGlyphInfo exten = {0};
	tchar_t font_token[1024] = {0};

	if(len < 0) len = xslen(txt);
	if(!len) return;

	if(pxf)
	{
		format_font_pattern(pxf, font_token);
		xft_font = XftFontOpenName(g_display, DefaultScreen(g_display), font_token);
		if (!xft_font)
		{
			xft_font = XftFontOpenName(g_display, DefaultScreen(g_display), default_fixed_pattern);
		}
	}
	else
	{
		xft_font = (XftFont *)fst->font_object;
	}

	if(!xft_font) return;

	XftTextExtentsUtf8(g_display, xft_font, (const FcChar8*)txt, len, &exten);

	if(pxf)
	{
		XftFontClose(g_display, xft_font);
	}

	pxs->w = exten.width;
	pxs->h = exten.height;
}

void xlGdiGradientRect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	int scr;
	Visual *vis;
	XRenderPictFormat *picfmt;
	Picture src_pic, dst_pic;
	XRenderColor clrs[2];
	XFixed stops[2];
	XLinearGradient linear_grad;
	XRadialGradient radia_grad;

	scr = DefaultScreen(g_display);
    vis = DefaultVisual(g_display, scr);
	picfmt = XRenderFindVisualFormat(g_display, vis);

	stops[0] = XDoubleToFixed(0.0);
	stops[1] = XDoubleToFixed(1.0);

	if (strcmp(gradient, GDI_ATTR_GRADIENT_RADIAL) == 0)
	{
		clrs[0].red = XRGB(clr_core->r);
		clrs[0].green = XRGB(clr_core->g);
		clrs[0].blue = XRGB(clr_core->b);
		clrs[0].alpha = 0xFFFF;

		clrs[1].red = XRGB(clr_brim->r);
		clrs[1].green = XRGB(clr_brim->g);
		clrs[1].blue = XRGB(clr_brim->b);
		clrs[1].alpha = 0xFFFF;

		radia_grad.inner.x = XDoubleToFixed((float)prt->w / 2.0f);
		radia_grad.inner.y = XDoubleToFixed((float)prt->h / 2.0f);
		radia_grad.inner.radius = 0.0;//XDoubleToFixed((float)(prt->w + prt->h) / 8.0f);
	
		radia_grad.outer.x = XDoubleToFixed((float)prt->w / 2.0f);
		radia_grad.outer.y = XDoubleToFixed((float)prt->h / 2.0f);
		radia_grad.outer.radius = XDoubleToFixed((float)(prt->w + prt->h) / 4.0f);

		src_pic = XRenderCreateRadialGradient(g_display, &radia_grad, stops, clrs, 2);
		dst_pic = XRenderCreatePicture(g_display, ctx->device, picfmt, 0, NULL);
		XRenderComposite(g_display, PictOpOver, src_pic, None, dst_pic, 0, 0, 0, 0, prt->x, prt->y, prt->w, prt->h);

		XRenderFreePicture(g_display, src_pic);
		XRenderFreePicture(g_display, dst_pic);
	}
	else if (strcmp(gradient, GDI_ATTR_GRADIENT_HORZ) == 0)
	{
		clrs[0].red = XRGB(clr_brim->r);
		clrs[0].green = XRGB(clr_brim->g);
		clrs[0].blue = XRGB(clr_brim->b);
		clrs[0].alpha = 0xFFFF;
	
		clrs[1].red = XRGB(clr_core->r);
		clrs[1].green = XRGB(clr_core->g);
		clrs[1].blue = XRGB(clr_core->b);
		clrs[1].alpha = 0xFFFF;

		linear_grad.p1.x = XDoubleToFixed(0.0);
		linear_grad.p1.y = XDoubleToFixed(0.0);
		linear_grad.p2.x = XDoubleToFixed((float)prt->w / 2.0f);
		linear_grad.p2.y = XDoubleToFixed(0.0);

		src_pic = XRenderCreateLinearGradient(g_display, &linear_grad, stops, clrs, 2);
		dst_pic = XRenderCreatePicture(g_display, ctx->device, picfmt, 0, NULL);
		XRenderComposite(g_display, PictOpOver, src_pic, None, dst_pic, 0, 0, 0, 0, prt->x, prt->y, prt->w / 2 + 1, prt->h);

		XRenderFreePicture(g_display, src_pic);
		XRenderFreePicture(g_display, dst_pic);

		clrs[0].red = XRGB(clr_core->r);
		clrs[0].green = XRGB(clr_core->g);
		clrs[0].blue = XRGB(clr_core->b);
		clrs[0].alpha = 0xFFFF;

		clrs[1].red = XRGB(clr_brim->r);
		clrs[1].green = XRGB(clr_brim->g);
		clrs[1].blue = XRGB(clr_brim->b);
		clrs[1].alpha = 0xFFFF;

		linear_grad.p1.x = XDoubleToFixed(0.0);
		linear_grad.p1.y = XDoubleToFixed(0.0);
		linear_grad.p2.x = XDoubleToFixed((float)prt->w / 2.0f);
		linear_grad.p2.y = XDoubleToFixed(0.0);

		src_pic = XRenderCreateLinearGradient(g_display, &linear_grad, stops, clrs, 2);
		dst_pic = XRenderCreatePicture(g_display, ctx->device, picfmt, 0, NULL);
		XRenderComposite(g_display, PictOpOver, src_pic, None, dst_pic, 0, 0, 0, 0, prt->x + prt->w / 2, prt->y, prt->w / 2, prt->h);

		XRenderFreePicture(g_display, src_pic);
		XRenderFreePicture(g_display, dst_pic);
	}else if (strcmp(gradient, GDI_ATTR_GRADIENT_VERT) == 0)
	{
		clrs[0].red = XRGB(clr_brim->r);
		clrs[0].green = XRGB(clr_brim->g);
		clrs[0].blue = XRGB(clr_brim->b);
		clrs[0].alpha = 0xFFFF;
	
		clrs[1].red = XRGB(clr_core->r);
		clrs[1].green = XRGB(clr_core->g);
		clrs[1].blue = XRGB(clr_core->b);
		clrs[1].alpha = 0xFFFF;

		linear_grad.p1.x = XDoubleToFixed(0.0);
		linear_grad.p1.y = XDoubleToFixed(0.0);
		linear_grad.p2.x = XDoubleToFixed(0.0);
		linear_grad.p2.y = XDoubleToFixed((float)prt->h / 2.0f);

		src_pic = XRenderCreateLinearGradient(g_display, &linear_grad, stops, clrs, 2);
		dst_pic = XRenderCreatePicture(g_display, ctx->device, picfmt, 0, NULL);
		XRenderComposite(g_display, PictOpOver, src_pic, None, dst_pic, 0, 0, 0, 0, prt->x, prt->y, prt->w, prt->h / 2 + 1);

		XRenderFreePicture(g_display, src_pic);
		XRenderFreePicture(g_display, dst_pic);

		clrs[0].red = XRGB(clr_core->r);
		clrs[0].green = XRGB(clr_core->g);
		clrs[0].blue = XRGB(clr_core->b);
		clrs[0].alpha = 0xFFFF;

		clrs[1].red = XRGB(clr_brim->r);
		clrs[1].green = XRGB(clr_brim->g);
		clrs[1].blue = XRGB(clr_brim->b);
		clrs[1].alpha = 0xFFFF;

		linear_grad.p1.x = XDoubleToFixed(0.0);
		linear_grad.p1.y = XDoubleToFixed(0.0);
		linear_grad.p2.x = XDoubleToFixed(0.0);
		linear_grad.p2.y = XDoubleToFixed((float)prt->h / 2.0f);

		src_pic = XRenderCreateLinearGradient(g_display, &linear_grad, stops, clrs, 2);
		dst_pic = XRenderCreatePicture(g_display, ctx->device, picfmt, 0, NULL);
		XRenderComposite(g_display, PictOpOver, src_pic, None, dst_pic, 0, 0, 0, 0, prt->x, prt->y + prt->h / 2, prt->w, prt->h / 2);

		XRenderFreePicture(g_display, src_pic);
		XRenderFreePicture(g_display, dst_pic);
	}
}

void xlGdiAlphablendRect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	int scr;
	Visual *vis;
	XRenderPictFormat *picfmt;
	Picture src_pic, dst_pic;

	XRenderColor clr = {0};

    clr.red = XRGB(pxc->r);
    clr.green = XRGB(pxc->g);
    clr.blue = XRGB(pxc->b);
    clr.alpha = (unsigned short)(opacity * 65535 / 255);

	scr = DefaultScreen(g_display);
    vis = DefaultVisual(g_display, scr);

    src_pic = XRenderCreateSolidFill(g_display, &clr);

	picfmt = XRenderFindVisualFormat(g_display, vis);
	dst_pic = XRenderCreatePicture(g_display, ctx->device, picfmt, 0, NULL);

	XRenderComposite(g_display, PictOpOver, src_pic, None, dst_pic, 0, 0, 0, 0, prt->x, prt->y, prt->w, prt->h);

	XRenderFreePicture(g_display, src_pic);
    XRenderFreePicture(g_display, dst_pic);
}

void xlGdiInvertRect(visual_t rdc, const xrect_t* prt)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);
	XGCValues old_func;

    XGetGCValues(g_display, ctx->context, GCFunction, &old_func);

    XSetFunction(g_display, ctx->context, GXinvert);
    XFillRectangle(g_display, ctx->device, ctx->context, prt->x, prt->y, prt->w, prt->h);

    XSetFunction(g_display, ctx->context, old_func.function);
}

void xlGdiExcludeRect(visual_t rdc, const xrect_t* pxr)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);
	Region full_region, excl_region;
	XRectangle full_rect = {
		.x = 0,
		.y = 0,
		.width = ctx->width,
		.height = ctx->height
	};
	XRectangle excl_rect = {
		.x = pxr->x,
		.y = pxr->y,
		.width = pxr->w,
		.height = pxr->h
	};

    full_region = XCreateRegion();
    XUnionRectWithRegion(&full_rect, full_region, full_region);

    excl_region = XCreateRegion();
    XUnionRectWithRegion(&excl_rect, excl_region, excl_region);

    XSubtractRegion(full_region, excl_region, full_region);

    XSetRegion(g_display, ctx->context, full_region);

    XDestroyRegion(full_region);
    XDestroyRegion(excl_region);
}

void xlGdiInclipRect(visual_t rdc, const xrect_t* pxr)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

    XRectangle clip_rect = {
		.x = pxr->x,
		.y = pxr->y,
		.width = pxr->w,
		.height = pxr->h
	};

    XSetClipRectangles(g_display, ctx->context, 0, 0, &clip_rect, 1, Unsorted);
}

void xlGdiDrawImage(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt)
{
    X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);
	X11_bitmap_t* bmp = (X11_bitmap_t*)rbm;

	XImage* pmi = (XImage*)bmp->image;

	XRectangle xr;
	XPoint pt[2];

	xr.x = prt->x;
	xr.y = prt->y;
	xr.width = prt->w;
	xr.height = prt->h;

	_adjust_rect(&xr, pmi->width, pmi->height, GDI_ATTR_TEXT_ALIGN_CENTER, GDI_ATTR_TEXT_ALIGN_CENTER);
    
	pt[0].x = xr.x;
	pt[0].y = xr.y;
	pt[1].x = xr.x + xr.width;
	pt[1].y = xr.y + xr.height;

	DPtoLP(rdc,pt,2);

	XPutImage(g_display, ctx->device, ctx->context, pmi, 0, 0, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);
}

void xlGdiDrawBitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);
	X11_bitmap_t* bmp = (X11_bitmap_t*)rbm;

	XImage* pmi = (XImage*)bmp->image;

	XPoint pt[1];
    
	pt[0].x = ppt->x;
	pt[0].y = ppt->y;

	XPutImage(g_display, ctx->device, ctx->context, pmi, 0, 0, pt[0].x, pt[0].y, pmi->width, pmi->height);
}
/*
void xlGdiFillRegion(visual_t rdc, const xbrush_t* pxb, res_rgn_t rgn)
{
    X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);
	xcolor_t xc;
	XColor clr;
	XRectangle rect;

	XSetRegion(g_display, ctx->context, (Region)rgn);

	parse_xcolor(&xc, pxb->color);

	clr.red = XRGB(xc.r);
	clr.green = XRGB(xc.g);
	clr.blue = XRGB(xc.b);
	
	XAllocColor(g_display, ctx->color, &clr);
	XSetForeground(g_display, ctx->context, clr.pixel);
	XFreeColors(g_display, ctx->color, &(clr.pixel), 1, 0);

	XClipBox(rgn, &rect);
    XFillRectangle(g_display, ctx->device, ctx->context, rect.x, rect.y, rect.width, rect.height);

	XSetClipMask(g_display, ctx->context, None);
}
*/
void xlGdiFontSize(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);
	X11_fontset_t* fst = TypePtrFromHead(X11_fontset_t, ctx->fontset);
	XftFont* xft_font;
	double size = 0.0;
	XGlyphInfo exten = {0};

	tchar_t font_token[1024] = {0};
	
	if(pxf)
	{
		format_font_pattern(pxf, font_token);
		xft_font = XftFontOpenName(g_display, DefaultScreen(g_display), font_token);
		if (!xft_font)
		{
			xft_font = XftFontOpenName(g_display, DefaultScreen(g_display), default_fixed_pattern);
		}
	}
	else
	{
		xft_font = (XftFont *)fst->font_object;
	}

	if(!xft_font) return;
	
	if (xft_font->pattern)
	{
		FcPatternGetDouble(xft_font->pattern, FC_SIZE, 0, &size);
	}
	else
	{
		size = (xft_font->ascent + xft_font->descent) / 2;
	}

	if(pxf)
	{
		XftFontClose(g_display, xft_font);
	}

	pxs->w = LOGPTPERMM;
	pxs->h = (int)size;
}

fontset_t xlGdiGetFontset(visual_t rdc)
{
	X11_context_t* ctx = TypePtrFromHead(X11_context_t, rdc);

	return ctx->fontset;
}

fontset_t xlGdiCreateFontset(const xfont_t* pxf)
{
	X11_fontset_t* fst;
	XftFont* xft_font;
	float px = 0.0f;
	tchar_t font_token[1024] = {0};
	
	format_font_pattern(pxf, font_token);

	xft_font = XftFontOpenName(g_display, DefaultScreen(g_display), font_token);
    if (!xft_font)
	{
        xft_font = XftFontOpenName(g_display, DefaultScreen(g_display), default_fixed_pattern);
    }

	if(!xft_font) return (fontset_t)0;

	font_metric_by_pt(xstof(pxf->size), NULL, &px);

	fst = (X11_fontset_t*)xmem_alloc_handle(sizeof(X11_fontset_t));
	fst->head.tag = _HANDLE_FONTSET;
	fst->font_object = (void*)xft_font;
	fst->font_height = px;

	return (fontset_t)&(fst->head);
}

void xlGdiDestroyFontset(fontset_t ft)
{
	X11_fontset_t* fst = TypePtrFromHead(X11_fontset_t, ft);

	if(fst && fst->font_object) XftFontClose(g_display, (XftFont*)(fst->font_object));

	if(fst) xmem_free_handle((xhand_t)fst);
}

void xlGdiWordSize(fontset_t ft, const tchar_t* pch, int chs, xsize_t* pxs)
{
	X11_fontset_t* fst = TypePtrFromHead(X11_fontset_t, ft);
	XftFont* xft_font = (XftFont*)fst->font_object;
	XGlyphInfo exten = {0};

	XftTextExtentsUtf8(g_display, xft_font, (const FcChar8*)pch, chs, &exten);
	
	pxs->w = exten.width;
	pxs->h = exten.height;
}




