/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdi document

	@module	if_gdi.c | linux implement file

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

#ifdef XDU_SUPPORT_CONTEXT_GDI

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
		prt->width = (prt->width < src_width) ? prt->width : src_width;
		prt->height = (prt->height < src_height) ? prt->height : src_height;
	}
	else if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		prt->x = (prt->width < src_width) ? prt->x : (prt->x + prt->width - src_width);
		prt->height = (prt->height < src_height) ? prt->height : src_height;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		prt->width = (prt->width < src_width) ? prt->width : src_width;
		prt->y = (prt->height < src_height) ? prt->y : (prt->y + prt->height - src_height);
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		prt->x = (prt->width < src_width) ? prt->x : (prt->x + prt->width - src_width);
		prt->y = (prt->height < src_height) ? prt->y : (prt->y + prt->height - src_height);
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		if (prt->width > src_width)
		{
			prt->x = prt->x + (prt->width - src_width) / 2;
			prt->width = src_width;
		}
		if (prt->height > src_height)
		{
			prt->y = prt->y + (prt->height - src_height) / 2;
			prt->height = src_height;
		}
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		prt->width = (prt->width < src_width) ? prt->width : src_width;
		prt->y = (prt->height < src_height) ? prt->y : (prt->y + (prt->height - src_height) / 2);
		prt->height = (prt->height < src_height) ? prt->height : src_height;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		prt->x = (prt->width < src_width) ? prt->x : (prt->x + prt->width - src_width);
		prt->y = (prt->height < src_height) ? prt->y : (prt->y + (prt->height - src_height) / 2);
		prt->height = (prt->height < src_height) ? prt->height : src_height;
	}
}

static void _calc_point(const xpoint_t* pt, int r, double a, xpoint_t* pp)
{
	pp->x = pt->x + (int)((float)r * cos(a));
	pp->y = pt->y + (int)((float)r * sin(a));
}


static XFontStruct* _create_font(const xfont_t* pxf)
{
	XFontStruct* fs;
	char font_token[1024] = {0};
	
	format_font_pattern(pxf, font_token);

	fs = XLoadQueryFont(g_display, font_token);

	return fs;
}

static void calc_penmode(const xpen_t* pxp, int* fs, int* ds)
{
	*fs = is_null(pxp->size) ? 1 : xstol(pxp->size);

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

void _gdi_init(int osv)
{

}

void _gdi_uninit(void)
{
	
}

void _gdi_get_point(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt)
{

}

void _gdi_set_point(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt)
{

}

void _gdi_draw_points(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

	unsigned long l_for;
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

		l_for = clr_pen.pixel;
	}else
	{
		l_for = BlackPixel(g_display, DefaultScreen(g_display));
	}

    XSetForeground(g_display, ctx->context, l_for);

	XDrawPoints(g_display, ctx->device, ctx->context, ppp, n, CoordModeOrigin);

	xmem_free(ppp);

	if(clr_pen.pixel)
	{
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);
	}
}

void _gdi_draw_line(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2)
{
    X11_context_t* ctx = (X11_context_t*)rdc;

	xcolor_t xc = {0};
	int l_w, l_s;
	unsigned long l_for;
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

		l_for = clr_pen.pixel;

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);
	}else
	{
		l_for = BlackPixel(g_display, DefaultScreen(g_display));
		l_w = 1;
		l_s = LineSolid;
	}

	XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapRound, JoinRound);

    XSetForeground(g_display, ctx->context, l_for);

    XDrawLine(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x, pt[1].y);

	if(clr_pen.pixel)
	{
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);
	}
}

void _gdi_draw_polyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

	xcolor_t xc = {0};
	int l_w, l_s;
	unsigned long l_p;
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

		l_p = clr_pen.pixel;

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);
	}else
	{
		l_p = BlackPixel(g_display, DefaultScreen(g_display));
		l_w = 1;
		l_s = LineSolid;
	}

	XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapRound, JoinRound);

    XSetForeground(g_display, ctx->context, l_p);

    XDrawLines(g_display, ctx->device, ctx->context, pa, n, CoordModeOrigin);

	xmem_free(pa);

	if(clr_pen.pixel)
	{
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);
	}
}

void _gdi_draw_arc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t sflag, bool_t lflag)
{
    X11_context_t* ctx = (X11_context_t*)rdc;

	xcolor_t xc = {0};
	int l_w, l_s;
	XColor ext, clr_brush = {0}, clr_pen = {0};
	unsigned long l_p;

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

	pt_calc_radian(sflag, lflag, rx, ry, &xp[0], &xp[1], &xp[2], &arcf, &arct);

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

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);
		l_p = clr_pen.pixel;
	}else
	{
		l_s = LineSolid;
		l_w = 1;
		l_p = BlackPixel(g_display, DefaultScreen(g_display));
	}
	
	XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapNotLast, JoinMiter);

	XSetForeground(g_display, ctx->context, l_p);
	
	XDrawArc(g_display, ctx->device, ctx->context, x, y, w, h, (int)fdeg, (int)sdeg);

	if(clr_pen.pixel)
	{
		XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);
	}
}

void _gdi_draw_bezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
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

	_gdi_draw_points(rdc, &xc, ppt, n);

	xmem_free(ppt);
}

void _gdi_draw_curve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn)
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
	}
	
	pt_world_to_screen(ppt[0], ppt_buf, n);

	parse_xcolor(&xc, pxp->color);

	_gdi_draw_points(rdc, &xc, ppt_buf, n);

	xmem_free(ppt_buf); 
}

void _gdi_draw_path(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa)
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

			_gdi_draw_line(rdc, pxp, &pt[0], &pt[1]);
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

			_gdi_draw_line(rdc, pxp, &pt[0], &pt[1]);
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

			_gdi_draw_curve(rdc, pxp, pt, 3);
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

			_gdi_draw_curve(rdc, pxp, pt, 3);
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

			_gdi_draw_curve(rdc, pxp, pt, 3);
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

			_gdi_draw_curve(rdc, pxp, pt, 3);
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

			_gdi_draw_bezier(rdc, pxp, &pt[0], &pt[1], &pt[2], &pt[3]);
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

			_gdi_draw_bezier(rdc, pxp, &pt[0], &pt[1], &pt[2], &pt[3]);
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

			_gdi_draw_bezier(rdc, pxp, &pt[0], &pt[1], &pt[2], &pt[3]);
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

			_gdi_draw_bezier(rdc, pxp, &pt[0], &pt[1], &pt[2], &pt[3]);
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

			_gdi_draw_arc(rdc, pxp, &pt[0], &pt[1], &xs, sflag, lflag);
			n = 3;
		}
		else if (*aa == _T('Z') || *aa == _T('z'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_m.x;
			pt[1].y = pt_m.y;

			_gdi_draw_line(rdc, pxp, &pt[0], &pt[1]);

			break;
		}

		aa++;
		pa += n;
	}
}

void _gdi_draw_rect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

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

		XSetFillRule(g_display, ctx->context, EvenOddRule);
		XSetFillStyle(g_display, ctx->context, FillOpaqueStippled);
    
		XFillRectangle(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);

		if(clr_brush.pixel)
		{
			XFreeColors(g_display, ctx->color, &(clr_brush.pixel), 1, 0);
		}
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);

		clr_pen.red = XRGB(xc.r);
		clr_pen.green = XRGB(xc.g);
		clr_pen.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_pen);

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);

		XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapNotLast, JoinMiter);

		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		
		XDrawRectangle(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);

		if(clr_pen.pixel)
		{
			XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);
		}
	}
}

void _gdi_draw_triangle(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const tchar_t* orient)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

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

	_gdi_draw_line(rdc, pxp, &pt[0], &pt[1]);
	_gdi_draw_line(rdc, pxp, &pt[1], &pt[2]);
	_gdi_draw_line(rdc, pxp, &pt[2], &pt[0]);
}

void _gdi_draw_round(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

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

	_gdi_draw_path(rdc, pxp, pxb, ta, pa);
}

void _gdi_draw_ellipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

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

		XSetFillRule(g_display, ctx->context, EvenOddRule);
		XSetFillStyle(g_display, ctx->context, FillOpaqueStippled);
    
		XFillArc(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y, 0, 360 * 64);

		if(clr_brush.pixel)
		{
			XFreeColors(g_display, ctx->color, &(clr_brush.pixel), 1, 0);
		}
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);

		clr_pen.red = XRGB(xc.r);
		clr_pen.green = XRGB(xc.g);
		clr_pen.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_pen);

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);

		XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapNotLast, JoinMiter);

		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		
		XDrawArc(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y, 0, 360 * 64);

		if(clr_pen.pixel)
		{
			XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);
		}
	}
}

void _gdi_draw_pie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt,  double arcf, double arct)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

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

		XSetFillRule(g_display, ctx->context, EvenOddRule);
		XSetFillStyle(g_display, ctx->context, FillOpaqueStippled);
    
		XFillArc(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y, (int)fdeg, (int)sdeg);

		if(clr_brush.pixel)
		{
			XFreeColors(g_display, ctx->color, &(clr_brush.pixel), 1, 0);
		}
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);

		clr_pen.red = XRGB(xc.r);
		clr_pen.green = XRGB(xc.g);
		clr_pen.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_pen);

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);

		XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapNotLast, JoinMiter);

		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		
		XDrawArc(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y, (int)fdeg, (int)sdeg);

		if(clr_pen.pixel)
		{
			XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);
		}
	}
}

void _gdi_draw_polygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n)
{
    X11_context_t* ctx = (X11_context_t*)rdc;

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

		XSetFillRule(g_display, ctx->context, EvenOddRule);
		XSetFillStyle(g_display, ctx->context, FillOpaqueStippled);
    
		XFillPolygon(g_display, ctx->device, ctx->context, pa, n + 1, Nonconvex, CoordModeOrigin);

		if(clr_brush.pixel)
		{
			XFreeColors(g_display, ctx->color, &(clr_brush.pixel), 1, 0);
		}
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);

		clr_pen.red = XRGB(xc.r);
		clr_pen.green = XRGB(xc.g);
		clr_pen.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_pen);

		if (xscmp(pxp->style, GDI_ATTR_STROKE_STYLE_DASH) == 0)
			l_s = LineOnOffDash;
		else if (xscmp(pxp->style,GDI_ATTR_STROKE_STYLE_DASHDASH) == 0)
			l_s = LineDoubleDash;
		else
			l_s = LineSolid;
		
		l_w = xstol(pxp->size);

		XSetLineAttributes(g_display, ctx->context, l_w, l_s, CapNotLast, JoinMiter);

		XSetForeground(g_display, ctx->context, clr_pen.pixel);
		
		XDrawLines(g_display, ctx->device, ctx->context, pa, n + 1, CoordModeOrigin);

		if(clr_pen.pixel)
		{
			XFreeColors(g_display, ctx->color, &(clr_pen.pixel), 1, 0);
		}
	}

	xmem_free(pa);
}

void _gdi_draw_sector(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* prl, const xspan_t* prs, double arcf, double arct)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

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

	_gdi_draw_path(rdc, pxp, pxb, ta, pa);
}

void _gdi_draw_text(visual_t rdc,const xfont_t* pxf,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len)
{
	X11_context_t* ctx = (X11_context_t*)rdc;
	XFontStruct* pfs = NULL;
	GContext cid;

	xcolor_t xc = {0};
	int tw, th;
	XColor ext, clr_font = {0};

	XCharStruct chs = {0};
	int direct = 0, ascent = 0, descent = 0;
	XPoint pt[2];
	XRectangle rt;

	DPtoLP(rdc,pt,2);

	cid = XGContextFromGC(ctx->context);

	if(pxf)
		pfs = _create_font(pxf);
	else
		pfs = XQueryFont(g_display, cid);

	if(!pfs)
		return;

	XSetFont(g_display, ctx->context, pfs->fid);

	if(pxf)
	{
		parse_xcolor(&xc, pxf->color);

		clr_font.red = XRGB(xc.r);
		clr_font.green = XRGB(xc.g);
		clr_font.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_font);
		XSetForeground(g_display, ctx->context, clr_font.pixel);
	}

	XSetFillRule(g_display, ctx->context, EvenOddRule);
	XSetFillStyle(g_display, ctx->context, FillOpaqueStippled);
    
	if(len < 0) len = xslen(txt);

	XTextExtents(pfs, txt, len, &direct, &ascent, &descent, &chs);
	tw = chs.width;
	th = chs.ascent + chs.descent;

	rt.x = prt->x;
	rt.y = prt->y;
	rt.width = prt->w;
	rt.height = prt->h;

	if(pxa)
		_adjust_rect(&rt, tw, th, pxa->text_align,pxa->line_align);
	else
		_adjust_rect(&rt, tw, th, GDI_ATTR_TEXT_ALIGN_NEAR, GDI_ATTR_TEXT_ALIGN_CENTER);
	
	pt[0].x = rt.x;
	pt[0].y = rt.y + rt.height;

	XDrawString(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, txt, len);

	XFreeFont(g_display, pfs);

	if(clr_font.pixel)
	{
		XFreeColors(g_display, ctx->color, &(clr_font.pixel), 1, 0);
	}
}

void _gdi_text_out(visual_t rdc, const xfont_t* pxf, const xpoint_t* ppt, const tchar_t* txt, int len)
{
	X11_context_t* ctx = (X11_context_t*)rdc;
	XFontStruct* pfs = NULL;
	GContext cid;

	xcolor_t xc = {0};
	int l_w, l_s;
	XColor ext, clr_font = {0};
	XCharStruct chs = {0};
	int direct = 0, ascent = 0, descent = 0;
	XPoint pt[2];
    
	pt[0].x = ppt->x;
	pt[0].y = ppt->y;
	pt[1].x = ppt->x;
	pt[1].y = ppt->y;

	DPtoLP(rdc,pt,2);

	cid = XGContextFromGC(ctx->context);

	if(pxf)
		pfs = _create_font(pxf);
	else
		pfs = XQueryFont(g_display, cid);

	if(!pfs)
		return;

	XSetFont(g_display, ctx->context, pfs->fid);

	if(pxf)
	{
		parse_xcolor(&xc, pxf->color);

		clr_font.red = XRGB(xc.r);
		clr_font.green = XRGB(xc.g);
		clr_font.blue = XRGB(xc.b);

		XAllocColor(g_display, ctx->color, &clr_font);
		XSetForeground(g_display, ctx->context, clr_font.pixel);
	}

	XSetFillRule(g_display, ctx->context, EvenOddRule);
	XSetFillStyle(g_display, ctx->context, FillOpaqueStippled);
    
	if(len < 0) len = xslen(txt);

	XTextExtents(pfs, txt, len, &direct, &ascent, &descent, &chs);
	pt[0].y += ascent;

	XDrawString(g_display, ctx->device, ctx->context, pt[0].x, pt[0].y, txt, len);

	XFreeFont(g_display, pfs);

	if(clr_font.pixel)
	{
		XFreeColors(g_display, ctx->color, &(clr_font.pixel), 1, 0);
	}
}

void _gdi_text_rect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt)
{
	X11_context_t* ctx = (X11_context_t*)rdc;
	XFontStruct* pfs = NULL;
	GContext cid;

	XCharStruct chs = {0};
	int direct = 0, ascent = 0, descent = 0;

	cid = XGContextFromGC(ctx->context);

	if(pxf)
		pfs = _create_font(pxf);
	else
		pfs = XQueryFont(g_display, cid);

	if(!pfs) return;
	
	if(len < 0) len = xslen(txt);

	XTextExtents(pfs, txt, len, &direct, &ascent, &descent, &chs);
	prt->w = chs.width;
	prt->h = ascent + descent;

	XFreeFont(g_display, pfs);
}

void _gdi_text_size(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
	X11_context_t* ctx = (X11_context_t*)rdc;
	GContext cid;

	XFontStruct* pfs = NULL;
	XCharStruct chs = {0};
	int direct = 0, ascent = 0, descent = 0;

	cid = XGContextFromGC(ctx->context);

	if(pxf)
		pfs = _create_font(pxf);
	else
		pfs = XQueryFont(g_display, cid);

	if(!pfs) return;
	
	if(len < 0) len = xslen(txt);

	XTextExtents(pfs, txt, len, &direct, &ascent, &descent, &chs);

	pxs->w = chs.width;
	pxs->h = ascent + descent;

	XFreeFont(g_display, pfs);
}

void _gdi_text_metric(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
	X11_context_t* ctx = (X11_context_t*)rdc;
	GContext cid;

	XFontStruct* pfs = NULL;
	XCharStruct chs = {0};
	int direct = 0, ascent = 0, descent = 0;

	cid = XGContextFromGC(ctx->context);

	if(pxf)
		pfs = _create_font(pxf);
	else
		pfs = XQueryFont(g_display, cid);

	if(!pfs) return;
	
	XTextExtents(pfs, "aj", 2, &direct, &ascent, &descent, &chs);

	pxs->w = chs.width / 2;
	pxs->h = (ascent + descent) / 2;

	XFreeFont(g_display, pfs);
}

#ifdef XDU_SUPPORT_CONTEXT_BITMAP
void _gdi_draw_image(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt)
{
    X11_context_t* ctx = (X11_context_t*)rdc;
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

void _gdi_draw_bitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt)
{
	X11_context_t* ctx = (X11_context_t*)rdc;
	X11_bitmap_t* bmp = (X11_bitmap_t*)rbm;

	XImage* pmi = (XImage*)bmp->image;

	XPoint pt[1];
    
	pt[0].x = ppt->x;
	pt[0].y = ppt->y;

	XPutImage(g_display, ctx->device, ctx->context, pmi, 0, 0, pt[0].x, pt[0].y, pmi->width, pmi->height);
}
#endif

void _gdi_gradient_rect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt)
{

}

void _gdi_alphablend_rect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity)
{
	
}

void _gdi_exclude_rect(visual_t rdc, const xrect_t* pxr)
{

}

#ifdef XDU_SUPPORT_CONTEXT_REGION
void _gdi_fill_region(visual_t rdc, const xbrush_t* pxb, res_rgn_t rgn)
{
    
}
#endif

#endif //XDU_SUPPORT_CONTEXT_GRAPHIC

