﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdi document

	@module	if_cairo.c | linux implement file

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

#ifdef XDU_SUPPORT_CONTEXT_CAIRO

static void DPtoLP(visual_t rdc, XPoint* pt,int n)
{
	int i;
	for(i = 0;i<n;i++)
	{
		pt[i].x = pt[i].x;
		pt[i].y = pt[i].y;
	}
}

static void LPtoDP(visual_t rdc, XPoint* pt,int n)
{
	int i;
	for(i = 0;i<n;i++)
	{
		pt[i].x = pt[i].x;
		pt[i].y = pt[i].y;
	}
}

static void AdjustRect(XRectangle* prt, int src_width, int src_height, const tchar_t* horz_align, const tchar_t* vert_align)
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

static int PolarToClockwise(double *pstart, double *pend)
{
	while(*pstart > 2 * XPI)
		*pstart -= 2 * XPI;

	while(*pstart < - 2 * XPI)
		*pstart += - 2 * XPI;

	while(*pend > 2 * XPI)
		*pend -= 2 * XPI;

	while(*pend < - 2 * XPI)
		*pend += - 2 * XPI;

	*pstart = 0 - *pstart;
	*pend = 0 - *pend;

	return (*pstart > *pend)? 0 : 1;
}

#define DASH_MODE_SIZE 3
static const double dash_mode[DASH_MODE_SIZE] = {1.0,2.0,3.0};

static void calc_penmode(const xpen_t* pxp, int* fs, int* ds)
{
	*fs = is_null(pxp->size) ? 1 : xstol(pxp->size);

	if (compare_text(pxp->style, -1, GDI_ATTR_STROKE_STYLE_DASH, -1, 1) == 0)
		*ds = 1;
	else if (compare_text(pxp->style, -1, GDI_ATTR_STROKE_STYLE_DASHDASH, -1, 1) == 0)
		*ds = 2;
	else if (compare_text(pxp->style, -1, GDI_ATTR_STROKE_STYLE_DASHDASHDASH, -1, 1) == 0)
		*ds = 3;
	else
		*ds = 0;
}
/************************************************************************************************/

void _cairo_init(int osv)
{

}

void _cairo_uninit(void)
{
	
}

void _cairo_get_point(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt)
{

}

void _cairo_set_point(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt)
{

}

void _cairo_draw_points(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n)
{
}

void _cairo_draw_line(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2)
{
    X11_context_t* ctx = (X11_context_t*)rdc;
	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	int fs, ds;

	XPoint pt[2];
	pt[0].x = ppt1->x;
	pt[0].y = ppt1->y;
	pt[1].x = ppt2->x;
	pt[1].y = ppt2->y;

	DPtoLP(rdc,pt,2);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);
		calc_penmode(pxp, &fs, &ds);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);
		cairo_set_dash(cai, dash_mode, ds, ds);
		cairo_set_line_width(cai, fs);
	}

	cairo_move_to(cai, pt[0].x, pt[0].y);
    cairo_line_to(cai, pt[1].x, pt[1].y);

    cairo_stroke(cai);

	cairo_surface_destroy(fac);

	cairo_destroy(cai);
}

void _cairo_draw_polyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n)
{
	X11_context_t* ctx = (X11_context_t*)rdc;
	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	int fs, ds;

	XPoint* pa;
	int i;
	
	if(!n) return;

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	pa = (XPoint*)calloc(n, sizeof(XPoint));
	for(i =0;i<n;i++)
	{
		pa[i].x = ppt[i].x;
		pa[i].y = ppt[i].y;
	}
	DPtoLP(rdc,pa,n);

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);
		calc_penmode(pxp, &fs, &ds);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);
		cairo_set_dash(cai, dash_mode, ds, ds);
		cairo_set_line_width(cai, fs);
	}

	cairo_move_to(cai, pa[0].x, pa[0].y);

	for(i =1;i<n;i++)
	{
		cairo_line_to(cai, pa[i].x, pa[i].y);
	}

	free(pa);

	cairo_stroke(cai);

	cairo_surface_destroy(fac);

	cairo_destroy(cai);
}

void _cairo_draw_arc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t sflag, bool_t lflag)
{
   X11_context_t* ctx = (X11_context_t*)rdc;

	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	int fs, ds;

	XPoint pt[4] = {0};

	int fdeg, tdeg;
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

	sflag = pt_calc_radian(sflag, lflag, rx, ry, &xp[0], &xp[1], &xp[2], &arcf, &arct);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	if(sflag)
		cairo_arc(cai, xp[2].x, xp[2].y, rx, arcf, arct);
	else
		cairo_arc_negative(cai, xp[2].x, xp[2].y, rx, arcf, arct);

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);
		calc_penmode(pxp, &fs, &ds);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);
		cairo_set_dash(cai, dash_mode, ds, ds);
		cairo_set_line_width(cai, fs);
	}

	cairo_stroke(cai);

	cairo_destroy(cai);

	cairo_surface_destroy(fac);
}

void _cairo_draw_bezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
	X11_context_t* ctx = (X11_context_t*)rdc;
	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	int fs, ds;

	XPoint pt[4];
	
	pt[0].x = ppt1->x;
	pt[0].y = ppt1->y;
	pt[1].x = ppt2->x;
	pt[1].y = ppt2->y;
	pt[2].x = ppt3->x;
	pt[2].y = ppt3->y;
	pt[3].x = ppt4->x;
	pt[3].y = ppt4->y;

	DPtoLP(rdc,pt,4);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);
		calc_penmode(pxp, &fs, &ds);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);
		cairo_set_dash(cai, dash_mode, DASH_MODE_SIZE, ds);
		cairo_set_line_width(cai, fs);
	}

	cairo_move_to(cai, pt[0].x, pt[0].y);

	cairo_curve_to(cai, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);

	cairo_stroke(cai);

	cairo_surface_destroy(fac);

	cairo_destroy(cai);
}

void _cairo_draw_curve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int n)
{
    	X11_context_t* ctx = (X11_context_t*)rdc;
	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	int fs, ds;

	XPoint pt[4];
	
	if(n == 4)
	{
		pt[0].x = ppt[0].x;
		pt[0].y = ppt[0].y;
		pt[1].x = ppt[1].x;
		pt[1].y = ppt[1].y;
		pt[2].x = ppt[2].x;
		pt[2].y = ppt[2].y;
		pt[3].x = ppt[3].x;
		pt[3].y = ppt[3].y;
	}else if(n == 3)
	{
		pt[0].x = ppt[0].x;
		pt[0].y = ppt[0].y;
		pt[1].x = ppt[1].x;
		pt[1].y = ppt[1].y;
		pt[2].x = ppt[1].x;
		pt[2].y = ppt[1].y;
		pt[3].x = ppt[2].x;
		pt[3].y = ppt[2].y;
	}

	DPtoLP(rdc,pt,4);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);
		calc_penmode(pxp, &fs, &ds);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);
		cairo_set_dash(cai, dash_mode, ds, ds);
		cairo_set_line_width(cai, fs);
	}

	cairo_move_to(cai, pt[0].x, pt[0].y);

	cairo_curve_to(cai, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);

	cairo_stroke(cai);

	cairo_surface_destroy(fac);

	cairo_destroy(cai);
}

void _cairo_draw_path(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

	XPoint pt_m = { 0 };
	XPoint pt_p = { 0 };
	XPoint pt_i = { 0 };
	XPoint pt[4] = { 0 };
	XPoint pk = { 0 };
	XRectangle rt;

	int rx, ry;
	int sflag, lflag;
	xpoint_t xp[3];
	double arcf, arct;
	int n = 0;

	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	int fs, ds;

	if (!aa)
		return NULL;

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	cairo_new_path(cai);

	while (*aa)
	{
		if (*aa == _T('M') || *aa == _T('m'))
		{
			pt_m.x = pa[0].x;
			pt_m.y = pa[0].y;

			pt_p.x = pt_m.x;
			pt_p.y = pt_m.y;

			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;

			DPtoLP(rdc, pt, 1);
			cairo_move_to(cai, pt[0].x, pt[0].y);
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

			DPtoLP(rdc, pt, 2);
			cairo_line_to(cai, pt[1].x, pt[1].y);
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

			DPtoLP(rdc, pt, 2);
			cairo_line_to(cai, pt[1].x, pt[1].y);
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

			DPtoLP(rdc, pt, 3);
			cairo_curve_to(cai, pt[1].x, pt[1].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y);
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

			DPtoLP(rdc, pt, 3);
			cairo_curve_to(cai, pt[1].x, pt[1].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y);
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

			DPtoLP(rdc, pt, 3);
			cairo_curve_to(cai, pt[1].x, pt[1].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y);
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

			DPtoLP(rdc, pt, 3);
			cairo_curve_to(cai, pt[1].x, pt[1].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y);
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

			DPtoLP(rdc, pt, 4);
			cairo_curve_to(cai, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);
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

			DPtoLP(rdc, pt, 4);
			cairo_curve_to(cai, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);
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

			DPtoLP(rdc, pt, 4);
			cairo_curve_to(cai, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);
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

			DPtoLP(rdc, pt, 4);
			cairo_curve_to(cai, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);
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

			DPtoLP(rdc, pt, 2);

			xp[0].x = pt[0].x;
			xp[0].y = pt[0].y;
			xp[1].x = pt[1].x;
			xp[1].y = pt[1].y;

			pt_calc_radian(sflag, lflag, rx, ry, &xp[0], &xp[1], &xp[2], &arcf, &arct);
			arct += arcf;
			arcf = 0 - arcf;
			arct = 0 - arct;

			pk.x = xp[2].x;
			pk.y = xp[2].y;
			
			if(sflag)
				cairo_arc(cai, pk.x, pk.y, rx, arcf, arct);
			else
				cairo_arc_negative(cai, pk.x, pk.y, rx, arcf, arct);
			
			n = 3;
		}
		else if (*aa == _T('Z') || *aa == _T('z'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_m.x;
			pt[1].y = pt_m.y;

			DPtoLP(rdc, pt, 2);
			cairo_line_to(cai, pt[1].x, pt[1].y);

			break;
		}

		aa++;
		pa += n;
	}

	cairo_close_path(cai);

	if(pxb)
	{
		parse_xcolor(&xc,pxb->color);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);

		cairo_fill_preserve(cai);
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);
		calc_penmode(pxp, &fs, &ds);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);
		cairo_set_dash(cai, dash_mode, ds, ds);
		cairo_set_line_width(cai, fs);

		cairo_stroke(cai);
	}

	cairo_surface_destroy(fac);

	cairo_destroy(cai);
}

void _cairo_draw_rect(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	int fs, ds;

	XPoint pt[2];
    
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(rdc,pt,2);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);
		calc_penmode(pxp, &fs, &ds);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);
		cairo_set_dash(cai, dash_mode, ds, ds);
		cairo_set_line_width(cai, fs);

		cairo_rectangle(cai, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);

		cairo_stroke(cai);
	}

	if(pxb)
	{
		parse_xcolor(&xc,pxb->color);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);

		cairo_rectangle(cai, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);

		cairo_fill(cai);
	}

	cairo_destroy(cai);

	cairo_surface_destroy(fac);
}

void _cairo_draw_triangle(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const tchar_t* orient)
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

	_cairo_draw_line(rdc, pxp, &pt[0], &pt[1]);
	_cairo_draw_line(rdc, pxp, &pt[1], &pt[2]);
	_cairo_draw_line(rdc, pxp, &pt[2], &pt[0]);
}

void _cairo_draw_round(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs)
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

	_cairo_draw_path(rdc, pxp, pxb, ta, pa);
}

void _cairo_draw_ellipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	int fs, ds;

	XPoint pt[2];
    
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(rdc,pt,2);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	cairo_arc (cai, (pt[0].x + pt[1].x) / 2, (pt[0].y + pt[1].y) / 2, (pt[1].x - pt[0].x) / 2, 0, 2 * XPI);

	if(pxb)
	{
		parse_xcolor(&xc,pxb->color);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);

		cairo_fill_preserve(cai);
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);
		calc_penmode(pxp, &fs, &ds);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);
		cairo_set_dash(cai, dash_mode, ds, ds);
		cairo_set_line_width(cai, fs);

		cairo_stroke(cai);
	}

	cairo_destroy(cai);

	cairo_surface_destroy(fac);	
}

void _cairo_draw_pie(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xrect_t* prt, double fang, double sang)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	int fs, ds;

	XPoint pt[2];
	double arcf, arct;
	int clockwise;
    
	arcf = fang;
	arct = fang + sang;

	clockwise = PolarToClockwise(&arcf, &arct);
	
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(rdc,pt,2);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	cairo_move_to(cai, (pt[0].x + pt[1].x) / 2, (pt[0].y + pt[1].y) / 2);

	if(clockwise)
		cairo_arc(cai, (pt[0].x + pt[1].x) / 2, (pt[0].y + pt[1].y) / 2, (pt[1].x - pt[0].x) / 2, arcf, arct);
	else
		cairo_arc_negative(cai, (pt[0].x + pt[1].x) / 2, (pt[0].y + pt[1].y) / 2, (pt[1].x - pt[0].x) / 2, arcf, arct);

	cairo_line_to(cai, (pt[0].x + pt[1].x) / 2, (pt[0].y + pt[1].y) / 2);

	if(pxb)
	{
		parse_xcolor(&xc,pxb->color);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);

		cairo_fill_preserve(cai);
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);
		calc_penmode(pxp, &fs, &ds);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);
		cairo_set_dash(cai, dash_mode, ds, ds);
		cairo_set_line_width(cai, fs);

		cairo_stroke(cai);
	}

	cairo_destroy(cai);

	cairo_surface_destroy(fac);	
}

void _cairo_draw_polygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n)
{
    X11_context_t* ctx = (X11_context_t*)rdc;

	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	int fs, ds;

	XPoint* pa;
	int i;

	if(!n) return;

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}
	
	pa = (XPoint*)calloc(n, sizeof(XPoint));
	for(i =0;i<n;i++)
	{
		pa[i].x = ppt[i].x;
		pa[i].y = ppt[i].y;
	}

	DPtoLP(rdc,pa,n);

	cairo_new_path(cai);

	cairo_move_to(cai, pa[0].x, pa[0].y);

	for(i =1;i<n;i++)
	{
		cairo_line_to(cai, pa[i].x, pa[i].y);
	}

	cairo_close_path(cai);

	free(pa);

	if(pxb)
	{
		parse_xcolor(&xc,pxb->color);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);

		cairo_fill_preserve(cai);
	}

	if(pxp)
	{
		parse_xcolor(&xc,pxp->color);
		calc_penmode(pxp, &fs, &ds);

		cairo_set_source_rgb(cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);
		cairo_set_dash(cai, dash_mode, ds, ds);
		cairo_set_line_width(cai, fs);

		cairo_stroke(cai);
	}

	cairo_surface_destroy(fac);

	cairo_destroy(cai);
}

void _cairo_draw_text(visual_t rdc,const xfont_t* pxf,const xface_t* pxa,const xrect_t* prt,const tchar_t* txt,int len)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

	XPoint pt[2];

	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	cairo_text_extents_t te; 
	int n_weight, n_size;
	int offx, offy;

	tchar_t* str;

	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(rdc,pt,2);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	n_weight = xstol(pxf->weight);
	n_size = xstol(pxf->size);

	parse_xcolor(&xc,pxf->color);

	cairo_set_source_rgb (cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);

	if(xscmp(pxf->style,GDI_ATTR_FONT_STYLE_ITALIC) == 0)
	{
		if(n_weight > 500)
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_BOLD);
		else
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_NORMAL);
	}else
	{
		if(n_weight > 500)
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
		else
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
	}
 
	cairo_set_font_size (cai, n_size); 
	
	if(len < 0) len = xslen(txt);

	str = xsnclone(txt, len);

	cairo_text_extents (cai, str, &te); 

	if(compare_text(pxa->text_align, -1, GDI_ATTR_TEXT_ALIGN_FAR, -1, 1) == 0)
	{
		offx = (pt[1].x - pt[0].x) - (te.x_bearing + te.width);
	}else if(compare_text(pxa->text_align, -1, GDI_ATTR_TEXT_ALIGN_CENTER, -1, 1) == 0) 
	{
		offx = ((pt[1].x - pt[0].x) - (te.x_bearing + te.width)) / 2;
	}else 
	{
		offx = 0;
	}

	if(compare_text(pxa->line_align, -1, GDI_ATTR_TEXT_ALIGN_FAR, -1, 1) == 0)
	{
		offy = (pt[1].y - pt[0].y) - (2 * te.height);
	}else if(compare_text(pxa->line_align, -1, GDI_ATTR_TEXT_ALIGN_NEAR, -1, 1) == 0) 
	{
		offy = te.height;
	}else 
	{
		offy = ((pt[1].y - pt[0].y) + (te.height)) / 2;
	}

	cairo_move_to (cai, pt[0].x + offx, pt[0].y + offy); 

	cairo_show_text (cai, str); 

	xsfree(str);

	cairo_surface_destroy(fac);

	cairo_destroy(cai);
}

void _cairo_text_out(visual_t rdc, const xfont_t* pxf, const xpoint_t* ppt, const tchar_t* txt, int len)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

	XPoint pt[2];
	cairo_t* cai;
	cairo_surface_t* fac;

	xcolor_t xc = {0};
	cairo_text_extents_t te; 
	int n_weight, n_size;

	tchar_t* str;

	pt[0].x = ppt->x;
	pt[0].y = ppt->y;
	pt[1].x = 0;
	pt[1].y = 0;

	DPtoLP(rdc,pt,2);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	n_weight = xstol(pxf->weight);
	n_size = xstol(pxf->size);

	parse_xcolor(&xc,pxf->color);

	cairo_set_source_rgb (cai, xc.r / 255.0, xc.g / 255.0, xc.b / 255.0);

	if(xscmp(pxf->style,GDI_ATTR_FONT_STYLE_ITALIC) == 0)
	{
		if(n_weight > 500)
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_BOLD);
		else
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_NORMAL);
	}else
	{
		if(n_weight > 500)
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
		else
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
	}
 
	cairo_set_font_size (cai, n_size); 

	if(len < 0) len = xslen(txt);

	str = xsnclone(txt, len);

	cairo_text_extents (cai, str, &te); 
	
	cairo_move_to(cai, pt[0].x, pt[0].y + te.height); 

	cairo_show_text (cai, str); 

	xsfree(str);

	cairo_surface_destroy(fac);

	cairo_destroy(cai);
}

void _cairo_text_rect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* prt)
{
	X11_context_t* ctx = (X11_context_t*)rdc;
	bool_t b_ref = 0;

	XPoint pt[2];
	cairo_t* cai;
	cairo_surface_t* fac;

	int n_weight, n_size;
	cairo_text_extents_t te; 

	tchar_t* str;

	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(rdc,pt,2);

	if(!ctx)
	{
		rdc = _create_display_context(NULL);
		ctx = (X11_context_t*)rdc;
		b_ref = 1;
	}

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
	{
		if(b_ref) _destroy_context(rdc);
		
		return;
	}
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
	
		if(b_ref) _destroy_context(rdc);

		return;
	}

	n_weight = xstol(pxf->weight);
	n_size = xstol(pxf->size);

	if(xscmp(pxf->style,GDI_ATTR_FONT_STYLE_ITALIC) == 0)
	{
		if(n_weight > 500)
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_BOLD);
		else
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_NORMAL);
	}else
	{
		if(n_weight > 500)
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
		else
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
	}
 
	cairo_set_font_size (cai, n_size); 

	if(len < 0) len = xslen(txt);

	str = xsnclone(txt, len);

	cairo_text_extents (cai, str, &te); 

	xsfree(str);

	pt[1].x = pt[0].x + te.width;
	pt[1].y = pt[0].y + te.height;

	LPtoDP(rdc, pt, 2);

	prt->w = pt[1].x - pt[0].x;
	prt->h = pt[1].y - pt[0].y;

	cairo_surface_destroy(fac);

	cairo_destroy(cai);

	if(b_ref) _destroy_context(rdc);
}

void _cairo_text_size(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
	X11_context_t* ctx = (X11_context_t*)rdc;
	bool_t b_ref = 0;

	XPoint pt[2];
	cairo_t* cai;
	cairo_surface_t* fac;

	int n_weight, n_size;
	cairo_text_extents_t te; 

	tchar_t* str;

	pt[0].x = 0;
	pt[0].y = 0;
	pt[1].x = pxs->w;
	pt[1].y = pxs->h;

	DPtoLP(rdc,pt,2);

	if(!ctx)
	{
		rdc = _create_display_context(NULL);
		ctx = (X11_context_t*)rdc;
		b_ref = 1;
	}

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
	{
		if(b_ref) _destroy_context(rdc);

		return;
	}
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);

		if(b_ref) _destroy_context(rdc);
		return;
	}

	n_weight = xstol(pxf->weight);
	n_size = xstol(pxf->size);

	if(xscmp(pxf->style,GDI_ATTR_FONT_STYLE_ITALIC) == 0)
	{
		if(n_weight > 500)
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_BOLD);
		else
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_NORMAL);
	}else
	{
		if(n_weight > 500)
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
		else
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
	}
 
	cairo_set_font_size (cai, n_size); 

	if(len < 0) len = xslen(txt);

	str = xsnclone(txt, len);

	cairo_text_extents (cai, str, &te); 

	xsfree(str);

	pt[1].x = pt[0].x + te.width;
	pt[1].y = pt[0].y + te.height;

	LPtoDP(rdc, pt, 2);

	pxs->w = pt[1].x - pt[0].x;
	pxs->h = pt[1].y - pt[0].y;

	cairo_surface_destroy(fac);

	cairo_destroy(cai);

	if(b_ref) _destroy_context(rdc);
}

void _cairo_text_metric(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
	X11_context_t* ctx = (X11_context_t*)rdc;
	bool_t b_ref = 0;

	XPoint pt[2];
	cairo_t* cai;
	cairo_surface_t* fac;

	int n_weight, n_size;
	cairo_font_extents_t te; 

	if(!ctx)
	{
		rdc = _create_display_context(NULL);
		ctx = (X11_context_t*)rdc;
		b_ref = 1;
	}

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
	{
		if(b_ref) _destroy_context(rdc);

		return;
	}
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);

		if(b_ref) _destroy_context(rdc);
		return;
	}

	n_weight = xstol(pxf->weight);
	n_size = xstol(pxf->size);

	if(xscmp(pxf->style,GDI_ATTR_FONT_STYLE_ITALIC) == 0)
	{
		if(n_weight > 500)
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_BOLD);
		else
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_NORMAL);
	}else
	{
		if(n_weight > 500)
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
		else
			cairo_select_font_face(cai, pxf->family, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
	}
 
	cairo_set_font_size (cai, n_size); 

	cairo_font_extents (cai, &te); 

	pt[0].x = 0;
	pt[0].y = 0;
	pt[1].x = pt[0].x + te.max_x_advance;
	pt[1].y = pt[0].y + (te.ascent + te.descent);

	LPtoDP(rdc, pt, 2);

	pxs->w = pt[1].x - pt[0].x;
	pxs->h = pt[1].y - pt[0].y;

	cairo_surface_destroy(fac);

	cairo_destroy(cai);

	if(b_ref) _destroy_context(rdc);
}

#ifdef XDU_SUPPORT_CONTEXT_BITMAP
void _cairo_draw_image(visual_t rdc, bitmap_t rbm, const xcolor_t* clr, const xrect_t* prt)
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

	AdjustRect(&xr, pmi->width, pmi->height, GDI_ATTR_TEXT_ALIGN_CENTER, GDI_ATTR_TEXT_ALIGN_CENTER);
    
	pt[0].x = xr.x;
	pt[0].y = xr.y;
	pt[1].x = xr.x + xr.width;
	pt[1].y = xr.y + xr.height;

	DPtoLP(ctx,pt,2);

	cairo_t* cai;
	cairo_surface_t* fac;
	cairo_surface_t* src;

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;

	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	src = cairo_image_surface_create_for_data(pmi->data, CAIRO_FORMAT_ARGB32, pmi->width, pmi->height, 0);
	if(!src)
	{
		cairo_surface_destroy(fac);
		cairo_destroy(cai);
		return;
	}

	cairo_set_source_surface(cai, src, pt[0].x, pt[0].y);

	cairo_paint(cai);

	cairo_surface_destroy(src);

	cairo_surface_destroy(fac);

	cairo_destroy(cai);
	//XPutImage(g_display, ctx->device, ctx->context, pmi, 0, 0, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);
}

void _cairo_draw_bitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt)
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

void _cairo_gradient_rect(visual_t rdc, const xcolor_t* xc_brim, const xcolor_t* xc_core, const tchar_t* gradient, const xrect_t* prt)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

	cairo_t* cai;
	cairo_surface_t* fac;
	cairo_pattern_t* pat;

	XPoint pt[2];
    
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(rdc,pt,2);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	if(compare_text(gradient, -1, GDI_ATTR_GRADIENT_HORZ, -1,1) == 0)
		pat = cairo_pattern_create_linear(pt[0].x, pt[0].y , pt[1].x , pt[0].y) ;
	else if(compare_text(gradient, -1, GDI_ATTR_GRADIENT_VERT, -1,1) == 0)
		pat = cairo_pattern_create_linear(pt[0].x, pt[0].y , pt[0].x , pt[1].y) ;
	
	cairo_pattern_add_color_stop_rgb (pat, 0, xc_brim->r / 255.0 , xc_brim->g / 255.0 , xc_brim->b / 255.0);;
	cairo_pattern_add_color_stop_rgb (pat, 0.5, xc_core->r / 255.0 , xc_core->g / 255.0 , xc_core->b / 255.0) ;
	cairo_pattern_add_color_stop_rgb (pat, 1, xc_brim->r / 255.0 , xc_brim->g / 255.0 , xc_brim->b / 255.0);

	cairo_rectangle (cai, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y) ;

	cairo_set_source (cai, pat);

	cairo_fill (cai);

	cairo_pattern_destroy (pat);

	cairo_destroy(cai);

	cairo_surface_destroy(fac);
}

void _cairo_alphablend_rect(visual_t rdc, const xcolor_t* pxc, const xrect_t* prt, int opacity)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

	cairo_t* cai;
	cairo_surface_t* fac;

	XPoint pt[2];
    
	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h;

	DPtoLP(rdc,pt,2);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;
	
	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	cairo_set_source_rgba(cai, pxc->r / 255.0, pxc->g / 255.0, pxc->b / 255.0, opacity / 255.0);

	cairo_rectangle(cai, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);

	cairo_fill(cai);

	cairo_destroy(cai);

	cairo_surface_destroy(fac);
}

void _cairo_exclude_rect(visual_t rdc, const xrect_t* pxr)
{
	X11_context_t* ctx = (X11_context_t*)rdc;

	cairo_t* cai;
	cairo_surface_t* fac;

	XPoint pt[2];

	pt[0].x = pxr->x;
	pt[0].y = pxr->y;
	pt[1].x = pxr->x + pxr->w;
	pt[1].y = pxr->y + pxr->h;

	DPtoLP(rdc,pt,2);

	fac = cairo_xlib_surface_create(g_display, ctx->device, ctx->visual, ctx->width, ctx->height);
	if(!fac)
		return;

	cai = cairo_create(fac);
	if(!cai)
	{
		cairo_surface_destroy(fac);
		return;
	}

	cairo_rectangle(cai, pt[0].x, pt[0].y, pt[1].x - pt[0].x, pt[1].y - pt[0].y);

	cairo_clip(cai);

	cairo_surface_destroy(fac);

	cairo_destroy(cai);
}

#ifdef XDU_SUPPORT_CONTEXT_REGION
void _cairo_fill_region(visual_t rdc, const xbrush_t* pxb, res_rgn_t rgn)
{
    
}
#endif

#endif //XDU_SUPPORT_CONTEXT_GRAPHIC

