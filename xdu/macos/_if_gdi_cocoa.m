/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdi document

	@module	if_gd_cocoa.m | macos implement file

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

static void DPtoLP(visual_t rdc, CGPoint* pt,int n)
{
	cocoa_context_t* ctx = (cocoa_context_t*)rdc;
	int i, h;
	h = ctx->client.size.height;

	for(i = 0;i<n;i++)
	{
		pt[i].x = pt[i].x;
		pt[i].y = h - pt[i].y;
	}
}

static void _adjust_rect(CGRect* prt, int src_width, int src_height, const tchar_t* horz_align, const tchar_t* vert_align)
{
	if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0 && xscmp(vert_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		prt->origin.y += (prt->size.height - src_height);
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		NOP;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		prt->origin.x += (prt->size.width - src_width);
		prt->origin.y += (prt->size.height - src_height);
	}
	else if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		prt->origin.x += (prt->size.width - src_width);
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		prt->origin.y += (prt->size.height - src_height) / 2;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		prt->origin.x += (prt->size.width - src_width);
		prt->origin.y += (prt->size.height - src_height) / 2;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		prt->origin.x += (prt->size.width - src_width) / 2;
		prt->origin.y += (prt->size.height - src_height);
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		prt->origin.x += (prt->size.width - src_width) / 2;
	}
	else if (xscmp(horz_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0 && xscmp(vert_align,GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		prt->origin.x += (prt->size.width - src_width) / 2;
		prt->origin.y += (prt->size.height - src_height) / 2;
	}

	prt->size.width = (prt->size.width < src_width) ? prt->size.width : src_width;
	prt->size.height = (prt->size.height < src_height) ? prt->size.height : src_height;
}

static void _calc_point(const xpoint_t* pt, int r, double a, xpoint_t* pp)
{
	pp->x = pt->x + (int)((float)r * cos(a));
	pp->y = pt->y + (int)((float)r * sin(a));
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
	NOP;
}

void _gdi_uninit(void)
{
	NOP;
}

void _gdi_get_point(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt)
{
	NOP;
}

void _gdi_set_point(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt)
{
	NOP;
}

void _gdi_draw_points(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt, int n)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	CGRect* pRect;
	int i;

	pRect = (CGRect*)xmem_alloc(sizeof(CGRect));

	for(i=0;i<n;i++)
	{
		pRect[i].origin.x = pRect[i].origin.x;
		pRect[i].origin.y = pRect[i].origin.y;

		DPtoLP(rdc,(CGPoint*)pRect,1);
	}

	if(pxc)
	{
		CGContextSetRGBFillColor(ctx->context, (float)(pxc->r) / 255.0f, (float)(pxc->g) / 255.0f, (float)(pxc->b) / 255.0f, 1.0); // Blue color
	}

	CGContextFillRects(ctx->context, pRect, n);

	xmem_free(pRect);
}

void _gdi_draw_line(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2)
{
    cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	CGPoint point1 = CGPointMake(ppt1->x, ppt1->y);
	CGPoint point2 = CGPointMake(ppt2->x, ppt2->y);

	DPtoLP(rdc, &point1, 1);
	DPtoLP(rdc, &point2, 1);

    if(pxp)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxp->color);
		CGContextSetRGBStrokeColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
    	CGContextSetLineWidth(ctx->context, (is_null(pxp->size) ? xstol(pxp->size) : 1)); 
	}
	
	CGContextMoveToPoint(ctx->context, point1.x, point1.y); 
    CGContextAddLineToPoint(ctx->context, point2.x, point2.y);

    CGContextStrokePath(ctx->context);
}

void _gdi_draw_polyline(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n)
{
    cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	CGPoint* points = (CGPoint*)xmem_alloc(n * sizeof(CGPoint));
	for(int i = 0; i < n; i++)
	{
		points[i].x = ppt[i].x;
		points[i].y = ppt[i].y;
	}
	DPtoLP(rdc, points, n);

	CGContextMoveToPoint(ctx->context, points[0].x, points[0].y); 
	for(int i = 1; i < n; i++)
	{
    	CGContextAddLineToPoint(ctx->context, points[i].x, points[i].y); 
	}

    if(pxp)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxp->color);
		CGContextSetRGBStrokeColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
    	CGContextSetLineWidth(ctx->context, (is_null(pxp->size) ? xstol(pxp->size) : 1)); 
	}

	CGContextStrokePath(ctx->context);

	xmem_free(points);
}

void _gdi_draw_arc(visual_t rdc, const xpen_t* pxp, const xpoint_t * ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t clockwise, bool_t largearc)
{
    cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	xpoint_t pt_center = {0};
	double arcf = 0.0, arct = 0.0;

	bool_t cw = pt_calc_radian(clockwise, largearc, pxs->w, pxs->h, ppt1, ppt2, &pt_center, &arcf, &arct);

	CGPoint points[3] = {0};
	points[0].x = ppt1->x;
	points[0].y = ppt1->y;
	points[1].x = ppt2->x;
	points[1].y = ppt2->y;
	points[2].x = pt_center.x;
	points[2].y = pt_center.y;

	DPtoLP(rdc, points, 3);

	CGContextAddArc(ctx->context, points[2].x, points[2].y, pxs->w, arcf, arct, cw);

	if(pxp)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxp->color);
		CGContextSetRGBStrokeColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
    	CGContextSetLineWidth(ctx->context, (is_null(pxp->size) ? xstol(pxp->size) : 1)); 
	}

	CGContextStrokePath(ctx->context);
}

void _gdi_draw_bezier(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	CGPoint points[4] = {0};
	points[0].x = ppt1->x;
	points[0].y = ppt1->y;
	points[1].x = ppt2->x;
	points[1].y = ppt2->y;
	points[2].x = ppt3->x;
	points[2].y = ppt3->y;
	points[3].x = ppt4->x;
	points[3].y = ppt4->y;

	DPtoLP(rdc, points, 4);

	if(pxp)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxp->color);
		CGContextSetRGBStrokeColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 

    	CGContextSetLineWidth(ctx->context, (is_null(pxp->size) ? xstol(pxp->size) : 1)); 
	}

	CGContextMoveToPoint(ctx->context, points[0].x, points[0].y);
    CGContextAddCurveToPoint(ctx->context, points[1].x, points[1].y, points[2].x, points[2].y, points[3].x, points[3].y); 

	CGContextStrokePath(ctx->context);
}

void _gdi_draw_curve(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int pn)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	CGPoint* points = (CGPoint*)xmem_alloc(pn * sizeof(CGPoint));
	for(int i = 0; i < pn; i++)
	{
		points[i].x = ppt[i].x;
		points[i].y = ppt[i].y;
	}
	DPtoLP(rdc, points, pn);

	if(pxp)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxp->color);
		CGContextSetRGBStrokeColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
    	CGContextSetLineWidth(ctx->context, (is_null(pxp->size) ? xstol(pxp->size) : 1)); 
	}

	CGContextMoveToPoint(ctx->context, points[0].x, points[0].y);

	if(pn == 3)
		CGContextAddQuadCurveToPoint(ctx->context, points[1].x, points[1].y, points[2].x, points[2].y);
	else if(pn == 4)
    	CGContextAddCurveToPoint(ctx->context, points[1].x, points[1].y, points[2].x, points[2].y, points[3].x, points[3].y); 

	CGContextStrokePath(ctx->context); 

	xmem_free(points);
}

void _gdi_draw_path(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int pn)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	xpoint_t pt_m = { 0 };
	xpoint_t pt_p = { 0 };
	xpoint_t pt_i = { 0 };
	xpoint_t pt[4] = { 0 };

	int sflag, lflag, nflag;
	double arcf, arct;
	int n = 0;
	xpoint_t cp;
	xsize_t xs;

	if (!aa) return;

	while (*aa && pn)
	{
		if (*aa == _T('M') || *aa == _T('m'))
		{
			pt_m.x = pa[0].x;
			pt_m.y = pa[0].y;

			pt_p.x = pt_m.x;
			pt_p.y = pt_m.y;

			n = 1;

			CGPoint point = CGPointMake(pt_m.x, pt_m.y);
			DPtoLP(rdc, &point, 1);
			CGContextMoveToPoint(ctx->context, point.x, point.y);
		}
		else if (*aa == _T('L') || *aa == _T('l'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pa[0].x;
			pt[1].y = pa[0].y;

			pt_p.x = pt[1].x;
			pt_p.y = pt[1].y;
			pt_i.x = 2 * pt[1].x - pt[0].x;
			pt_i.y = 2 * pt[1].y - pt[0].y;

			n = 1;

			CGPoint point = CGPointMake(pt[1].x, pt[1].y);
			DPtoLP(rdc, &point, 1);
			CGContextAddLineToPoint(ctx->context, point.x, point.y); 
		}
		else if (*aa == _T('Q') || *aa == _T('q'))
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

			n = 2;

			CGPoint points[2];
			points[0] = CGPointMake(pt[1].x, pt[1].y);
			points[1] = CGPointMake(pt[2].x, pt[2].y);
			DPtoLP(rdc, points, 2);
			CGContextAddQuadCurveToPoint(ctx->context, points[0].x, points[0].y, points[1].x, points[1].y);
		}
		else if (*aa == _T('T') || *aa == _T('t'))
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

			n = 1;

			CGPoint points[2];
			points[0] = CGPointMake(pt[1].x, pt[1].y);
			points[1] = CGPointMake(pt[2].x, pt[2].y);
			DPtoLP(rdc, points, 2);
			CGContextAddQuadCurveToPoint(ctx->context, points[0].x, points[0].y, points[1].x, points[1].y);
		}
		else if (*aa == _T('C') || *aa == _T('c'))
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

			n = 3;

			CGPoint points[3];
			points[0] = CGPointMake(pt[1].x, pt[1].y);
			points[1] = CGPointMake(pt[2].x, pt[2].y);
			points[2] = CGPointMake(pt[3].x, pt[3].y);
			DPtoLP(rdc, points, 3);
			CGContextAddCurveToPoint(ctx->context, points[0].x, points[0].y, points[1].x, points[1].y, points[2].x, points[2].y); 
		}
		else if (*aa == _T('S') || *aa == _T('s'))
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

			n = 2;

			CGPoint points[3];
			points[0] = CGPointMake(pt[1].x, pt[1].y);
			points[1] = CGPointMake(pt[2].x, pt[2].y);
			points[2] = CGPointMake(pt[3].x, pt[3].y);
			DPtoLP(rdc, points, 3);
			CGContextAddCurveToPoint(ctx->context, points[0].x, points[0].y, points[1].x, points[1].y, points[2].x, points[2].y); 
		}
		else if (*aa == _T('A') || *aa == _T('a'))
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

			n = 3;

			nflag = pt_calc_radian(sflag, lflag, xs.w, xs.h, &pt[0], &pt[1], &cp, &arcf, &arct);
			
			CGPoint points[3] = {0};
			points[0].x = pt[0].x;
			points[0].y = pt[0].y;
			points[1].x = pt[1].x;
			points[1].y = pt[1].y;
			points[2].x = cp.x;
			points[2].y = cp.y;
			DPtoLP(rdc, points, 3);
			if(nflag == sflag)
				CGContextAddArc(ctx->context, points[2].x, points[2].y, xs.w, arcf, arct, sflag);
			else
				CGContextAddArc(ctx->context, points[2].x, points[2].y, xs.w, arct, arcf, sflag);
		}
		else if (*aa == _T('Z') || *aa == _T('z'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_m.x;
			pt[1].y = pt_m.y;

			pt_p.x = pt[1].x;
			pt_p.y = pt[1].y;
			pt_i.x = 2 * pt[1].x - pt[0].x;
			pt_i.y = 2 * pt[1].y - pt[0].y;

			n = 1;

			CGPoint point = CGPointMake(pt[1].x, pt[1].y);
			DPtoLP(rdc, &point, 1);
			CGContextAddLineToPoint(ctx->context, point.x, point.y);
			break;
		}

		aa++;
		pa += n;
		pn -= n;
	}

	if(pxp)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxp->color);
		CGContextSetRGBStrokeColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
		CGContextSetLineWidth(ctx->context, (is_null(pxp->size) ? xstol(pxp->size) : 1)); 
	}

	if(pxb)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxb->color);
		CGContextSetRGBFillColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 

		CGContextClosePath(ctx->context);
	}

	if(pxb)
		CGContextDrawPath(ctx->context, kCGPathFillStroke);
	else
		CGContextStrokePath(ctx->context);
}

void _gdi_draw_rect(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	CGPoint point = {pxr->x, pxr->y + pxr->h};
	DPtoLP(rdc,(CGPoint*)&point,1);

	CGRect rect = CGRectMake(point.x, point.y, pxr->w, pxr->h);
	CGContextAddRect(ctx->context, rect);

	if(pxp)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxp->color);
		CGContextSetRGBStrokeColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
		CGContextSetLineWidth(ctx->context, (is_null(pxp->size) ? xstol(pxp->size) : 1)); 
	}

	if(pxb)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxb->color);
		CGContextSetRGBFillColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
	}

	if(pxb)
		CGContextDrawPath(ctx->context, kCGPathFillStroke);
	else
		CGContextStrokePath(ctx->context);
}

void _gdi_draw_ellipse(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* pxr)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	CGPoint point = {pxr->x, pxr->y + pxr->h};
	DPtoLP(rdc,(CGPoint*)&point,1);

	CGRect rect = CGRectMake(point.x, point.y, pxr->w, pxr->h);
    CGContextAddEllipseInRect(ctx->context, rect);

	if(pxp)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxp->color);
		CGContextSetRGBStrokeColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
		CGContextSetLineWidth(ctx->context, (is_null(pxp->size) ? xstol(pxp->size) : 1)); 
	}

	if(pxb)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxb->color);
		CGContextSetRGBFillColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
	}

	if(pxb)
		CGContextDrawPath(ctx->context, kCGPathFillStroke);
	else
		CGContextStrokePath(ctx->context);
}

void _gdi_draw_round(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* prt,const xsize_t* pxs)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

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

	CGPoint* points = (CGPoint*)xmem_alloc(8 * sizeof(CGPoint));

	//the line segments
	points[0].x = prt->x + rx, points[0].y = prt->y;
	points[1].x = prt->x + prt->w - rx, points[1].y = prt->y;

	points[2].x = prt->x + prt->w, points[2].y = prt->y + ry;
	points[3].x = prt->x + prt->w, points[3].y = prt->y + prt->h - ry;

	points[4].x = prt->x + prt->w - rx, points[4].y = prt->y + prt->h;
	points[5].x = prt->x + rx, points[5].y = prt->y + prt->h;

	points[6].x = prt->x, points[6].y = prt->y + prt->h - ry;
	points[7].x = prt->x, points[7].y = prt->y + ry;

	DPtoLP(rdc, points, 8);

    CGContextBeginPath(ctx->context);
    CGContextMoveToPoint(ctx->context, points[0].x, points[0].y);
   	CGContextAddLineToPoint(ctx->context, points[1].x, points[1].y);
    CGContextAddArcToPoint(ctx->context, points[2].x, points[1].y, points[2].x, points[2].y, rx);
	
	CGContextAddLineToPoint(ctx->context, points[3].x, points[3].y);
	CGContextAddArcToPoint(ctx->context, points[3].x, points[4].y, points[4].x, points[4].y, rx);
	
	CGContextAddLineToPoint(ctx->context, points[5].x, points[5].y);
	CGContextAddArcToPoint(ctx->context, points[6].x, points[5].y, points[6].x, points[6].y, rx);
	
	CGContextAddLineToPoint(ctx->context, points[7].x, points[7].y);
	CGContextAddArcToPoint(ctx->context, points[7].x, points[0].y, points[0].x, points[0].y, rx);
    CGContextClosePath(ctx->context);

	if(pxp)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxp->color);
		CGContextSetRGBStrokeColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
		CGContextSetLineWidth(ctx->context, (is_null(pxp->size) ? xstol(pxp->size) : 1)); 
	}

	if(pxb)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxb->color);
		CGContextSetRGBFillColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
	}

	if(pxb)
		CGContextDrawPath(ctx->context, kCGPathFillStroke);
	else
		CGContextStrokePath(ctx->context);

	xmem_free(points);
}

void _gdi_draw_pie(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr,  double arcf, double arct)
{
    cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	CGPoint point = CGPointMake(pxr->x + pxr->w / 2, pxr->y + pxr->h / 2);
	DPtoLP(rdc, &point, 1);

	CGContextBeginPath(ctx->context);
	CGContextMoveToPoint(ctx->context, point.x, point.y);
	CGContextAddArc(ctx->context, point.x, point.y, pxr->w / 2, arcf, arct, 0);
	CGContextClosePath(ctx->context);

	if(pxp)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxp->color);
		CGContextSetRGBStrokeColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
    	CGContextSetLineWidth(ctx->context, (is_null(pxp->size) ? xstol(pxp->size) : 1)); 
	}

	if(pxb)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxb->color);
		CGContextSetRGBFillColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
	}

	if(pxb)
		CGContextDrawPath(ctx->context, kCGPathFillStroke);
	else
		CGContextStrokePath(ctx->context);
}

void _gdi_draw_polygon(visual_t rdc, const xpen_t* pxp, const xbrush_t*pxb, const xpoint_t* ppt, int n)
{
    cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	CGPoint* points = (CGPoint*)xmem_alloc(n * sizeof(CGPoint));
	for(int i = 0; i < n; i++)
	{
		points[i].x = ppt[i].x;
		points[i].y = ppt[i].y;
	}
	DPtoLP(rdc, points, n);

	CGContextBeginPath(ctx->context);
    CGContextMoveToPoint(ctx->context, points[0].x, points[0].y); 
	for(int i = 1; i < n; i++)
	{
    	CGContextAddLineToPoint(ctx->context, points[i].x, points[i].y); 
	}
	CGContextClosePath(ctx->context);

	if(pxp)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxp->color);
		CGContextSetRGBStrokeColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
    	CGContextSetLineWidth(ctx->context, (is_null(pxp->size) ? xstol(pxp->size) : 1)); 
	}

	if(pxb)
	{
		xcolor_t xc = {0};
		parse_xcolor(&xc, pxb->color);
		CGContextSetRGBFillColor(ctx->context, (float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0); 
	}
	
	if(pxb)
		CGContextDrawPath(ctx->context, kCGPathFillStroke);
	else
		CGContextStrokePath(ctx->context);

	xmem_free(points);
}

void _gdi_draw_text(visual_t rdc,const xfont_t* pxf,const xface_t* pxa,const xrect_t* pxr,const tchar_t* txt,int len)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);
	
	if(len < 0) len = xslen(txt);
	if(!len) return;

	CGPoint cgPoints = {pxr->x, pxr->y + pxr->h};
	DPtoLP(rdc, &cgPoints, 1);
	CGRect cgRect = {cgPoints.x, cgPoints.y, pxr->w, pxr->h};

	tchar_t* new_txt = xsnclone(txt, len);
    CFStringRef cfString = CFStringCreateWithCString(NULL, new_txt, kCFStringEncodingUTF8);
	xsfree(new_txt);

	float px = 0.0f;
	font_metric_by_pt(xstof(pxf->size), NULL, &px); 
	CFStringRef cfFamily = CFStringCreateWithCString(NULL, pxf->family, kCFStringEncodingUTF8);
    CTFontRef cfFont = CTFontCreateWithName(cfFamily, px, NULL);
	CFRelease(cfFamily);

    CFMutableAttributedStringRef attrString = CFAttributedStringCreateMutable(kCFAllocatorDefault, 0);
    CFAttributedStringReplaceString(attrString, CFRangeMake(0, 0), cfString);
    CFAttributedStringSetAttribute(attrString, CFRangeMake(0, CFStringGetLength(cfString)), kCTFontAttributeName, cfFont);

	xcolor_t xc = {0};
	parse_xcolor(&xc, pxf->color);
	CGColorRef cfColor = CGColorCreateGenericRGB((float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0);
	CFAttributedStringSetAttribute(attrString, CFRangeMake(0, CFStringGetLength(cfString)), kCTForegroundColorAttributeName, cfColor);
	CGColorRelease(cfColor);

    CTLineRef cfLine = CTLineCreateWithAttributedString(attrString);

	CGFloat ascent = 0.0, descent = 0.0, leading = 0.0;
    CGFloat width = CTLineGetTypographicBounds(cfLine, &ascent, &descent, &leading);
    CGFloat height = ascent + descent + leading;
	_adjust_rect(&cgRect, width, height, pxa->text_align, pxa->line_align);

    CGContextSetTextPosition(ctx->context,cgRect.origin.x, cgRect.origin.y);
    CTLineDraw(cfLine, ctx->context);

	CFRelease(cfString);
    CFRelease(cfLine);
    CFRelease(attrString);
    CFRelease(cfFont);
}

void _gdi_text_out(visual_t rdc, const xfont_t* pxf, const xpoint_t* ppt, const tchar_t* txt, int len)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);
	
	if(len < 0) len = xslen(txt);
	if(!len) return;

	CGPoint cgPoint = { ppt->x, ppt->y }; 
	DPtoLP(rdc, &cgPoint, 1);

    tchar_t* new_txt = xsnclone(txt, len);
    CFStringRef cfString = CFStringCreateWithCString(NULL, new_txt, kCFStringEncodingUTF8);
	xsfree(new_txt);

	float px = 0.0f;
	font_metric_by_pt(xstof(pxf->size), NULL, &px);
    CFStringRef cfFamily = CFStringCreateWithCString(NULL, pxf->family, kCFStringEncodingUTF8); 
    CTFontRef cfFont = CTFontCreateWithName(cfFamily, px, NULL);
	CFRelease(cfFamily);
	cgPoint.y -= px;

    CFMutableAttributedStringRef attrString = CFAttributedStringCreateMutable(kCFAllocatorDefault, 0);
    CFAttributedStringReplaceString(attrString, CFRangeMake(0, 0), cfString);
    CFAttributedStringSetAttribute(attrString, CFRangeMake(0, CFStringGetLength(cfString)), kCTFontAttributeName, cfFont);

	xcolor_t xc = {0};
	parse_xcolor(&xc, pxf->color);
	CGColorRef cfColor = CGColorCreateGenericRGB((float)(xc.r) / 255.0f, (float)(xc.g) / 255.0f, (float)(xc.b) / 255.0f, 1.0);
	CFAttributedStringSetAttribute(attrString, CFRangeMake(0, CFStringGetLength(cfString)), kCTForegroundColorAttributeName, cfColor);
	CGColorRelease(cfColor);

    CTLineRef cfLine = CTLineCreateWithAttributedString(attrString);

    CGContextSetTextPosition(ctx->context, cgPoint.x, cgPoint.y);
    CTLineDraw(cfLine, ctx->context);

	CFRelease(cfString);
    CFRelease(cfLine);
    CFRelease(attrString);
    CFRelease(cfFont);
}

void _gdi_text_rect(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* pxr)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	if(len < 0) len = xslen(txt);
	if(!len) return;

	tchar_t* new_txt = xsnclone(txt, len);
	CFStringRef cfString = CFStringCreateWithCString(NULL, new_txt, kCFStringEncodingUTF8);
	xsfree(new_txt);
 
 	float px = 0.0f;
	font_metric_by_pt(xstof(pxf->size), NULL, &px); 
    CFStringRef cfFamily = CFStringCreateWithCString(NULL, pxf->family, kCFStringEncodingUTF8);
    CTFontRef cfFont = CTFontCreateWithName(cfFamily, px, NULL);
	CFRelease(cfFamily);

    CFMutableAttributedStringRef attrString = CFAttributedStringCreateMutable(kCFAllocatorDefault, 0);
    CFAttributedStringReplaceString(attrString, CFRangeMake(0, 0), cfString);
    CFAttributedStringSetAttribute(attrString, CFRangeMake(0, CFStringGetLength(cfString)), kCTFontAttributeName, cfFont);

    CTLineRef cfLine = CTLineCreateWithAttributedString(attrString);

    CGFloat ascent = 0.0, descent = 0.0, leading = 0.0;
    CGFloat width = CTLineGetTypographicBounds(cfLine, &ascent, &descent, &leading);
    CGFloat height = ascent + descent + leading;

	CFRelease(cfString);
    CFRelease(cfLine);
    CFRelease(attrString);
    CFRelease(cfFont);

    if(pxr->w < (int)width) pxr->w = (int)width;
	if(pxr->h < (int)height) pxr->h = (int)height;
}

void _gdi_text_size(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	if(len < 0) len = xslen(txt);
	if(!len) {
		pxs->w = 0;
		pxs->h = 0;
		return;
	}

	tchar_t* new_txt = xsnclone(txt, len);
	CFStringRef cfString = CFStringCreateWithCString(NULL, new_txt, kCFStringEncodingUTF8);
	xsfree(new_txt);

    float px = 0.0f;
	font_metric_by_pt(xstof(pxf->size), NULL, &px); 
    CFStringRef cfFamily = CFStringCreateWithCString(NULL, pxf->family, kCFStringEncodingUTF8);
    CTFontRef cfFont = CTFontCreateWithName(cfFamily, px, NULL);
	CFRelease(cfFamily);

    CFMutableAttributedStringRef attrString = CFAttributedStringCreateMutable(kCFAllocatorDefault, 0);
    CFAttributedStringReplaceString(attrString, CFRangeMake(0, 0), cfString);
    CFAttributedStringSetAttribute(attrString, CFRangeMake(0, CFStringGetLength(cfString)), kCTFontAttributeName, cfFont);

    CTLineRef cfLine = CTLineCreateWithAttributedString(attrString);

    CGFloat ascent = 0.0, descent = 0.0, leading = 0.0;
    CGFloat width = CTLineGetTypographicBounds(cfLine, &ascent, &descent, &leading);
    CGFloat height = ascent + descent;

	CFRelease(cfString);
    CFRelease(cfLine);
    CFRelease(attrString);
    CFRelease(cfFont);

    pxs->w = (int)width;
	pxs->h = (int)height;
}

void _gdi_font_size(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	float px = 0.0f;
	font_metric_by_pt(xstof(pxf->size), NULL, &px); 
	CFStringRef cfFamily = CFStringCreateWithCString(NULL, pxf->family, kCFStringEncodingUTF8);
	
    CTFontRef cfFont = CTFontCreateWithName(cfFamily, px, NULL);
	CFRelease(cfFamily);

    CGFloat ascent = CTFontGetAscent(cfFont);
    CGFloat descent = CTFontGetDescent(cfFont);
    CGFloat leading = CTFontGetLeading(cfFont);
    CGFloat capHeight = CTFontGetCapHeight(cfFont);
	CFRelease(cfFont);

	pxs->w = pxs->h = (int)(ascent + descent + leading);
}

void _gdi_gradient_rect(visual_t rdc, const xcolor_t* clr_brim, const xcolor_t* clr_core, const tchar_t* gradient, const xrect_t* prt)
{
    cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();

	if(compare_text(gradient,-1,GDI_ATTR_GRADIENT_VERT,-1,1) == 0)
	{
    	CGFloat clrs1[8] = {
        	(float)clr_brim->r / 255.0f, (float)clr_brim->g / 255.0f, (float)clr_brim->b / 255.0f, 1.0,
        	(float)clr_core->r / 255.0f, (float)clr_core->g / 255.0f, (float)clr_core->b / 255.0f, 1.0
    	};

		CGGradientRef ref1 = CGGradientCreateWithColorComponents(colorSpace, clrs1, NULL, 2);

		CGRect rect1 = CGRectMake(prt->x, prt->y + prt->h, prt->w, prt->h / 2);
    	DPtoLP(rdc, (CGPoint*)&rect1, 1);

    	CGPoint sp1 = CGPointMake(CGRectGetMidX(rect1), CGRectGetMinY(rect1));
    	CGPoint ep1 = CGPointMake(CGRectGetMidX(rect1), CGRectGetMaxY(rect1));

		CGContextSaveGState(ctx->context);
    	CGContextClipToRect(ctx->context, rect1);
    	CGContextDrawLinearGradient(ctx->context, ref1, sp1, ep1, 0);

    	CGGradientRelease(ref1);
		CGContextRestoreGState(ctx->context);

		CGFloat clrs2[8] = {
			(float)clr_core->r / 255.0f, (float)clr_core->g / 255.0f, (float)clr_core->b / 255.0f, 1.0,
        	(float)clr_brim->r / 255.0f, (float)clr_brim->g / 255.0f, (float)clr_brim->b / 255.0f, 1.0
		};

		CGGradientRef ref2 = CGGradientCreateWithColorComponents(colorSpace, clrs2, NULL, 2);

		CGRect rect2 = CGRectMake(prt->x, prt->y + prt->h / 2, prt->w, prt->h / 2);
    	DPtoLP(rdc, (CGPoint*)&rect2, 1);

    	CGPoint sp2 = CGPointMake(CGRectGetMidX(rect2), CGRectGetMinY(rect2));
    	CGPoint ep2 = CGPointMake(CGRectGetMidX(rect2), CGRectGetMaxY(rect2));

		CGContextSaveGState(ctx->context);
    	CGContextClipToRect(ctx->context, rect2);
    	CGContextDrawLinearGradient(ctx->context, ref2, sp2, ep2, 0);

    	CGGradientRelease(ref2);
		CGContextRestoreGState(ctx->context);
	}else if(compare_text(gradient,-1,GDI_ATTR_GRADIENT_HORZ,-1,1) == 0)
	{
    	CGFloat clrs1[8] = {
        	(float)clr_brim->r / 255.0f, (float)clr_brim->g / 255.0f, (float)clr_brim->b / 255.0f, 1.0,
        	(float)clr_core->r / 255.0f, (float)clr_core->g / 255.0f, (float)clr_core->b / 255.0f, 1.0
    	};

		CGGradientRef ref1 = CGGradientCreateWithColorComponents(colorSpace, clrs1, NULL, 2);

		CGRect rect1 = CGRectMake(prt->x, prt->y + prt->h, prt->w / 2, prt->h);
    	DPtoLP(rdc, (CGPoint*)&rect1, 1);

    	CGPoint sp1 = CGPointMake(CGRectGetMinX(rect1), CGRectGetMidY(rect1));
    	CGPoint ep1 = CGPointMake(CGRectGetMaxX(rect1), CGRectGetMidY(rect1));

		CGContextSaveGState(ctx->context);
    	CGContextClipToRect(ctx->context, rect1);
    	CGContextDrawLinearGradient(ctx->context, ref1, sp1, ep1, 0);

    	CGGradientRelease(ref1);
		CGContextRestoreGState(ctx->context);

		CGFloat clrs2[8] = {
			(float)clr_core->r / 255.0f, (float)clr_core->g / 255.0f, (float)clr_core->b / 255.0f, 1.0,
        	(float)clr_brim->r / 255.0f, (float)clr_brim->g / 255.0f, (float)clr_brim->b / 255.0f, 1.0
		};

		CGGradientRef ref2 = CGGradientCreateWithColorComponents(colorSpace, clrs2, NULL, 2);

		CGRect rect2 = CGRectMake(prt->x + prt->w / 2, prt->y + prt->h, prt->w / 2, prt->h);
    	DPtoLP(rdc, (CGPoint*)&rect2, 1);

    	CGPoint sp2 = CGPointMake(CGRectGetMinX(rect2), CGRectGetMidY(rect2));
    	CGPoint ep2 = CGPointMake(CGRectGetMaxX(rect2), CGRectGetMidY(rect2));

		CGContextSaveGState(ctx->context);
    	CGContextClipToRect(ctx->context, rect2);
    	CGContextDrawLinearGradient(ctx->context, ref2, sp2, ep2, 0);

    	CGGradientRelease(ref2);
		CGContextRestoreGState(ctx->context);
	}
	
	CGColorSpaceRelease(colorSpace);
}

void _gdi_alphablend_rect(visual_t rdc, const xcolor_t* pxc, const xrect_t* pxr, int opacity)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

    CGRect rect = CGRectMake(pxr->x, pxr->y + pxr->h, pxr->w, pxr->h);
	DPtoLP(rdc,(CGPoint*)&rect,1);

    CGFloat alpha = opacity / 255.0;
    CGContextSetAlpha(ctx->context, alpha);
    CGContextSetRGBFillColor(ctx->context, (float)pxc->r / 255, (float)pxc->g / 255, (float)pxc->b / 255, 1.0); 

    CGContextFillRect(ctx->context, rect);
}

void _gdi_invert_rect(visual_t rdc, const xrect_t* pxr)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

    CGRect rect = CGRectMake(pxr->x, pxr->y + pxr->h, pxr->w, pxr->h);
	DPtoLP(rdc,(CGPoint*)&rect,1);

    CGContextSetBlendMode(ctx->context, kCGBlendModeDifference);
	CGContextSetRGBFillColor(ctx->context, 1.0, 1.0, 1.0, 1.0); 
    CGContextFillRect(ctx->context, rect);
	CGContextSetBlendMode(ctx->context, kCGBlendModeNormal);
}

void _gdi_exclude_rect(visual_t rdc, const xrect_t* pxr)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

	CGRect rect = CGRectMake(pxr->x, pxr->y + pxr->h, pxr->w, pxr->h);
	DPtoLP(rdc,(CGPoint*)&rect,1);

	CGContextAddRect(ctx->context, CGContextGetClipBoundingBox(ctx->context));
	CGContextAddRect(ctx->context, rect); 
    CGContextEOClip(ctx->context);
}

void _gdi_inclip_rect(visual_t rdc, const xrect_t* pxr)
{
   	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);

    CGRect rect = CGRectMake(pxr->x, pxr->y + pxr->h, pxr->w, pxr->h);
	DPtoLP(rdc,(CGPoint*)&rect,1);

    CGContextClipToRect(ctx->context, rect);
}

#ifdef XDU_SUPPORT_CONTEXT_BITMAP
void _gdi_draw_image(visual_t rdc,bitmap_t rbm,const xcolor_t* clr,const xrect_t* prt)
{
    cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);
	cocoa_bitmap_t* bmp = TypePtrFromHead(cocoa_bitmap_t, rbm);

	CGRect rect = CGRectMake(prt->x, prt->y + prt->h, prt->w, prt->h);
	DPtoLP(rdc,(CGPoint*)&rect,1);

  	size_t width = CGImageGetWidth(bmp->image);
    size_t height = CGImageGetHeight(bmp->image);

	_adjust_rect(&rect, width, height, GDI_ATTR_TEXT_ALIGN_CENTER, GDI_ATTR_TEXT_ALIGN_CENTER);
    
    CGContextDrawImage(ctx->context, rect, bmp->image);
}

void _gdi_draw_bitmap(visual_t rdc, bitmap_t rbm, const xpoint_t* ppt)
{
	cocoa_context_t* ctx = TypePtrFromHead(cocoa_context_t, rdc);
	cocoa_bitmap_t* bmp = TypePtrFromHead(cocoa_bitmap_t, rbm);

  	size_t width = CGImageGetWidth(bmp->image);
    size_t height = CGImageGetHeight(bmp->image);

	CGRect rect = CGRectMake(ppt->x, ppt->y + height, width, height);
	DPtoLP(rdc,(CGPoint*)&rect,1);

    CGContextDrawImage(ctx->context, rect, bmp->image);
}
#endif


#endif //XDU_SUPPORT_CONTEXT_GRAPHIC

