﻿/***********************************************************************
	Easily xdl v5.5

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc gdi document

	@module	impgdi.c | implement file

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

#include "impgdi.h"

#include "../xdcimp.h"
#include "../xdcinit.h"

#if defined(XDU_SUPPORT_CONTEXT)

void get_point_raw(visual_t rdc, xcolor_t* pxc, const xpoint_t* ppt)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_get_point)(rdc, pxc, ppt);
}

void get_point(canvas_t canv, xcolor_t* pxc, const xpoint_t* ppt)
{
	visual_t rdc;
	xpoint_t pt;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	rdc = get_canvas_visual(canv);

	xmem_copy((void*)&pt, (void*)ppt, sizeof(xpoint_t));

	point_tm_to_pt(canv, &pt);

	(*pif->pf_gdi_get_point)(rdc, pxc, &pt);
}

void set_point_raw(visual_t rdc, const xcolor_t* pxc, const xpoint_t* ppt)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_set_point)(rdc, pxc, ppt);
}

void set_point(canvas_t canv, const xcolor_t* pxc, const xpoint_t* ppt)
{
	visual_t rdc;
	xpoint_t pt;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	rdc = get_canvas_visual(canv);

	xmem_copy((void*)&pt, (void*)ppt, sizeof(xpoint_t));

	point_tm_to_pt(canv, &pt);

	(*pif->pf_gdi_set_point)(rdc, pxc, &pt);
}

void draw_line_raw(visual_t rdc,const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_line)(rdc, pxp, ppt1, ppt2);
}

void draw_line(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2)
{
	visual_t rdc;
	xpoint_t pt1, pt2;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	rdc = get_canvas_visual(canv);

	xmem_copy((void*)&pt1, (void*)ppt1, sizeof(xpoint_t));
	xmem_copy((void*)&pt2, (void*)ppt2, sizeof(xpoint_t));

	point_tm_to_pt(canv, &pt1);
	point_tm_to_pt(canv, &pt2);

	(*pif->pf_gdi_draw_line)(rdc, pxp, &pt1, &pt2);
}

void draw_bezier_raw(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_bezier)(rdc, pxp, ppt1, ppt2, ppt3, ppt4);
}

void draw_bezier(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xpoint_t* ppt3, const xpoint_t* ppt4)
{
	visual_t rdc;
	xpoint_t pt1, pt2, pt3, pt4;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	rdc = get_canvas_visual(canv);

	xmem_copy((void*)&pt1, (void*)ppt1, sizeof(xpoint_t));
	xmem_copy((void*)&pt2, (void*)ppt2, sizeof(xpoint_t));
	xmem_copy((void*)&pt3, (void*)ppt3, sizeof(xpoint_t));
	xmem_copy((void*)&pt4, (void*)ppt4, sizeof(xpoint_t));

	point_tm_to_pt(canv, &pt1);
	point_tm_to_pt(canv, &pt2);
	point_tm_to_pt(canv, &pt3);
	point_tm_to_pt(canv, &pt4);

	(*pif->pf_gdi_draw_bezier)(rdc, pxp, &pt1, &pt2, &pt3, &pt4);
}

void draw_curve_raw(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt, int n)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_curve)(rdc, pxp, ppt, n);
}

void draw_curve(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt, int n)
{
	visual_t rdc;
	xpoint_t* pa;
	int i;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	rdc = get_canvas_visual(canv);

	pa = (xpoint_t*)xmem_alloc(n * sizeof(xpoint_t));
	for (i = 0; i < n; i++)
	{
		xmem_copy((void*)&pa[i], (void*)&ppt[i], sizeof(xpoint_t));
		point_tm_to_pt(canv, &pa[i]);
	}

	(*pif->pf_gdi_draw_curve)(rdc, pxp, pa, n);

	xmem_free(pa);
}

void draw_arc_raw(visual_t rdc, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t sflag, bool_t lflag)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_arc)(rdc, pxp, ppt1, ppt2, pxs, sflag, lflag);
}

void draw_arc(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt1, const xpoint_t* ppt2, const xsize_t* pxs, bool_t sflag, bool_t lflag)
{
	visual_t rdc = get_canvas_visual(canv);
	xpoint_t pt[2];
	xsize_t xs;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	pt[0].fx = ppt1->fx;
	pt[0].fy = ppt1->fy;
	pt[1].fx = ppt2->fx;
	pt[1].fy = ppt2->fy;

	point_tm_to_pt(canv, &pt[0]);
	point_tm_to_pt(canv, &pt[1]);

	xs.fw = pxs->fw;
	xs.fh = pxs->fh;
	size_tm_to_pt(canv, &xs);

	(*pif->pf_gdi_draw_arc)(rdc, pxp, &pt[0], &pt[1], &xs, sflag, lflag);
}

void draw_polyline_raw(visual_t rdc,const xpen_t* pxp,const xpoint_t* ppt,int n)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;
	
	(*pif->pf_gdi_draw_polyline)(rdc,pxp,ppt,n);
}

void draw_polyline(canvas_t canv, const xpen_t* pxp, const xpoint_t* ppt, int n)
{
	visual_t rdc = get_canvas_visual(canv);
	xpoint_t* lpt;
	int i;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	lpt = (xpoint_t*)xmem_alloc(sizeof(xpoint_t)* n);
	for (i = 0; i < n; i++)
	{
		xmem_copy((void*)&lpt[i], (void*)&ppt[i], sizeof(xpoint_t));
		point_tm_to_pt(canv, &lpt[i]);
	}

	(*pif->pf_gdi_draw_polyline)(rdc, pxp, lpt, n);

	xmem_free(lpt);
}

void draw_polygon_raw(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xpoint_t* ppt,int n)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_polygon)(rdc,pxp,pxb,ppt,n);
}


void draw_polygon(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, int n)
{
	visual_t rdc = get_canvas_visual(canv);
	xpoint_t* lpt;
	int i;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	lpt = (xpoint_t*)xmem_alloc(sizeof(xpoint_t)* n);
	for (i = 0; i < n; i++)
	{
		xmem_copy((void*)&lpt[i], (void*)&ppt[i], sizeof(xpoint_t));
		point_tm_to_pt(canv, &lpt[i]);
	}

	(*pif->pf_gdi_draw_polygon)(rdc, pxp, pxb, lpt, n);

	xmem_free(lpt);
}

void draw_rect_raw(visual_t rdc,const xpen_t* pxp,const xbrush_t* pxb,const xrect_t* pxr)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_rect)(rdc,pxp,pxb,pxr);
}

void draw_rect(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr)
{
	visual_t rdc = get_canvas_visual(canv);
	xrect_t xr;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));
	rect_tm_to_pt(canv, &xr);

	(*pif->pf_gdi_draw_rect)(rdc, pxp, pxb, &xr);
}

void draw_round_raw(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const xsize_t* pxs)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_round)(rdc, pxp, pxb, pxr, pxs);
}

void draw_round(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const xsize_t* pxs)
{
	visual_t rdc = get_canvas_visual(canv);
	xrect_t xr;
	xsize_t xs;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));
	rect_tm_to_pt(canv, &xr);

	if (pxs)
	{
		xmem_copy((void*)&xs, (void*)pxs, sizeof(xsize_t));
		size_tm_to_pt(canv, &xs);
	}

	(*pif->pf_gdi_draw_round)(rdc, pxp, pxb, &xr, ((pxs)? &xs : NULL));
}

void draw_ellipse_raw(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_ellipse)(rdc, pxp, pxb, pxr);
}

void draw_ellipse(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr)
{
	visual_t rdc = get_canvas_visual(canv);
	xrect_t xr;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));
	rect_tm_to_pt(canv, &xr);

	if (xr.w < xr.h)
		xr.w = xr.h;
	else if (xr.w > xr.h)
		xr.h = xr.w;

	(*pif->pf_gdi_draw_ellipse)(rdc, pxp, pxb, &xr);
}

void draw_pie_raw(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt, double fang, double tang)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_pie)(rdc, pxp, pxb, prt, fang, tang);
}

void draw_pie(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* prt, double fang, double tang)
{
	visual_t rdc = get_canvas_visual(canv);
	xrect_t xr;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	xmem_copy((void*)&xr, (void*)prt, sizeof(xrect_t));
	rect_tm_to_pt(canv, &xr);

	(*pif->pf_gdi_draw_pie)(rdc, pxp, pxb, &xr, fang, tang);
}

void draw_path_raw(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int n)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_path)(rdc, pxp, pxb, aa, pa);
}

void draw_path(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const tchar_t* aa, const xpoint_t* pa, int n)
{
	visual_t rdc = get_canvas_visual(canv);
	xpoint_t* ppt;
	int i, j;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	if (is_null(aa))
		return;

	ppt = (xpoint_t*)xmem_alloc(n * sizeof(xpoint_t));
	xmem_copy((void*)ppt, (void*)pa, n * sizeof(xpoint_t));

	i = j = 0;
	while (*(aa + j))
	{
		if (*(aa + j) == _T('M') || *(aa + j) == _T('m'))
		{
			point_tm_to_pt(canv, &ppt[i]);
			i += 1;
		}
		else if (*(aa + j) == _T('L') || *(aa + j) == _T('l'))
		{
			point_tm_to_pt(canv, &ppt[i]);
			i += 1;
		}
		else if (*(aa + j) == _T('Q') || *(aa + j) == _T('q'))
		{
			point_tm_to_pt(canv, &ppt[i]);
			point_tm_to_pt(canv, &ppt[i + 1]);
			i += 2;
		}
		else if (*(aa + j) == _T('T') || *(aa + j) == _T('t'))
		{
			point_tm_to_pt(canv, &ppt[i]);
			i += 1;
		}
		else if (*(aa + j) == _T('C') || *(aa + j) == _T('c'))
		{
			point_tm_to_pt(canv, &ppt[i]);
			point_tm_to_pt(canv, &ppt[i + 1]);
			point_tm_to_pt(canv, &ppt[i + 2]);
			i += 3;
		}
		else if (*(aa + j) == _T('S') || *(aa + j) == _T('s'))
		{
			point_tm_to_pt(canv, &ppt[i]);
			point_tm_to_pt(canv, &ppt[i + 1]);
			i += 2;
		}
		else if (*(aa + j) == _T('A') || *(aa + j) == _T('a'))
		{
			size_tm_to_pt(canv, (xsize_t*)(&ppt[i]));
			size_tm_to_pt(canv, (xsize_t*)(&ppt[i + 1]));
			point_tm_to_pt(canv, &ppt[i + 2]);
			i += 3;
		}
		else if (*(aa + j) == _T('Z') || *(aa + j) == _T('z'))
		{
			break;
		}

		j++;
	}

	(*pif->pf_gdi_draw_path)(rdc, pxp, pxb, aa, ppt);

	xmem_free(ppt);
}

void draw_text_raw(visual_t rdc,const xfont_t* pxf,const xface_t* pxa,const xrect_t* pxr,const tchar_t* txt,int len)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_text)(rdc,pxf,pxa,pxr,txt,len);
}

void draw_text(canvas_t canv, const xfont_t* pxf, const xface_t* pxa, const xrect_t* pxr, const tchar_t* txt, int len)
{
	visual_t rdc = get_canvas_visual(canv);
	xrect_t xr;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));
	rect_tm_to_pt(canv, &xr);

	(*pif->pf_gdi_draw_text)(rdc, pxf, pxa, &xr, txt, len);
}

void text_out_raw(visual_t rdc, const xfont_t* pxf, const xpoint_t* ppt, const tchar_t* txt, int len)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_text_out)(rdc, pxf, ppt, txt, len);
}

void text_out(canvas_t canv, const xfont_t* pxf, const xpoint_t* ppt, const tchar_t* txt, int len)
{
	visual_t rdc = get_canvas_visual(canv);
	xpoint_t pt;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	xmem_copy((void*)&pt, (void*)ppt, sizeof(xpoint_t));
	point_tm_to_pt(canv, &pt);

	(*pif->pf_gdi_text_out)(rdc, pxf, &pt, txt, len);
}

void text_rect_raw(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* pxr)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_text_rect)(rdc, pxf, pxa, txt, len, pxr);
}


void text_rect(canvas_t canv, const xfont_t* pxf, const xface_t* pxa, const tchar_t* txt, int len, xrect_t* pxr)
{
	visual_t rdc = get_canvas_visual(canv);

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_text_rect)(rdc, pxf, pxa, txt, len, pxr);

	rect_pt_to_tm(canv, pxr);
}

void text_size_raw(visual_t rdc, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_text_size)(rdc, pxf, txt, len, pxs);
}

void text_size(canvas_t canv, const xfont_t* pxf, const tchar_t* txt, int len, xsize_t* pxs)
{
	visual_t rdc = get_canvas_visual(canv);

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_text_size)(rdc, pxf, txt, len, pxs);

	size_pt_to_tm(canv, pxs);
}

void text_metric_raw(visual_t rdc, const xfont_t* pxf, xsize_t* pxs)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_text_metric)(rdc, pxf, pxs);
}

void text_metric(canvas_t canv, const xfont_t* pxf, xsize_t* pxs)
{
	visual_t rdc = get_canvas_visual(canv);

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_text_metric)(rdc, pxf, pxs);

	size_pt_to_tm(canv, pxs);
}

float pixel_metric(canvas_t canv, bool_t horz)
{
	visual_t rdc = get_canvas_visual(canv);

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	return (*pif->pf_pt_per_mm)(rdc, horz);
}

float pixel_metric_raw(visual_t view, bool_t horz)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	return (*pif->pf_pt_per_mm)(view, horz);
}

void draw_bitmap_raw(visual_t rdc, bitmap_t bmp, const xpoint_t* ppt)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_draw_bitmap)(rdc, bmp, ppt);
}

void draw_bitmap(canvas_t canv, bitmap_t bmp, const xpoint_t* ppt)
{
	visual_t rdc = get_canvas_visual(canv);
	xpoint_t pt;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	xmem_copy((void*)&pt, (void*)ppt, sizeof(xpoint_t));
	point_tm_to_pt(canv, &pt);

	(*pif->pf_gdi_draw_bitmap)(rdc, bmp, &pt);
}

void draw_icon_raw(visual_t rdc, const tchar_t* iname, const xrect_t* prt)
{
	if_context_t *pif;
	bitmap_t bmp;

	pif = PROCESS_CONTEXT_INTERFACE;

	bmp = load_bitmap_from_icon(rdc, iname);

	if (bmp)
	{
		(*pif->pf_gdi_draw_image)(rdc, bmp, NULL, prt);
		destroy_bitmap(bmp);
	}
}

void draw_icon(canvas_t canv, const tchar_t* iname, const xrect_t* prt)
{
	visual_t rdc = get_canvas_visual(canv);
	xrect_t xr;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	xmem_copy((void*)&xr, (void*)prt, sizeof(xrect_t));
	rect_tm_to_pt(canv, &xr);

	draw_icon_raw(rdc, iname, &xr);
}

void draw_thumb_raw(visual_t rdc, const tchar_t* fname, const xrect_t* prt)
{
	if_context_t *pif;
	bitmap_t bmp;

	pif = PROCESS_CONTEXT_INTERFACE;

	bmp = load_bitmap_from_thumb(rdc, fname);

	if (bmp)
	{
		(*pif->pf_gdi_draw_image)(rdc, bmp, NULL, prt);
		destroy_bitmap(bmp);
	}
}

void draw_thumb(canvas_t canv, const tchar_t* fname, const xrect_t* prt)
{
	visual_t rdc = get_canvas_visual(canv);
	xrect_t xr;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	xmem_copy((void*)&xr, (void*)prt, sizeof(xrect_t));
	rect_tm_to_pt(canv, &xr);

	draw_thumb_raw(rdc, fname, &xr);
}

void draw_image_raw(visual_t rdc, const ximage_t* pxi, const xrect_t* pxr)
{
	if_context_t *pif;
	bitmap_t bmp;
	xcolor_t xc;

	pif = PROCESS_CONTEXT_INTERFACE;

	parse_xcolor(&xc, pxi->color);

	if (compare_text(pxi->type, -1, GDI_ATTR_IMAGE_TYPE_URL, -1, 1) == 0)
	{
		bmp = load_bitmap_from_file(rdc, pxi->source);
		if (bmp)
		{
			(*pif->pf_gdi_draw_image)(rdc, bmp, &xc, pxr);
			destroy_bitmap(bmp);
		}
	}
	else
	{
		bmp = load_bitmap_from_ximage(rdc, (ximage_t*)pxi, pxr->w, pxr->h);
		if (bmp)
		{
			(*pif->pf_gdi_draw_image)(rdc, bmp, &xc, pxr);
			destroy_bitmap(bmp);
		}
	}
}

void draw_image(canvas_t canv, const ximage_t* pxi, const xrect_t* pxr)
{
	visual_t rdc = get_canvas_visual(canv);
	xrect_t xr;

	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));
	rect_tm_to_pt(canv, &xr);

	draw_image_raw(rdc, pxi, &xr);
}


void gradient_rect_raw(visual_t rdc, const xcolor_t* xc_brim, const xcolor_t* xc_core, const tchar_t* gradient, const xrect_t* pxr)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_gradient_rect)(rdc, xc_brim, xc_core, gradient, pxr);
}

void alphablend_rect_raw(visual_t rdc, const xcolor_t* pxc, const xrect_t* pxr, int opacity)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_alphablend_rect)(rdc, pxc, pxr, opacity);
}

void exclude_rect_raw(visual_t rdc, const xrect_t* pxr)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_exclude_rect)(rdc, pxr);
}

void fill_region_raw(visual_t rdc, const xbrush_t* pxb, res_rgn_t rgn)
{
	if_context_t *pif;

	pif = PROCESS_CONTEXT_INTERFACE;

	(*pif->pf_gdi_fill_region)(rdc, pxb, rgn);
}

/******************************************************************************************************************/

void image_size_raw(visual_t rdc, const ximage_t* pxi, xsize_t* pxs)
{
	bitmap_t bmp;

	bmp = load_bitmap_from_ximage(rdc, (ximage_t*)pxi, 0, 0);
	if (bmp)
	{
		get_bitmap_size(bmp, &pxs->w, &pxs->h);
		destroy_bitmap(bmp);
	}
}

void image_size(canvas_t canv, const ximage_t* pxi, xsize_t* pxs)
{
	visual_t rdc = get_canvas_visual(canv);

	image_size_raw(rdc, pxi, pxs);

	size_pt_to_tm(canv, pxs);
}

void draw_triangle_raw(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const tchar_t* orient)
{
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

	draw_polygon_raw(rdc, pxp, pxb, pt, 3);
}

void draw_triangle(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xrect_t* pxr, const tchar_t* orient)
{
	visual_t rdc = get_canvas_visual(canv);
	xrect_t rt;

	xmem_copy((void*)&rt, (void*)pxr, sizeof(xrect_t));
	rect_tm_to_pt(canv, &rt);

	draw_triangle_raw(rdc, pxp, pxb, &rt, orient);
}

void draw_sector_raw(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* prl, const xspan_t* prs, double arcf, double arct)
{
	xpoint_t pt[4] = { 0 };
	tchar_t ta[5] = { 0 };
	xpoint_t pa[8] = { 0 };
	int lflag;

	pt_calc_sector(ppt, prl->s, prs->s, arcf, arct, pt, 4);
	lflag = (arcf - arct > XPI || arct - arcf > XPI) ? 1 : 0;

	ta[0] = _T('M');
	pa[0].x = pt[0].x, pa[0].y = pt[0].y;

	ta[1] = _T('A');
	pa[1].x = 0, pa[1].y = lflag; //anti clockwise
	pa[2].x = prl->s, pa[2].y = prl->s;
	pa[3].x = pt[1].x, pa[3].y = pt[1].y;

	ta[2] = _T('L');
	pa[4].x = pt[2].x, pa[4].y = pt[2].y;

	ta[3] = _T('A');
	pa[5].x = 1, pa[5].y = 0; //clockwise and small arc
	pa[6].x = prs->s, pa[6].y = prs->s;
	pa[7].x = pt[3].x, pa[7].y = pt[3].y;

	ta[4] = _T('Z');

	draw_path_raw(rdc, pxp, pxb, ta, pa, 8);
}

void draw_sector(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* prl, const xspan_t* prs, double arcf, double arct)
{
	visual_t rdc = get_canvas_visual(canv);
	xpoint_t pt;
	xspan_t rl, rs;

	pt.fx = ppt->fx;
	pt.fy = ppt->fy;
	point_tm_to_pt(canv, &pt);

	rl.s = tm_to_pt(canv, prl->fs, 0);
	rs.s = tm_to_pt(canv, prs->fs, 0);

	draw_sector_raw(rdc, pxp, pxb, &pt, &rl, &rs, arcf, arct);
}

void multi_line_raw(visual_t rdc, const xfont_t* pxf, const xface_t* pxa, const xpen_t* pxp, const xrect_t* pxr)
{
	float line_rati;
	int lh, th;
	int i, rows;
	xpoint_t pt1, pt2;
	xsize_t xs;

	if (is_null(pxa->line_height))
		line_rati = xstof(DEF_GDI_TEXT_LINE_HEIGHT);
	else
		line_rati = xstof(pxa->line_height);

	if (line_rati < 1)
		line_rati = 1.0;

	text_metric_raw(rdc, pxf, &xs);

	th = xs.h;
	lh = (int)((float)th * (line_rati - 1.0));

	rows = pxr->h / (th + lh);

	pt1.x = pxr->x;
	pt1.y = pxr->y + th + lh;
	pt2.x = pxr->x + pxr->w;
	pt2.y = pxr->y + th + lh;

	for (i = 0; i < rows; i++)
	{
		draw_line_raw(rdc, pxp, &pt1, &pt2);

		pt1.y += (th + lh);
		pt2.y += (th + lh);
	}
}

void multi_line(canvas_t canv, const xfont_t* pxf, const xface_t* pxa, const xpen_t* pxp, const xrect_t* pxr)
{
	visual_t rdc = get_canvas_visual(canv);
	xrect_t xr;

	xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));
	rect_tm_to_pt(canv, &xr);

	multi_line_raw(rdc, pxf, pxa, pxp, &xr);
}

void draw_equilagon_raw(visual_t rdc, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* pxn, int n)
{
	xpoint_t* pa;

	if (n < 3) return;

	pa = (xpoint_t*)xmem_alloc(sizeof(xpoint_t)* n);

	pt_calc_equilater(ppt, pxn->s, pa, n);

	draw_polygon_raw(rdc, pxp, pxb, pa, n);

	xmem_free(pa);
}

void draw_equilagon(canvas_t canv, const xpen_t* pxp, const xbrush_t* pxb, const xpoint_t* ppt, const xspan_t* pxn, int n)
{
	xpoint_t* pa;

	if (n < 3) return;

	pa = (xpoint_t*)xmem_alloc(sizeof(xpoint_t)* n);

	ft_calc_equilater(ppt, pxn->fs, pa, n);

	draw_polygon(canv, pxp, pxb, pa, n);

	xmem_free(pa);
}

void color_out_raw(visual_t rdc, const xrect_t* pxr, bool_t horz, const tchar_t* rgbstr, int len)
{
	xrect_t xr;
	xcolor_t xc;
	xbrush_t xb;
	tchar_t* val;
	int vlen;
	tchar_t clr[CLR_LEN + 1];
	int n, total = 0;

	if (len < 0)
		len = xslen(rgbstr);

	default_xbrush(&xb);
	xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));

	while (n = parse_string_token((rgbstr + total), (len - total), _T(';'), &val, &vlen))
	{
		total += n;

		xsncpy(clr, val, vlen);
		parse_xcolor(&xc, clr);
		format_xcolor(&xc, xb.color);

		draw_rect_raw(rdc, NULL, &xb, &xr);

		if (horz)
			xr.x += xr.w;
		else
			xr.y += xr.h;
	}
}

void color_out(canvas_t canv, const xrect_t* pxr, bool_t horz, const tchar_t* rgbstr, int len)
{
	visual_t rdc = get_canvas_visual(canv);
	xrect_t xr;

	xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));
	rect_tm_to_pt(canv, &xr);

	color_out_raw(rdc, &xr, horz, rgbstr, len);
}

#endif /*XDU_SUPPORT_CONTEXT*/
