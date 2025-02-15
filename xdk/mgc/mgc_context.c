/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc mgc gdi document

	@module	mgcgdi.c | implement file

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

#include "mgc.h"

#include "mdrv.h"
#include "mdev.h"
#include "mpap.h"
#include "mfnt.h"
#include "mclr.h"

#include "../g2/g2.h"
#include "../dot/dot.h"

#include "../xdkimg.h"
#include "../xdkimp.h"
#include "../xdkstd.h"
#include "../xdkutil.h"
#include "../xdkinit.h"

typedef struct _memo_context_t
{
	handle_head head;

	mem_device_ptr device;
	device_t handle;

	bitmap_file_head_t bitmap_head;
	int rop; /*raster operation mode*/
} memo_context_t;

static const mem_device_ptr select_device(const tchar_t *devName)
{
	if (xsicmp(devName, MGC_DEVICE_BITMAP_MONOCHROME) == 0)
		return &monochrome_bitmap_device;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_GRAYSCALE) == 0)
		return &grayscale_bitmap_device;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_TRUECOLOR16) == 0)
		return &truecolor16_bitmap_device;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_TRUECOLOR24) == 0)
		return &truecolor24_bitmap_device;
	else if (xsicmp(devName, MGC_DEVICE_BITMAP_TRUECOLOR32) == 0)
		return &truecolor32_bitmap_device;
	else
	{
		set_last_error(_T("select_device"), _T("unknown memory device"), -1);
		return NULL;
	}
}

static const mem_font_ptr select_font(const tchar_t *fntName)
{
	if (xsicmp(fntName, MGC_FONT_FIXED) == 0)
		return &font_Fixed;
	else
	{
		set_last_error(_T("select_font"), _T("unknown memory font"), -1);
		return NULL;
	}
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

visual_t create_mgc_visual(const tchar_t *devName, const tchar_t *formName, int width, int height, int dpi)
{
	memo_context_t *pmgc;
	dev_prn_t prn = {0};
	dword_t total, pixels;
	float mmperpt;

	TRY_CATCH;

	pmgc = (memo_context_t *)xmem_alloc(sizeof(memo_context_t));
	pmgc->head.tag = _VISUAL_MEMORY;

	pmgc->device = select_device(devName);
	if (!pmgc->device)
	{
		raise_user_error(_T("create_mgc_visual"), _T("select_device"));
	}

	if (!select_paper(formName, &prn))
	{
		mmperpt = MMPERINCH / (float)dpi;
		prn.paper_width = (int)((float)width * mmperpt * 10.0);
		prn.paper_height = (int)((float)height * mmperpt * 10.0);
	}

	xscpy(prn.devname, devName);

	pmgc->handle = (*(pmgc->device->openDevice))(&prn, dpi);
	if (!pmgc->handle)
	{
		raise_user_error(_T("create_mgc_visual"), _T("openDevice"));
	}

	(*(pmgc->device->getBitmapSize))(pmgc->handle, &total, &pixels);

	pmgc->bitmap_head.flag = BMP_FLAG;
	pmgc->bitmap_head.fsize = BMP_FILEHEADER_SIZE + total;
	pmgc->bitmap_head.offset = BMP_FILEHEADER_SIZE + (total - pixels);

	END_CATCH;

	return &(pmgc->head);

ONERROR:
	XDK_TRACE_LAST;

	if (pmgc)
	{
		xmem_free(pmgc);
	}

	return NULL;
}

void destroy_mgc_visual(visual_t mgc)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	if (pmgc->device)
	{
		(*(pmgc->device->closeDevice))(pmgc->handle);
	}

	xmem_free(pmgc);
}

int mgc_get_rop(visual_t mgc)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	return pgc->rop;
}

void mgc_set_rop(visual_t mgc, int rop)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	pgc->rop = rop;
}

void mgc_get_point(visual_t mgc, xcolor_t *pxc, const xpoint_t *ppt)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	(*(pgc->device->getPoint))(pgc->handle, ppt, pxc);
}

void mgc_set_point(visual_t mgc, const xcolor_t *pxc, const xpoint_t *ppt)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	(*(pgc->device->setPoint))(pgc->handle, ppt, pxc, pgc->rop);
}

dword_t mgc_save_bytes(visual_t mgc, byte_t *buf, dword_t max)
{
	memo_context_t *pgc = (memo_context_t *)mgc;
	dword_t total = 0;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);

	total += xbmp_set_head(&pgc->bitmap_head, ((buf) ? (buf + total) : NULL), (max - total));
	total += (*(pgc->device->getBitmap))(pgc->handle, ((buf) ? (buf + total) : NULL), (max - total));

	return total;
}

int mgc_pt_per_mm_raw(visual_t mgc, bool_t horz)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	dev_cap_t cap;
	double ptpermm;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_SCRIPT);

	(*pmgc->device->getDeviceCaps)(pmgc->handle, &cap);

	if (horz)
		ptpermm = (float)cap.horz_res / (float)cap.horz_size;
	else
		ptpermm = (float)cap.vert_res / (float)cap.vert_size;

	return (int)(ptpermm);
}

int mgc_pt_per_mm(canvas_t canv, bool_t horz)
{
	visual_t view;

	view = mgc_get_canvas_visual(canv);

	return mgc_pt_per_mm_raw(view, horz);
}

int mgc_pt_per_in_raw(visual_t mgc, bool_t horz)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	dev_cap_t cap;
	double ptpermm;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_SCRIPT);

	(*pmgc->device->getDeviceCaps)(pmgc->handle, &cap);

	if (horz)
		ptpermm = (float)cap.horz_res / (float)cap.horz_size;
	else
		ptpermm = (float)cap.vert_res / (float)cap.vert_size;

	return (int)(ptpermm * MMPERINCH);
}

int mgc_pt_per_in(canvas_t canv, bool_t horz)
{
	visual_t view;

	view = mgc_get_canvas_visual(canv);

	return mgc_pt_per_in_raw(view, horz);
}

float mgc_pt_to_tm_raw(visual_t mgc, int pt, bool_t horz)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	dev_cap_t cap;
	double mmperpt;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_SCRIPT);

	(*pmgc->device->getDeviceCaps)(pmgc->handle, &cap);

	if (horz)
		mmperpt = (float)cap.horz_size / (float)cap.horz_res;
	else
		mmperpt = (float)cap.vert_size / (float)cap.vert_res;

	return (float)((float)pt * mmperpt);
}

float mgc_pt_to_tm(canvas_t canv, int pt, bool_t horz)
{
	visual_t view;

	view = mgc_get_canvas_visual(canv);

	return mgc_pt_to_tm_raw(view, pt, horz);
}

int mgc_tm_to_pt_raw(visual_t mgc, float tm, bool_t horz)
{
	memo_context_t *pmgc = TypePtrFromHead(memo_context_t, mgc);

	dev_cap_t cap;
	double ptpermm;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_SCRIPT);

	(*pmgc->device->getDeviceCaps)(pmgc->handle, &cap);

	if (horz)
		ptpermm = (float)cap.horz_res / (float)cap.horz_size;
	else
		ptpermm = (float)cap.vert_res / (float)cap.vert_size;

	return (int)((float)tm * ptpermm);
}

int mgc_tm_to_pt(canvas_t canv, float tm, bool_t horz)
{
	visual_t view;

	view = mgc_get_canvas_visual(canv);

	return mgc_tm_to_pt_raw(view, tm, horz);
}

void mgc_draw_line_raw(visual_t mgc, const xpen_t *pxp, const xpoint_t *ppt1, const xpoint_t *ppt2)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(ppt1 != NULL && ppt2 != NULL && pxp != NULL);

	xcolor_t xc;
	int n, fs, ds;
	xpoint_t *ppt;
	xpoint_t pt;

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc, pxp->color);

	pt.x = ppt2->x;
	pt.y = ppt2->y;
	pt_screen_to_world(*ppt1, &pt, 1);

	n = dot_line(fs, ds, pt.x, pt.y, NULL, MAX_LONG);
	ppt = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
	n = dot_line(fs, ds, pt.x, pt.y, ppt, n);

	pt_world_to_screen(*ppt1, ppt, n);

	(*(pgc->device->drawPoints))(pgc->handle, ppt, n, &xc, 1, pgc->rop);
	xmem_free(ppt);
}

void mgc_draw_line(canvas_t canv, const xpen_t *pxp, const xpoint_t *ppt1, const xpoint_t *ppt2)
{
	visual_t view;
	xpoint_t pt[2];

	view = mgc_get_canvas_visual(canv);

	pt[0].fx = ppt1->fx;
	pt[0].fy = ppt1->fy;
	pt[1].fx = ppt2->fx;
	pt[1].fy = ppt2->fy;

	mgc_point_tm_to_pt(canv, &pt[0]);
	mgc_point_tm_to_pt(canv, &pt[1]);

	mgc_draw_line_raw(view, pxp, &pt[0], &pt[1]);
}

void mgc_draw_polyline_raw(visual_t mgc, const xpen_t *pxp, const xpoint_t *ppt, int pn)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(ppt != NULL && pxp != NULL);

	xcolor_t xc;
	int fs, ds;
	xpoint_t *ppt_buff = NULL;
	xpoint_t pt;
	int i, n, total = 0; 

	if (pn < 1) return;

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc, pxp->color);

	for (i = 1; i < pn; i++)
	{
		pt.x = ppt[i].x;
		pt.y = ppt[i].y;
		pt_screen_to_world(ppt[i - 1], &pt, 1);

		n = dot_line(fs, ds, pt.x, pt.y, NULL, MAX_LONG);
		ppt_buff = (xpoint_t *)xmem_realloc(ppt_buff, (total + n) * sizeof(xpoint_t));
		n = dot_line(fs, ds, pt.x, pt.y, ppt_buff + total, n);

		pt_world_to_screen(ppt[i - 1], ppt_buff + total, n);
		total += n;
	}

	(*(pgc->device->drawPoints))(pgc->handle, ppt_buff, total, &xc, 1, pgc->rop);
	xmem_free(ppt_buff);
}

void mgc_draw_polyline(canvas_t canv, const xpen_t *pxp, const xpoint_t *ppt, int n)
{
	visual_t view;
	xpoint_t *pa;
	int i;

	view = mgc_get_canvas_visual(canv);

	pa = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
	for (i = 0; i < n; i++)
	{
		pa[i].fx = ppt[i].fx;
		pa[i].fy = ppt[i].fy;
		mgc_point_tm_to_pt(canv, &pa[i]);
	}

	mgc_draw_polyline_raw(view, pxp, pa, n);

	xmem_free(pa);
}

void mgc_draw_bezier_raw(visual_t mgc, const xpen_t *pxp, const xpoint_t *ppt1, const xpoint_t *ppt2, const xpoint_t *ppt3, const xpoint_t *ppt4)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxp != NULL && ppt1 != NULL && ppt2 != NULL && ppt3 != NULL && ppt3 != NULL);

	xcolor_t xc;
	int n, fs, ds;
	xpoint_t *ppt;
	xpoint_t pt[3];

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc, pxp->color);

	pt[0].x = ppt2->x, pt[0].y = ppt2->y;
	pt[1].x = ppt3->x, pt[1].y = ppt3->y;
	pt[2].x = ppt4->x, pt[2].y = ppt4->y;
	pt_screen_to_world(*ppt1, pt, 3);

	n = dot_curve3(fs, ds, &pt[0], &pt[1], &pt[2], NULL, MAX_LONG);
	ppt = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
	n = dot_curve3(fs, ds, &pt[0], &pt[1], &pt[2], ppt, n);

	pt_world_to_screen(*ppt1, ppt, n);

	(*(pgc->device->drawPoints))(pgc->handle, ppt, n, &xc, 1, pgc->rop);
	xmem_free(ppt);
}

void mgc_draw_bezier(canvas_t canv, const xpen_t *pxp, const xpoint_t *ppt1, const xpoint_t *ppt2, const xpoint_t *ppt3, const xpoint_t *ppt4)
{
	visual_t view;
	xpoint_t pt[4];

	view = mgc_get_canvas_visual(canv);

	pt[0].fx = ppt1->fx;
	pt[0].fy = ppt1->fy;
	pt[1].fx = ppt2->fx;
	pt[1].fy = ppt2->fy;
	pt[2].fx = ppt3->fx;
	pt[2].fy = ppt3->fy;
	pt[3].fx = ppt4->fx;
	pt[3].fy = ppt4->fy;

	mgc_point_tm_to_pt(canv, &pt[0]);
	mgc_point_tm_to_pt(canv, &pt[1]);
	mgc_point_tm_to_pt(canv, &pt[2]);
	mgc_point_tm_to_pt(canv, &pt[3]);

	mgc_draw_bezier_raw(view, pxp, &pt[0], &pt[1], &pt[2], &pt[3]);
}

void mgc_draw_curve_raw(visual_t mgc, const xpen_t *pxp, const xpoint_t *ppt_ctl, int ppt_count)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxp != NULL && ppt_ctl != NULL);

	xcolor_t xc;
	int n, fs, ds;
	xpoint_t *ppt;
	xpoint_t pt[3];

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc, pxp->color);

	if (ppt_count == 3)
	{
		pt[0].x = ppt_ctl[1].x, pt[0].y = ppt_ctl[1].y;
		pt[1].x = ppt_ctl[2].x, pt[1].y = ppt_ctl[2].y;
		pt_screen_to_world(ppt_ctl[0], pt, 2);

		n = dot_curve2(fs, ds, &pt[0], &pt[1], NULL, MAX_LONG);
		ppt = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
		n = dot_curve2(fs, ds, &pt[0], &pt[1], ppt, n);

		pt_world_to_screen(ppt_ctl[0], ppt, n);

		(*(pgc->device->drawPoints))(pgc->handle, ppt, n, &xc, 1, pgc->rop);
		xmem_free(ppt);
	}
	else if (ppt_count == 4)
	{
		pt[0].x = ppt_ctl[1].x, pt[0].y = ppt_ctl[1].y;
		pt[1].x = ppt_ctl[2].x, pt[1].y = ppt_ctl[2].y;
		pt[2].x = ppt_ctl[3].x, pt[2].y = ppt_ctl[3].y;
		pt_screen_to_world(ppt_ctl[0], pt, 3);

		n = dot_curve3(fs, ds, &pt[0], &pt[1], &pt[2], NULL, MAX_LONG);
		ppt = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
		n = dot_curve3(fs, ds, &pt[0], &pt[1], &pt[2], ppt, n);

		pt_world_to_screen(ppt_ctl[0], ppt, n);

		(*(pgc->device->drawPoints))(pgc->handle, ppt, n, &xc, 1, pgc->rop);
		xmem_free(ppt);
	}
}

void mgc_draw_curve(canvas_t canv, const xpen_t *pxp, const xpoint_t *ppt, int n)
{
	visual_t view;
	xpoint_t *pa;
	int i;

	view = mgc_get_canvas_visual(canv);

	pa = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));

	for (i = 0; i < n; i++)
	{
		xmem_copy((void *)&pa[i], (void *)&ppt[i], sizeof(xpoint_t));
		mgc_point_tm_to_pt(canv, &pa[i]);
	}

	mgc_draw_curve_raw(view, pxp, pa, n);

	xmem_free(pa);
}

void mgc_draw_arc_raw(visual_t mgc, const xpen_t *pxp, const xpoint_t *ppt1, const xpoint_t *ppt2, const xsize_t *pxs, bool_t clockwise, bool_t largearc)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxp != NULL && pxs != NULL && ppt1 != NULL && ppt2 != NULL);

	xcolor_t xc;
	int n, fs, ds;
	xpoint_t *ppt;
	xpoint_t pt;
	double a1, a2;

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc, pxp->color);

	clockwise = pt_calc_radian(clockwise, largearc, pxs->w, pxs->h, ppt1, ppt2, &pt, &a1, &a2);

	n = dot_arc(fs, ds, pxs->w, pxs->h, a1, a2, clockwise, NULL, MAX_LONG);
	ppt = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
	n = dot_arc(fs, ds, pxs->w, pxs->h, a1, a2, clockwise, ppt, n);

	pt_world_to_screen(pt, ppt, n);

	(*(pgc->device->drawPoints))(pgc->handle, ppt, n, &xc, 1, pgc->rop);
	xmem_free(ppt);
}

void mgc_draw_arc(canvas_t canv, const xpen_t *pxp, const xpoint_t *ppt1, const xpoint_t *ppt2, const xsize_t *pxs, bool_t sflag, bool_t lflag)
{
	visual_t view;
	xpoint_t pt1, pt2;
	xsize_t xs;

	view = mgc_get_canvas_visual(canv);

	pt1.fx = ppt1->fx;
	pt1.fy = ppt1->fy;
	mgc_point_tm_to_pt(canv, &pt1);

	pt2.fx = ppt2->fx;
	pt2.fy = ppt2->fy;
	mgc_point_tm_to_pt(canv, &pt2);

	xs.fw = pxs->fw;
	xs.fh = pxs->fh;
	mgc_size_tm_to_pt(canv, &xs);

	mgc_draw_arc_raw(view, pxp, &pt1, &pt2, &xs, sflag, lflag);
}

void mgc_draw_triangle_raw(visual_t mgc, const xpen_t *pxp, const xbrush_t *pxb, const xrect_t *pxr, const tchar_t *orient)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxp != NULL && pxr != NULL && pxp != NULL);

	xcolor_t xc[2];
	int fs, ds;
	int n, total = 0;
	xpoint_t *ppt_buff = NULL;
	xpoint_t pt[3] = { 0 };
	xpoint_t pk;

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc[0], pxp->color);

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

	pk.x = pt[1].x;
	pk.y = pt[1].y;
	pt_screen_to_world(pt[0], &pk, 1);

	n = dot_line(fs, ds, pk.x, pk.y, NULL, MAX_LONG);
	ppt_buff = (xpoint_t *)xmem_realloc(ppt_buff, (total + n) * sizeof(xpoint_t));
	n = dot_line(fs, ds, pk.x, pk.y, ppt_buff + total, n);

	pt_world_to_screen(pt[0], ppt_buff + total, n);
	total += n;

	pk.x = pt[2].x;
	pk.y = pt[2].y;
	pt_screen_to_world(pt[1], &pk, 1);

	n = dot_line(fs, ds, pk.x, pk.y, NULL, MAX_LONG);
	ppt_buff = (xpoint_t *)xmem_realloc(ppt_buff, (total + n) * sizeof(xpoint_t));
	n = dot_line(fs, ds, pk.x, pk.y, ppt_buff + total, n);

	pt_world_to_screen(pt[1], ppt_buff + total, n);
	total += n;

	pk.x = pt[0].x;
	pk.y = pt[0].y;
	pt_screen_to_world(pt[2], &pk, 1);

	n = dot_line(fs, ds, pk.x, pk.y, NULL, MAX_LONG);
	ppt_buff = (xpoint_t *)xmem_realloc(ppt_buff, (total + n) * sizeof(xpoint_t));
	n = dot_line(fs, ds, pk.x, pk.y, ppt_buff + total, n);

	pt_world_to_screen(pt[2], ppt_buff + total, n);
	total += n;

	(*(pgc->device->drawPoints))(pgc->handle, ppt_buff, total, xc, 1, pgc->rop);
	xmem_free(ppt_buff);

	if (!is_null_xbrush(pxb))
	{
		parse_xcolor(&xc[0], pxb->color);
		parse_xcolor(&xc[1], pxb->linear);

		pk.x = pxr->x + pxr->w / 2;
		pk.y = pxr->y + pxr->h / 2;

		if (compare_text(pxb->style, -1, GDI_ATTR_FILL_STYLE_GRADIENT, -1, 1) == 0)
		{
			(*(pgc->device->radialLinear))(pgc->handle, pxr, &pk, xc, pgc->rop);
		}
		else
		{
			(*(pgc->device->floodFill))(pgc->handle, pxr, &pk, xc, pgc->rop);
		}
	}
}

void mgc_draw_triangle(canvas_t canv, const xpen_t *pxp, const xbrush_t *pxb, const xrect_t *pxr, const tchar_t *orient)
{
	visual_t view;
	xrect_t xr;

	view = mgc_get_canvas_visual(canv);

	xr.fx = pxr->fx;
	xr.fy = pxr->fy;
	xr.fw = pxr->fw;
	xr.fh = pxr->fh;

	mgc_rect_tm_to_pt(canv, &xr);

	mgc_draw_triangle_raw(view, pxp, pxb, &xr, orient);
}

void mgc_draw_rect_raw(visual_t mgc, const xpen_t *pxp, const xbrush_t *pxb, const xrect_t *pxr)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxr != NULL && pxp != NULL);

	int n, fs, ds;
	xpoint_t *ppt;
	xpoint_t pt;
	xcolor_t xc[2] = { 0 };

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc[0], pxp->color);

	n = dot_rect(fs, ds, pxr->w, pxr->h, NULL, MAX_LONG);
	ppt = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
	n = dot_rect(fs, ds, pxr->w, pxr->h, ppt, n);

	pt.x = pxr->x + pxr->w / 2;
	pt.y = pxr->y + pxr->h / 2;
	pt_world_to_screen(pt, ppt, n);

	(*(pgc->device->drawPoints))(pgc->handle, ppt, n, xc, 1, pgc->rop);
	xmem_free(ppt);

	if (!is_null_xbrush(pxb))
	{
		parse_xcolor(&xc[0], pxb->color);
		parse_xcolor(&xc[1], pxb->linear);
		pt.x = pxr->x + pxr->w / 2;
		pt.y = pxr->y + pxr->h / 2;

		if (compare_text(pxb->style, -1, GDI_ATTR_FILL_STYLE_GRADIENT, -1, 1) == 0)
		{
			if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_HORZ, -1, 1) == 0)
				(*(pgc->device->horzLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
			else if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_VERT, -1, 1) == 0)
				(*(pgc->device->vertLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
			else if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_RADIAL, -1, 1) == 0)
				(*(pgc->device->radialLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
		}
		else
		{
			(*(pgc->device->floodFill))(pgc->handle, pxr, &pt, &xc[0], pgc->rop);
		}
	}
}

void mgc_draw_rect(canvas_t canv, const xpen_t *pxp, const xbrush_t *pxb, const xrect_t *pxr)
{
	visual_t view;
	xrect_t xr;

	view = mgc_get_canvas_visual(canv);

	xr.fx = pxr->fx;
	xr.fy = pxr->fy;
	xr.fw = pxr->fw;
	xr.fh = pxr->fh;

	mgc_rect_tm_to_pt(canv, &xr);

	mgc_draw_rect_raw(view, pxp, pxb, &xr);
}

void mgc_draw_round_raw(visual_t mgc, const xpen_t *pxp, const xbrush_t *pxb, const xrect_t *pxr, const xsize_t *pxs)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxr != NULL && pxp != NULL);

	tchar_t aa[10] = { 0 };
	xpoint_t pa[16];
	int r = 0, i = 0, j = 0;
	xpoint_t pt;
	xcolor_t xc[2] = { 0 };
	
	if (!pxs)
	{
		r = (pxr->w) / 10;
		if (r < 1)
			r = 1;
		else if (r > 6)
			r = 6;
	}

	aa[i] = _T('M');
	pa[j].x = pxr->x, pa[j].y = pxr->y + ((pxs)? pxs->h : r);
	i++, j++;

	aa[i] = _T('A');
	pa[j].x = 1, pa[j].y = 0; //clockwise and small arc
	pa[j + 1].x = ((pxs)? pxs->w : r), pa[j + 1].y = ((pxs)? pxs->h : r);
	pa[j + 2].x = pxr->x + ((pxs)? pxs->w : r), pa[j + 2].y = pxr->y;
	i++, j += 3;

	aa[i] = _T('L');
	pa[j].x = pxr->x + pxr->w - ((pxs)? pxs->w : r), pa[j].y = pxr->y;
	i++, j++;

	aa[i] = _T('A');
	pa[j].x = 1, pa[j].y = 0; //clockwise and small arc
	pa[j + 1].x = ((pxs)? pxs->w : r), pa[j + 1].y = ((pxs)? pxs->h : r);
	pa[j + 2].x = pxr->x + pxr->w, pa[j + 2].y = pxr->y + ((pxs)? pxs->h : r);
	i++, j += 3;

	aa[i] = _T('L');
	pa[j].x = pxr->x + pxr->w, pa[j].y = pxr->y + pxr->h - ((pxs)? pxs->h : r);
	i++, j++;

	aa[i] = _T('A');
	pa[j].x = 1, pa[j].y = 0; //clockwise and small arc
	pa[j + 1].x = ((pxs)? pxs->w : r), pa[j + 1].y = ((pxs)? pxs->h : r);
	pa[j + 2].x = pxr->x + pxr->w - ((pxs)? pxs->w : r), pa[j + 2].y = pxr->y + pxr->h;
	i++, j += 3;

	aa[i] = _T('L');
	pa[j].x = pxr->x + ((pxs)? pxs->w : r), pa[j].y = pxr->y + pxr->h;
	i++, j++;

	aa[i] = _T('A');
	pa[j].x = 1, pa[j].y = 0; //clockwise and small arc
	pa[j + 1].x = ((pxs)? pxs->w : r), pa[j + 1].y = ((pxs)? pxs->h : r);
	pa[j + 2].x = pxr->x, pa[j + 2].y = pxr->y + pxr->h - ((pxs)? pxs->h : r);
	i++, j += 3;

	aa[i] = _T('Z');

	mgc_draw_path_raw(mgc, pxp, NULL, aa, pa, j);

	if (!is_null_xbrush(pxb))
	{
		parse_xcolor(&xc[0], pxb->color);
		parse_xcolor(&xc[1], pxb->linear);
		pt.x = pxr->x + pxr->w / 2;
		pt.y = pxr->y + pxr->h / 2;

		if (compare_text(pxb->style, -1, GDI_ATTR_FILL_STYLE_GRADIENT, -1, 1) == 0)
		{
			if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_HORZ, -1, 1) == 0)
				(*(pgc->device->horzLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
			else if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_VERT, -1, 1) == 0)
				(*(pgc->device->vertLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
			else if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_RADIAL, -1, 1) == 0)
				(*(pgc->device->radialLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
		}
		else
		{
			(*(pgc->device->floodFill))(pgc->handle, pxr, &pt, &xc[0], pgc->rop);
		}
	}
}

void mgc_draw_round(canvas_t canv, const xpen_t *pxp, const xbrush_t *pxb, const xrect_t *pxr, const xsize_t *pxs)
{
	visual_t view;
	xrect_t xr;
	xsize_t xs;

	view = mgc_get_canvas_visual(canv);

	xr.fx = pxr->fx;
	xr.fy = pxr->fy;
	xr.fw = pxr->fw;
	xr.fh = pxr->fh;
	mgc_rect_tm_to_pt(canv, &xr);

	if (pxs)
	{
		xs.fw = pxs->fw;
		xs.fh = pxs->fh;
		mgc_size_tm_to_pt(canv, &xs);
	}

	mgc_draw_round_raw(view, pxp, pxb, &xr, ((pxs)? &xs : NULL));
}

void mgc_draw_ellipse_raw(visual_t mgc, const xpen_t *pxp, const xbrush_t *pxb, const xrect_t *pxr)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxr != NULL && pxp != NULL);

	int n, fs, ds;
	xpoint_t *ppt;
	xpoint_t pt;
	xcolor_t xc[2] = { 0 };

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc[0], pxp->color);

	n = dot_ellipse(fs, ds, pxr->w / 2, pxr->h / 2, NULL, MAX_LONG);
	ppt = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
	n = dot_ellipse(fs, ds, pxr->w / 2, pxr->h / 2, ppt, n);

	pt.x = pxr->x + pxr->w / 2;
	pt.y = pxr->y + pxr->h / 2;
	pt_world_to_screen(pt, ppt, n);

	(*(pgc->device->drawPoints))(pgc->handle, ppt, n, xc, 1, pgc->rop);
	xmem_free(ppt);

	if (!is_null_xbrush(pxb))
	{
		parse_xcolor(&xc[0], pxb->color);
		parse_xcolor(&xc[1], pxb->linear);
		pt.x = pxr->x + pxr->w / 2;
		pt.y = pxr->y + pxr->h / 2;

		if (compare_text(pxb->style, -1, GDI_ATTR_FILL_STYLE_GRADIENT, -1, 1) == 0)
		{
			if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_HORZ, -1, 1) == 0)
				(*(pgc->device->horzLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
			else if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_VERT, -1, 1) == 0)
				(*(pgc->device->vertLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
			else if (compare_text(pxb->gradient, -1, GDI_ATTR_GRADIENT_RADIAL, -1, 1) == 0)
				(*(pgc->device->radialLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
		}
		else
		{
			(*(pgc->device->floodFill))(pgc->handle, pxr, &pt, xc, pgc->rop);
		}
	}
}

void mgc_draw_ellipse(canvas_t canv, const xpen_t *pxp, const xbrush_t *pxb, const xrect_t *pxr)
{
	visual_t view;
	xrect_t xr;

	view = mgc_get_canvas_visual(canv);

	xr.fx = pxr->fx;
	xr.fy = pxr->fy;
	xr.fw = pxr->fw;
	xr.fh = pxr->fh;

	mgc_rect_tm_to_pt(canv, &xr);

	mgc_draw_ellipse_raw(view, pxp, pxb, &xr);
}

void mgc_draw_pie_raw(visual_t mgc, const xpen_t *pxp, const xbrush_t *pxb, const xrect_t *pxr, double fang, double tang)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxr != NULL && pxp != NULL);

	bool_t clockwise, largearc;
	xpoint_t pt, pt1, pt2;
	int n, fs, ds, total = 0;
	xpoint_t *ppt = NULL;
	xcolor_t xc[2] = { 0 };

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc[0], pxp->color);

	pt.x = pxr->x + pxr->w / 2;
	pt.y = pxr->y + pxr->h / 2;

	pt_calc_points(&pt, pxr->w / 2, pxr->h / 2, fang, tang, &clockwise, &largearc, &pt1, &pt2);

	pt_screen_to_world(pt, &pt1, 1);
	pt_screen_to_world(pt, &pt2, 1);

	n = dot_line(fs, ds, pt1.x, pt1.y, NULL, MAX_LONG);
	total += n;

	n = dot_arc(fs, ds, pxr->w / 2, pxr->h / 2, fang, tang, clockwise, NULL, MAX_LONG);
	total += n;

	n = dot_line(fs, ds, pt2.x, pt2.y, NULL, MAX_LONG);
	total += n;

	ppt = (xpoint_t *)xmem_alloc(total * sizeof(xpoint_t));

	total = 0;
	n = dot_line(fs, ds, pt1.x, pt1.y, ppt + total, MAX_LONG);
	total += n;

	n = dot_arc(fs, ds, pxr->w / 2, pxr->h / 2, fang, tang, clockwise, ppt + total, MAX_LONG);
	total += n;

	n = dot_line(fs, ds, pt2.x, pt2.y, ppt + total, MAX_LONG);
	total += n;

	pt_world_to_screen(pt, ppt, total);

	(*(pgc->device->drawPoints))(pgc->handle, ppt, total, xc, 1, pgc->rop);
	xmem_free(ppt);

	if (!is_null_xbrush(pxb))
	{
		parse_xcolor(&xc[0], pxb->color);
		parse_xcolor(&xc[1], pxb->linear);

		pt1.x = pxr->x + pxr->w / 2;
		pt1.y = pxr->y + pxr->h / 2;
		pt.x = (int)((float)(pxr->w / 4) * cos((fang + tang) / 2));
		pt.y = (int)((float)(pxr->h / 4) * sin((fang + tang) / 2));
		pt_world_to_screen(pt1, &pt, 1);

		if (compare_text(pxb->style, -1, GDI_ATTR_FILL_STYLE_GRADIENT, -1, 1) == 0)
		{
			(*(pgc->device->radialLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
		}
		else
		{
			(*(pgc->device->floodFill))(pgc->handle, pxr, &pt, xc, pgc->rop);
		}
	}
}

void mgc_draw_pie(canvas_t canv, const xpen_t *pxp, const xbrush_t *pxb, const xrect_t *prt, double fang, double tang)
{
	visual_t view;
	xrect_t xr;

	view = mgc_get_canvas_visual(canv);

	xr.fx = prt->fx;
	xr.fy = prt->fy;
	xr.fw = prt->fw;
	xr.fh = prt->fh;

	mgc_rect_tm_to_pt(canv, &xr);

	mgc_draw_pie_raw(view, pxp, pxb, &xr, fang, tang);
}

void mgc_draw_sector_raw(visual_t mgc, const xpen_t *pxp, const xbrush_t *pxb, const xpoint_t *ppt_center, const xspan_t *prl, const xspan_t *prs, double fang, double tang)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(ppt_center != NULL && pxp != NULL && prl != NULL && prs != NULL);

	xpoint_t pt[4];
	tchar_t aa[5];
	xpoint_t pm[8];

	xcolor_t xc[2];
	xpoint_t pt1, pt2;
	xrect_t xr;
	bool_t b;

	pt_calc_sector(ppt_center, prl->s, prs->s, fang, tang, pt, 4);

	b = (tang - fang > XPI || tang - fang < -XPI) ? 1 : 0;

	aa[0] = _T('M');
	pm[0].x = pt[0].x, pm[0].y = pt[0].y;

	aa[1] = _T('A');
	pm[1].x = 0, pm[1].y = b; //anti-closewise
	pm[2].x = prl->s, pm[2].y = prl->s; //large radius
	pm[3].x = pt[1].x, pm[3].y = pt[1].y;

	aa[2] = _T('L');
	pm[4].x = pt[2].x, pm[4].y = pt[2].y;

	aa[3] = _T('A');
	pm[5].x = 1, pm[5].y = 0; //closewise and small arc
	pm[6].x = prs->s, pm[6].y = prs->s; //small radius
	pm[7].x = pt[3].x, pm[7].y = pt[3].y;

	aa[4] = _T('Z');

	mgc_draw_path_raw(mgc, pxp, NULL, aa, pm, 8);

	if (!is_null_xbrush(pxb))
	{
		parse_xcolor(&xc[0], pxb->color);
		parse_xcolor(&xc[1], pxb->linear);

		pt1.x = (int)((float)(prl->s) * cos((fang + tang) / 2));
		pt1.y = (int)((float)(prl->s) * sin((fang + tang) / 2));
		pt_world_to_screen(*ppt_center, &pt1, 1);

		pt2.x = (int)((float)(prs->s) * cos((fang + tang) / 2));
		pt2.y = (int)((float)(prs->s) * sin((fang + tang) / 2));
		pt_world_to_screen(*ppt_center, &pt2, 1);

		pt1.x = (pt1.x + pt2.x) / 2;
		pt1.y = (pt1.y + pt2.y) / 2;

		xr.x = ppt_center->x - prl->s;
		xr.y = ppt_center->y - prl->s;
		xr.w = 2 * prl->s;
		xr.h = 2 * prl->s;

		if (compare_text(pxb->style, -1, GDI_ATTR_FILL_STYLE_GRADIENT, -1, 1) == 0)
		{
			(*(pgc->device->radialLinear))(pgc->handle, &xr, &pt1, xc, pgc->rop);
		}
		else
		{
			(*(pgc->device->floodFill))(pgc->handle, &xr, &pt1, xc, pgc->rop);
		}
	}
}

void mgc_draw_sector(canvas_t canv, const xpen_t *pxp, const xbrush_t *pxb, const xpoint_t *ppt, const xspan_t *prl, const xspan_t *prs, double fang, double tang)
{
	visual_t view;
	xpoint_t pt;
	xspan_t rl, rs;

	view = mgc_get_canvas_visual(canv);

	pt.fx = ppt->fx;
	pt.fy = ppt->fy;
	mgc_point_tm_to_pt(canv, &pt);

	rl.fs = prl->fs;
	mgc_span_tm_to_pt(canv, &rl);

	rs.fs = prs->fs;
	mgc_span_tm_to_pt(canv, &rs);

	mgc_draw_sector_raw(view, pxp, pxb, &pt, &rl, &rs, fang, tang);
}

void mgc_draw_polygon_raw(visual_t mgc, const xpen_t *pxp, const xbrush_t *pxb, const xpoint_t *ppt, int pn)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(ppt != NULL && pxp != NULL);

	xcolor_t xc[2];
	int fs, ds;
	xpoint_t *ppt_buff = NULL;
	xpoint_t pt;
	xrect_t xr;
	int i, n, total = 0;

	if (pn < 2) return;

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc[0], pxp->color);

	for (i = 1; i < pn; i++)
	{
		pt.x = ppt[i].x;
		pt.y = ppt[i].y;
		pt_screen_to_world(ppt[i - 1], &pt, 1);

		n = dot_line(fs, ds, pt.x, pt.y, NULL, MAX_LONG);
		ppt_buff = (xpoint_t *)xmem_realloc(ppt_buff, (total + n) * sizeof(xpoint_t));
		n = dot_line(fs, ds, pt.x, pt.y, ppt_buff + total, n);

		pt_world_to_screen(ppt[i - 1], ppt_buff + total, n);
		total += n;
	}

	pt.x = ppt[0].x;
	pt.y = ppt[0].y;
	pt_screen_to_world(ppt[i - 1], &pt, 1);

	n = dot_line(fs, ds, pt.x, pt.y, NULL, MAX_LONG);
	ppt_buff = (xpoint_t *)xmem_realloc(ppt_buff, (total + n) * sizeof(xpoint_t));
	n = dot_line(fs, ds, pt.x, pt.y, ppt_buff + total, n);

	pt_world_to_screen(ppt[i - 1], ppt_buff + total, n);
	total += n;

	(*(pgc->device->drawPoints))(pgc->handle, ppt_buff, total, xc, 1, pgc->rop);

	if (!is_null_xbrush(pxb))
	{
		parse_xcolor(&xc[0], pxb->color);
		parse_xcolor(&xc[1], pxb->linear);

		pt_gravity_point(ppt_buff, total, &pt);
		pt_polygon_rect(ppt_buff, total, &xr);

		if (compare_text(pxb->style, -1, GDI_ATTR_FILL_STYLE_GRADIENT, -1, 1) == 0)
		{
			(*(pgc->device->radialLinear))(pgc->handle, &xr, &pt, xc, pgc->rop);
		}
		else
		{
			(*(pgc->device->floodFill))(pgc->handle, &xr, &pt, xc, pgc->rop);
		}
	}

	xmem_free(ppt_buff);
}

void mgc_draw_polygon(canvas_t canv, const xpen_t *pxp, const xbrush_t *pxb, const xpoint_t *ppt, int n)
{
	visual_t view;
	xpoint_t *pa;
	int i;

	view = mgc_get_canvas_visual(canv);

	pa = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));
	for (i = 0; i < n; i++)
	{
		pa[i].fx = ppt[i].fx;
		pa[i].fy = ppt[i].fy;
		mgc_point_tm_to_pt(canv, &pa[i]);
	}

	mgc_draw_polygon_raw(view, pxp, pxb, pa, n);

	xmem_free(pa);
}

void mgc_draw_equilagon_raw(visual_t mgc, const xpen_t *pxp, const xbrush_t *pxb, const xpoint_t *ppt_center, const xspan_t *pxn, int pn)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(ppt_center != NULL && pxp != NULL && pxn != NULL);

	xcolor_t xc[2];
	int fs, ds;
	xpoint_t *ppt_buff = NULL;
	xpoint_t* ppt;
	xpoint_t pt;
	xrect_t xr;
	int i, n, total = 0;

	if (pn < 3) return;

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc[0], pxp->color);

	ppt = (xpoint_t*)xmem_alloc(sizeof(xpoint_t)* pn);

	pt_calc_equilater(ppt_center, pxn->s, ppt, pn);

	for (i = 1; i < pn; i++)
	{
		pt.x = ppt[i].x;
		pt.y = ppt[i].y;
		pt_screen_to_world(ppt[i - 1], &pt, 1);

		n = dot_line(fs, ds, pt.x, pt.y, NULL, MAX_LONG);
		ppt_buff = (xpoint_t *)xmem_realloc(ppt_buff, (total + n) * sizeof(xpoint_t));
		n = dot_line(fs, ds, pt.x, pt.y, ppt_buff + total, n);

		pt_world_to_screen(ppt[i - 1], ppt_buff + total, n);
		total += n;
	}

	pt.x = ppt[0].x;
	pt.y = ppt[0].y;
	pt_screen_to_world(ppt[i - 1], &pt, 1);

	n = dot_line(fs, ds, pt.x, pt.y, NULL, MAX_LONG);
	ppt_buff = (xpoint_t *)xmem_realloc(ppt_buff, (total + n) * sizeof(xpoint_t));
	n = dot_line(fs, ds, pt.x, pt.y, ppt_buff + total, n);

	pt_world_to_screen(ppt[i - 1], ppt_buff + total, n);
	total += n;

	xmem_free(ppt);

	(*(pgc->device->drawPoints))(pgc->handle, ppt_buff, total, xc, 1, pgc->rop);
	xmem_free(ppt_buff);

	if (!is_null_xbrush(pxb))
	{
		parse_xcolor(&xc[0], pxb->color);
		parse_xcolor(&xc[1], pxb->linear);

		pt.x = ppt_center->x;
		pt.y = ppt_center->y;

		xr.x = ppt_center->x - pxn->s;
		xr.y = ppt_center->y - pxn->s;
		xr.w = 2 * pxn->s;
		xr.h = 2 * pxn->s;

		if (compare_text(pxb->style, -1, GDI_ATTR_FILL_STYLE_GRADIENT, -1, 1) == 0)
		{
			(*(pgc->device->radialLinear))(pgc->handle, &xr, &pt, xc, pgc->rop);
		}
		else
		{
			(*(pgc->device->floodFill))(pgc->handle, &xr, &pt, xc, pgc->rop);
		}
	}
}

void mgc_draw_equilagon(canvas_t canv, const xpen_t *pxp, const xbrush_t *pxb, const xpoint_t *ppt, const xspan_t *pxn, int n)
{
	visual_t view;

	xpoint_t pt;
	xspan_t xn;

	view = mgc_get_canvas_visual(canv);

	if (n < 3)
		return;

	pt.fx = ppt->fx;
	pt.fy = ppt->fy;

	mgc_point_tm_to_pt(canv, &pt);

	xn.fs = pxn->fs;
	mgc_span_tm_to_pt(canv, &xn);

	mgc_draw_equilagon_raw(view, pxp, pxb, &pt, &xn, n);
}

void mgc_draw_path_raw(visual_t mgc, const xpen_t *pxp, const xbrush_t *pxb, const tchar_t *aa, const xpoint_t *pa, int pn)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(aa != NULL && pa != NULL && pxp != NULL);

	xpoint_t pt_m = {0};
	xpoint_t pt_p = {0};
	xpoint_t pt_i = {0};
	xpoint_t pt[4] = {0};
	xpoint_t pc, pk = {0};
	xcolor_t xc;
	int fs, ds;
	int rx, ry;
	int n, dw, total = 0, ppt_size = 0;
	int sflag, lflag;
	double arcf, arct;
	xpoint_t *ppt_buf = NULL;

	calc_penmode(pxp, &fs, &ds);
	parse_xcolor(&xc, pxp->color);

	while (*aa)
	{
		n = 0;

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

			pt_screen_to_world(pt[0], &pt[1], 1);
			dw = dot_line(fs, ds, pt[1].x, pt[1].y, NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_line(fs, ds, pt[1].x, pt[1].y, ppt_buf + ppt_size, dw);

			pt_world_to_screen(pt[0], &pt[1], 1);
			pt_world_to_screen(pt[0], ppt_buf + ppt_size, dw);
			ppt_size += dw;

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

			pt_screen_to_world(pt[0], &pt[1], 1);
			dw = dot_line(fs, ds, pt[1].x, pt[1].y, NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_line(fs, ds, pt[1].x, pt[1].y, ppt_buf + ppt_size, dw);

			pt_world_to_screen(pt[0], &pt[1], 1);
			pt_world_to_screen(pt[0], ppt_buf + ppt_size, dw);
			ppt_size += dw;

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

			pt_screen_to_world(pt[0], pt + 1, 2);
			dw = dot_curve2(fs, ds, &pt[1], &pt[2], NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_curve2(fs, ds, &pt[1], &pt[2], ppt_buf + ppt_size, dw);

			pt_world_to_screen(pt[0], pt + 1, 2);
			pt_world_to_screen(pt[0], ppt_buf + ppt_size, dw);
			ppt_size += dw;

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

			pt_screen_to_world(pt[0], pt + 1, 2);
			dw = dot_curve2(fs, ds, &pt[1], &pt[2], NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_curve2(fs, ds, &pt[1], &pt[2], ppt_buf + ppt_size, dw);

			pt_world_to_screen(pt[0], pt + 1, 2);
			pt_world_to_screen(pt[0], ppt_buf + ppt_size, dw);
			ppt_size += dw;

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

			pt_screen_to_world(pt[0], pt + 1, 2);
			dw = dot_curve2(fs, ds, &pt[1], &pt[2], NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_curve2(fs, ds, &pt[1], &pt[2], ppt_buf + ppt_size, dw);

			pt_world_to_screen(pt[0], pt + 1, 2);
			pt_world_to_screen(pt[0], ppt_buf + ppt_size, dw);
			ppt_size += dw;

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

			pt_screen_to_world(pt[0], pt + 1, 2);
			dw = dot_curve2(fs, ds, &pt[1], &pt[2], NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_curve2(fs, ds, &pt[1], &pt[2], ppt_buf + ppt_size, dw);

			pt_world_to_screen(pt[0], pt + 1, 2);
			pt_world_to_screen(pt[0], ppt_buf + ppt_size, dw);
			ppt_size += dw;

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

			pt_screen_to_world(pt[0], pt + 1, 3);
			dw = dot_curve3(fs, ds, &pt[1], &pt[2], &pt[3], NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_curve3(fs, ds, &pt[1], &pt[2], &pt[3], ppt_buf + ppt_size, dw);

			pt_world_to_screen(pt[0], pt + 1, 3);
			pt_world_to_screen(pt[0], ppt_buf + ppt_size, dw);
			ppt_size += dw;

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

			pt_screen_to_world(pt[0], pt + 1, 3);
			dw = dot_curve3(fs, ds, &pt[1], &pt[2], &pt[3], NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_curve3(fs, ds, &pt[1], &pt[2], &pt[3], ppt_buf + ppt_size, dw);

			pt_world_to_screen(pt[0], pt + 1, 3);
			pt_world_to_screen(pt[0], ppt_buf + ppt_size, dw);
			ppt_size += dw;

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

			pt_screen_to_world(pt[0], pt + 1, 3);
			dw = dot_curve3(fs, ds, &pt[1], &pt[2], &pt[3], NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_curve3(fs, ds, &pt[1], &pt[2], &pt[3], ppt_buf + ppt_size, dw);

			pt_world_to_screen(pt[0], pt + 1, 3);
			pt_world_to_screen(pt[0], ppt_buf + ppt_size, dw);
			ppt_size += dw;

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

			pt_screen_to_world(pt[0], pt + 1, 3);
			dw = dot_curve3(fs, ds, &pt[1], &pt[2], &pt[3], NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_curve3(fs, ds, &pt[1], &pt[2], &pt[3], ppt_buf + ppt_size, dw);

			pt_world_to_screen(pt[0], pt + 1, 3);
			pt_world_to_screen(pt[0], ppt_buf + ppt_size, dw);
			ppt_size += dw;

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

			sflag = pt_calc_radian(sflag, lflag, rx, ry, &pt[0], &pt[1], &pc, &arcf, &arct);

			dw = dot_arc(fs, ds, rx, ry, arcf, arct, sflag, NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_arc(fs, ds, rx, ry, arcf, arct, sflag, ppt_buf + ppt_size, dw);

			pt_world_to_screen(pc, ppt_buf + ppt_size, dw);
			ppt_size += dw;

			n = 3;
		}
		else if (*aa == _T('Z') || *aa == _T('z'))
		{
			pt[0].x = pt_p.x;
			pt[0].y = pt_p.y;
			pt[1].x = pt_m.x;
			pt[1].y = pt_m.y;

			pt_screen_to_world(pt[0], &pt[1], 1);
			dw = dot_line(fs, ds, pt[1].x, pt[1].y, NULL, MAX_LONG);
			ppt_buf = (xpoint_t *)xmem_realloc(ppt_buf, sizeof(xpoint_t) * (ppt_size + dw));
			dw = dot_line(fs, ds, pt[1].x, pt[1].y, ppt_buf + ppt_size, dw);

			pt_world_to_screen(pt[0], &pt[1], 1);
			pt_world_to_screen(pt[0], ppt_buf + ppt_size, dw);
			ppt_size += dw;

			break;
		}

		aa++;
		pa += n;
		total += n;
	}

	(*(pgc->device->drawPoints))(pgc->handle, ppt_buf, ppt_size, &xc, 1, pgc->rop);
	xmem_free(ppt_buf);
}

void mgc_draw_path(canvas_t canv, const xpen_t *pxp, const xbrush_t *pxb, const tchar_t *aa, const xpoint_t *pa, int n)
{
	visual_t view;
	xpoint_t *ppt;
	int i, j;

	view = mgc_get_canvas_visual(canv);

	if (is_null(aa))
		return;

	ppt = (xpoint_t *)xmem_alloc(n * sizeof(xpoint_t));

	xmem_copy((void *)ppt, (void *)pa, n * sizeof(xpoint_t));

	i = j = 0;
	while (*(aa + j))
	{
		if (*(aa + j) == _T('M') || *(aa + j) == _T('m'))
		{
			mgc_point_tm_to_pt(canv, &ppt[i]);
			i += 1;
		}
		else if (*(aa + j) == _T('L') || *(aa + j) == _T('l'))
		{
			mgc_point_tm_to_pt(canv, &ppt[i]);
			i += 1;
		}
		else if (*(aa + j) == _T('Q') || *(aa + j) == _T('q'))
		{
			mgc_point_tm_to_pt(canv, &ppt[i]);
			mgc_point_tm_to_pt(canv, &ppt[i + 1]);
			i += 2;
		}
		else if (*(aa + j) == _T('T') || *(aa + j) == _T('t'))
		{
			mgc_point_tm_to_pt(canv, &ppt[i]);
			i += 1;
		}
		else if (*(aa + j) == _T('C') || *(aa + j) == _T('c'))
		{
			mgc_point_tm_to_pt(canv, &ppt[i]);
			mgc_point_tm_to_pt(canv, &ppt[i + 1]);
			mgc_point_tm_to_pt(canv, &ppt[i + 2]);
			i += 3;
		}
		else if (*(aa + j) == _T('S') || *(aa + j) == _T('s'))
		{
			mgc_point_tm_to_pt(canv, &ppt[i]);
			mgc_point_tm_to_pt(canv, &ppt[i + 1]);
			i += 2;
		}
		else if (*(aa + j) == _T('A') || *(aa + j) == _T('a'))
		{
			mgc_size_tm_to_pt(canv, (xsize_t *)(&ppt[i]));
			mgc_size_tm_to_pt(canv, (xsize_t *)(&ppt[i + 1]));
			mgc_point_tm_to_pt(canv, &ppt[i + 2]);
			i += 3;
		}
		else if (*(aa + j) == _T('Z') || *(aa + j) == _T('z'))
		{
			break;
		}

		j++;
	}

	mgc_draw_path_raw(view, pxp, pxb, aa, ppt, n);

	xmem_free(ppt);
}

void mgc_multi_line_raw(visual_t mgc, const xfont_t *pxf, const xface_t *pxa, const xpen_t *pxp, const xrect_t *pxr)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxf != NULL && pxp != NULL && pxr != NULL);

	float line_rati;
	int th, lh;
	int i, rows;
	xpoint_t pt1, pt2;
	xsize_t xs;

	if (is_null(pxa->line_height))
		line_rati = xstof(DEF_GDI_TEXT_LINE_HEIGHT);
	else
		line_rati = xstof(pxa->line_height);

	if (line_rati < 1.0)
		line_rati = 1.0;

	mgc_text_metric_raw(mgc, pxf, &xs);

	th = xs.h;
	lh = (int)((float)th * (line_rati - 1.0));

	rows = pxr->h / (th + lh);

	pt1.x = pxr->x;
	pt1.y = pxr->y + th + lh;
	pt2.x = pxr->x + pxr->w;
	pt2.y = pxr->y + th + lh;

	for (i = 0; i < rows; i++)
	{
		mgc_draw_line_raw(mgc, pxp, &pt1, &pt2);

		pt1.y += (th + lh);
		pt2.y += (th + lh);
	}
}

void mgc_multi_line(canvas_t canv, const xfont_t *pxf, const xface_t *pxa, const xpen_t *pxp, const xrect_t *pxr)
{
	visual_t view;
	xrect_t xr;

	xmem_copy((void *)&xr, (void *)pxr, sizeof(xrect_t));
	mgc_rect_tm_to_pt(canv, &xr);

	view = mgc_get_canvas_visual(canv);

	mgc_multi_line_raw(view, pxf, pxa, pxp, &xr);
}

void mgc_text_out_raw(visual_t mgc, const xfont_t *pxf, const xpoint_t *ppt, const tchar_t *txt, int len)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	dword_t total = 0;
	mem_font_ptr pmf;
	font_t fnt = NULL;
	font_metrix_t fm = {0};
	mem_pixmap_ptr pix = NULL;
	xcolor_t xc;
	int x, y, w, n;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxf != NULL && ppt != NULL);

	TRY_CATCH;

	if (len < 0)
		len = xslen(txt);

	pmf = select_font(MGC_FONT_FIXED);
	if (!pmf)
	{
		raise_user_error(_T("mgc_text_out"), _T("select_font"));
	}

	fnt = (*pmf->createFont)(pxf);
	if (!fnt)
	{
		raise_user_error(_T("mgc_text_out"), _T("createFont"));
	}

	(*pmf->getFontMetrix)(fnt, NULL, &fm);

	pix = alloc_pixmap(fm.width, fm.height);
	if (!pix)
	{
		raise_user_error(_T("mgc_text_out"), _T("alloc_pixmap"));
	}

	x = ppt->x;
	y = ppt->y;

	parse_xcolor(&xc, pxf->color);

	while (len)
	{
		clean_pixmap(pix);
		w = (*pmf->getCharPixmap)(fnt, txt, pix);
		pix->fg_color = PUT_PIXVAL(0, xc.r, xc.g, xc.b);
		pix->bg_used = 0;

		(*(pgc->device->drawPixmap))(pgc->handle, x, y, pix->width, pix->height, pix, 0, 0, pgc->rop);
		x += w;

#if defined(_UNICODE) || defined(UNICODE)
		n = 1;
#else
		n = mbs_sequence(*txt);
#endif
		txt += n;
		len -= n;
	}

	free_pixmap(pix);
	pix = NULL;

	(*pmf->destroyFont)(fnt);
	fnt = NULL;

	END_CATCH;

	return;
ONERROR:

	if (pix)
		free_pixmap(pix);
	if (fnt)
		(*pmf->destroyFont)(fnt);

	return;
}

void mgc_text_out(canvas_t canv, const xfont_t *pxf, const xpoint_t *ppt, const tchar_t *txt, int len)
{
	xpoint_t pt = {0};
	visual_t view;

	view = mgc_get_canvas_visual(canv);

	pt.fx = ppt->fx;
	pt.fy = ppt->fy;

	mgc_point_tm_to_pt(canv, &pt);

	mgc_text_out_raw(view, pxf, &pt, txt, len);
}

void mgc_draw_text_raw(visual_t mgc, const xfont_t *pxf, const xface_t *pxa, const xrect_t *pxr, const tchar_t *txt, int len)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	mem_font_ptr pmf;
	font_t fnt = NULL;
	font_metrix_t fm = { 0 };
	mem_pixmap_ptr pix = NULL;
	xcolor_t xc;
	tchar_t pch[CHS_LEN + 1] = { 0 };
	int n = 0, total = 0;
	xrect_t xr = { 0 };
	xrect_t *pa = NULL;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxf != NULL && pxr != NULL);

	TRY_CATCH;

	len = words_count(txt, len);
	if (!len)
	{
		raise_user_error(_T("mgc_draw_text"), _T("empty text"));
	}

	pmf = select_font(MGC_FONT_FIXED);
	if (!pmf)
	{
		raise_user_error(_T("mgc_draw_text"), _T("select_font"));
	}

	fnt = (*pmf->createFont)(pxf);
	if (!fnt)
	{
		raise_user_error(_T("mgc_draw_text"), _T("createFont"));
	}

	(*pmf->getFontMetrix)(fnt, NULL, &fm);

	pix = alloc_pixmap(fm.width, fm.height);
	if (!pix)
	{
		raise_user_error(_T("mgc_draw_text"), _T("alloc_pixmap"));
	}

	pa = (xrect_t *)xmem_alloc(sizeof(xrect_t) * len);
	mgc_text_indicate_raw(mgc, pxf, pxa, txt, -1, pxr, pa, len);

	parse_xcolor(&xc, pxf->color);

	while (n < len)
	{
		total += peek_word((txt + total), pch);

		clean_pixmap(pix);
		(*pmf->getCharPixmap)(fnt, pch, pix);
		pix->fg_color = PUT_PIXVAL(0, xc.r, xc.g, xc.b);
		pix->bg_used = 0;

		if (pt_in_rect(RECTPOINT(&(pa[n])), pxr))
		{
			(*(pgc->device->drawPixmap))(pgc->handle, pa[n].x, pa[n].y, pix->width, pix->height, pix, 0, 0, pgc->rop);
		}
		n++;
	}

	xmem_free(pa);
	pa = NULL;

	free_pixmap(pix);
	pix = NULL;

	(*pmf->destroyFont)(fnt);
	fnt = NULL;

	END_CATCH;

	return;
ONERROR:

	if (pa)
		xmem_free(pa);
	if (pix)
		free_pixmap(pix);
	if (fnt)
		(*pmf->destroyFont)(fnt);

	return;
}

void mgc_draw_text(canvas_t canv, const xfont_t *pxf, const xface_t *pxa, const xrect_t *pxr, const tchar_t *txt, int len)
{
	visual_t view;
	xrect_t xr;

	view = mgc_get_canvas_visual(canv);

	xr.fx = pxr->fx;
	xr.fy = pxr->fy;
	xr.fw = pxr->fw;
	xr.fh = pxr->fh;

	mgc_rect_tm_to_pt(canv, &xr);

	mgc_draw_text_raw(view, pxf, pxa, &xr, txt, len);
}

void mgc_text_rect_raw(visual_t mgc, const xfont_t *pxf, const xface_t *pxa, const tchar_t *txt, int len, xrect_t *pxr)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	mem_font_ptr pmf;
	font_t fnt = NULL;
	int n = 0, total = 0;
	tchar_t pch[CHS_LEN + 1] = {0};
	xsize_t se;
	int w, h, maxw = 0;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxf != NULL && pxr != NULL);

	TRY_CATCH;

	len = words_count(txt, len);

	pmf = select_font(MGC_FONT_FIXED);
	if (!pmf)
	{
		raise_user_error(_T("mgc_text_rect"), _T("select_font"));
	}

	fnt = (*pmf->createFont)(pxf);
	if (!fnt)
	{
		raise_user_error(_T("mgc_text_rect"), _T("createFont"));
	}

	w = 0;
	h = 0;
	n = 0;
	while (n++ < len)
	{
		total += peek_word((txt + total), pch);

		(*pmf->getCharSize)(fnt, pch, &se);

		if (!h)
		{
			if (is_null(pxa->line_height))
				h = se.h;
			else
				h = (int)((float)se.h * xstof(pxa->line_height));
		}

		if (pxa && compare_text(pxa->text_wrap, -1, GDI_ATTR_TEXT_WRAP_WORDBREAK, -1, 1) == 0)
		{
			if (pxr->w && (w + se.w > pxr->w))
			{
				if (is_null(pxa->line_height))
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
		else if (pxa && compare_text(pxa->text_wrap, -1, GDI_ATTR_TEXT_WRAP_LINEBREAK, -1, 1) == 0)
		{
			if (pch[0] == _T('\n'))
			{
				if (is_null(pxa->line_height))
					h += se.h;
				else
					h += (int)((float)se.h * xstof(pxa->line_height));

				w = 0;
			}
			else if (pxr->w && (w + se.w > pxr->w))
			{
				if (is_null(pxa->line_height))
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

	(*pmf->destroyFont)(fnt);
	fnt = NULL;

	pxr->h = h;
	if (!pxr->w) pxr->w = maxw;

	END_CATCH;

	return;
ONERROR:
	if (fnt)
		(*pmf->destroyFont)(fnt);

	return;
}

void mgc_text_rect(canvas_t canv, const xfont_t *pxf, const xface_t *pxa, const tchar_t *txt, int len, xrect_t *pxr)
{
	int n, m = 0, total = 0;
	float fw = 0.0f, fh = 0.0f;
	float px, pm;
	tchar_t pch[CHS_LEN + 1] = {0};

	if (len < 0)
		len = xslen(txt);

	if (is_null(txt) || !len)
		return;

	font_metric_by_pt(xstof(pxf->size), &pm, &px);
	fh = px;
	m = 0;
	while (total < len)
	{
		n = peek_word((txt + total), pch);
		m += n;
		total += n;
		fw += px;
		if ((fw >= pxr->fw) || (total == len && (int)fw))
		{
			m = 0;
			fw = 0.0f;

			if (n)
				fh += px;
		}
	}

	pxr->fh = fh;
}

void mgc_text_size_raw(visual_t mgc, const xfont_t *pxf, const tchar_t *txt, int len, xsize_t *pxs)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	mem_font_ptr pmf;
	font_t fnt = NULL;
	int n;
	xsize_t se;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxf != NULL && pxs != NULL);

	TRY_CATCH;

	if (len < 0)
		len = xslen(txt);

	pmf = select_font(MGC_FONT_FIXED);
	if (!pmf)
	{
		raise_user_error(_T("mgc_text_size"), _T("select_font"));
	}

	fnt = (*pmf->createFont)(pxf);
	if (!fnt)
	{
		raise_user_error(_T("mgc_text_size"), _T("createFont"));
	}

	pxs->w = 0;
	pxs->h = 0;

	n = 0;
	while (n < len)
	{
		(*pmf->getCharSize)(fnt, (txt + n), &se);

		pxs->w += se.w;
		if (pxs->h < se.h)
			pxs->h = se.h;

#if defined(_UNICODE) || defined(UNICODE)
		n += ucs_sequence(*(txt + n));
#else
		n += mbs_sequence(*(txt + n));
#endif
	}

	(*pmf->destroyFont)(fnt);
	fnt = NULL;

	END_CATCH;

	return;
ONERROR:
	if (fnt)
		(*pmf->destroyFont)(fnt);

	return;
}

void mgc_text_size(canvas_t canv, const xfont_t *pxf, const tchar_t *txt, int len, xsize_t *pxs)
{
	float pm, mm = 0.0f;
	int n, total = 0;
	byte_t chs[5];
	tchar_t pch[CHS_LEN + 1] = {0};

	font_metric_by_pt(xstof(pxf->size), &pm, NULL);

	if (len < 0)
		len = xslen(txt);
	if (is_null(txt) || !len)
	{
		pxs->w = 0;
		pxs->h = 0;
		return;
	}

	while (n = peek_word((txt + total), pch))
	{
		if (n > 1)
		{
			mm += pm;
		}
		else if (n > 0)
		{
#if defined(_UNICODE) || defined(UNICODE)
			if (ucs_byte_to_utf8(*(txt + total), chs) > 1)
				mm += pm;
			else
				mm += (float)(pm * 0.75);
#else
			mm += (float)(pm * 0.75);
#endif
		}

		total += n;
	}

	pxs->fw = mm;
	pxs->fh = pm * 1.2f;
}

void mgc_text_metric_raw(visual_t mgc, const xfont_t *pxf, xsize_t *pxs)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	mem_font_ptr pmf;
	font_t fnt = NULL;
	font_metrix_t fm = {0};

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxf != NULL && pxs != NULL);

	TRY_CATCH;

	pmf = select_font(MGC_FONT_FIXED);
	if (!pmf)
	{
		raise_user_error(_T("mgc_text_size"), _T("select_font"));
	}

	fnt = (*pmf->createFont)(pxf);
	if (!fnt)
	{
		raise_user_error(_T("mgc_text_size"), _T("createFont"));
	}

	(*pmf->getFontMetrix)(fnt, NULL, &fm);

	pxs->w = fm.width;
	pxs->h = fm.height;

	(*pmf->destroyFont)(fnt);
	fnt = NULL;

	END_CATCH;

	return;
ONERROR:
	if (fnt)
		(*pmf->destroyFont)(fnt);

	return;
}

void mgc_text_metric(canvas_t canv, const xfont_t *pxf, xsize_t *pxs)
{
	visual_t view;

	view = mgc_get_canvas_visual(canv);

	mgc_text_metric_raw(view, pxf, pxs);

	mgc_size_pt_to_tm(canv, pxs);
}

void mgc_text_indicate_raw(visual_t mgc, const xfont_t *pxf, const xface_t *pxa, const tchar_t *txt, int len, const xrect_t* pxr, xrect_t *pr, int pn)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	mem_font_ptr pmf;
	font_t fnt = NULL;
	int n = 0, total = 0;
	tchar_t pch[CHS_LEN + 1] = { 0 };
	xsize_t se;
	xrect_t xr;
	int w, h, maxw, maxh;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxf != NULL && pxr != NULL);

	TRY_CATCH;

	len = words_count(txt, len);
	len = (len < pn) ? len : pn;

	pmf = select_font(MGC_FONT_FIXED);
	if (!pmf)
	{
		raise_user_error(_T("mgc_text_rect"), _T("select_font"));
	}

	fnt = (*pmf->createFont)(pxf);
	if (!fnt)
	{
		raise_user_error(_T("mgc_text_rect"), _T("createFont"));
	}

	w = 0, maxw = 0;
	h = 0, maxh = 0;
	n = 0;
	while (n < len)
	{
		total += peek_word((txt + total), pch);

		(*pmf->getCharSize)(fnt, pch, &se);

		if (!h)
		{
			if (is_null(pxa->line_height))
				h = se.h;
			else
				h = (int)((float)se.h * xstof(pxa->line_height));
		}

		if (pxa && compare_text(pxa->text_wrap, -1, GDI_ATTR_TEXT_WRAP_WORDBREAK, -1, 1) == 0)
		{
			if (pxr->w && (w + se.w > pxr->w))
			{
				if (is_null(pxa->line_height))
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

				if (pr)
				{
					pr[n].x = w;
					pr[n].y = h;
					pr[n].w = se.w;
					pr[n].h = se.h;
				}
				n++;
			}
		}
		else if (pxa && compare_text(pxa->text_wrap, -1, GDI_ATTR_TEXT_WRAP_LINEBREAK, -1, 1) == 0)
		{
			if (pch[0] == _T('\n'))
			{
				if (pr)
				{
					pr[n].x = w;
					pr[n].y = h;
					pr[n].w = se.w;
					pr[n].h = se.h;
				}
				n++;

				if (is_null(pxa->line_height))
					h += se.h;
				else
					h += (int)((float)se.h * xstof(pxa->line_height));

				w = 0;
			}
			else if (pxr->w && (w + se.w > pxr->w))
			{
				if (is_null(pxa->line_height))
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

				if (pr)
				{
					pr[n].x = w;
					pr[n].y = h;
					pr[n].w = se.w;
					pr[n].h = se.h;
				}
				n++;
			}
		}
		else
		{
			w += se.w;

			if (pr)
			{
				pr[n].x = w;
				pr[n].y = h;
				pr[n].w = se.w;
				pr[n].h = se.h;
			}
			n++;
		}

		if (maxw < w) maxw = w;
	}

	maxh = h;

	xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));
	pt_adjust_rect(&xr, maxw, maxh, pxa->text_align, pxa->line_align);

	for (n = 0; n < len; n++)
	{
		pr[n].x += (xr.x - pr[n].w);
		pr[n].y += (xr.y - pr[n].h);
	}

	(*pmf->destroyFont)(fnt);
	fnt = NULL;

	END_CATCH;

	return;
ONERROR:
	if (fnt)
		(*pmf->destroyFont)(fnt);

	return;
}

void mgc_text_indicate(canvas_t canv, const xfont_t *pxf, const xface_t *pxa, const tchar_t *str, int len, const xrect_t *pxr, xrect_t *pa, int n)
{
	visual_t view;
	int i;

	view = mgc_get_canvas_visual(canv);

	mgc_text_indicate_raw(view, pxf, pxa, str, len, pxr, pa, n);

	for (i = 0; i < n; i++)
	{
		mgc_rect_pt_to_tm(canv, &pa[i]);
	}
}

float mgc_pixel_metric_raw(visual_t mgc, bool_t horz)
{
	return 1.0;
}

float mgc_pixel_metric(canvas_t canv, bool_t horz)
{
	visual_t view;

	view = mgc_get_canvas_visual(canv);

	return mgc_pixel_metric_raw(view, horz);
}

void mgc_color_out_raw(visual_t mgc, const xrect_t *pxr, bool_t horz, const tchar_t *rgbstr, int len)
{
	xrect_t xr;
	xcolor_t xc;
	xbrush_t xb;
	tchar_t *val;
	int vlen;
	tchar_t clr[CLR_LEN + 1];
	int n, total = 0;

	if (len < 0)
		len = xslen(rgbstr);

	default_xbrush(&xb);

	while (n = parse_string_token((rgbstr + total), (len - total), _T(';'), &val, &vlen))
	{
		total += n;

		xsncpy(clr, val, CLR_LEN);
		parse_xcolor(&xc, clr);
		format_xcolor(&xc, xb.color);

		mgc_draw_rect_raw(mgc, NULL, &xb, &xr);

		if (horz)
			xr.x += xr.w;
		else
			xr.y += xr.h;
	}
}

void mgc_color_out(canvas_t canv, const xrect_t *pxr, bool_t horz, const tchar_t *rgbstr, int len)
{
	xrect_t xr;
	xcolor_t xc;
	xbrush_t xb;
	tchar_t *val;
	int vlen;
	tchar_t clr[CLR_LEN + 1];
	int n, total = 0;

	if (len < 0)
		len = xslen(rgbstr);

	default_xbrush(&xb);

	while (n = parse_string_token((rgbstr + total), (len - total), _T(';'), &val, &vlen))
	{
		total += n;

		xsncpy(clr, val, CLR_LEN);
		parse_xcolor(&xc, clr);
		format_xcolor(&xc, xb.color);

		mgc_draw_rect(canv, NULL, &xb, &xr);

		if (horz)
			xr.fx += xr.fw;
		else
			xr.fy += xr.fh;
	}
}

void mgc_gradient_rect_raw(visual_t mgc, const xcolor_t *clr_brim, const xcolor_t *clr_core, const tchar_t *gradient, const xrect_t *pxr)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxr != NULL && clr_brim != NULL && clr_core != NULL);

	xcolor_t xc[2] = {0};
	xpoint_t pt;

	xmem_copy((void*)&xc[0], (void*)clr_brim, sizeof(xcolor_t));
	xmem_copy((void*)&xc[1], (void*)clr_core, sizeof(xcolor_t));

	pt.x = pxr->x + pxr->w / 2;
	pt.y = pxr->y + pxr->h / 2;

	if (compare_text(gradient, -1, GDI_ATTR_GRADIENT_HORZ, -1, 1) == 0)
		(*(pgc->device->horzLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
	else if (compare_text(gradient, -1, GDI_ATTR_GRADIENT_VERT, -1, 1) == 0)
		(*(pgc->device->vertLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
	else if (compare_text(gradient, -1, GDI_ATTR_GRADIENT_RADIAL, -1, 1) == 0)
		(*(pgc->device->radialLinear))(pgc->handle, pxr, &pt, xc, pgc->rop);
}

void mgc_alphablend_rect_raw(visual_t mgc, const xcolor_t* pxc, const xrect_t* pxr, int opacity)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxr != NULL && pxc != NULL);

	(*(pgc->device->maskRect))(pgc->handle, pxr, pxc, opacity);
}

void mgc_draw_image_raw(visual_t mgc, const ximage_t *pmi, const xrect_t *pxr)
{
	memo_context_t *pgc = (memo_context_t *)mgc;

	XDK_ASSERT(mgc && mgc->tag == _VISUAL_MEMORY);
	XDK_ASSERT(pxr != NULL && pmi != NULL);

	bitmap_t ih = NULL;
	int len, len_bmp, len_zip;
	byte_t *buf_bmp, *buf_zip;
	xcolor_t xc;
	xsize_t xs;
	xrect_t xr;
	tchar_t itype[NUM_LEN];

	parse_xcolor(&xc, pmi->color);

	if (xsicmp(pmi->type, GDI_ATTR_IMAGE_TYPE_JPG) == 0)
	{
		len = xslen(pmi->source);
		len_zip = xbas_decode(pmi->source, len, NULL, MAX_LONG);
		buf_zip = (byte_t*)xmem_alloc(len_zip);
		xbas_decode(pmi->source, len, buf_zip, len_zip);

		len_bmp = xjpg_decompress(buf_zip, len_zip, NULL, MAX_LONG);
		buf_bmp = (byte_t*)xmem_alloc(len_bmp);
		xjpg_decompress(buf_zip, len_zip, buf_bmp, len_bmp);

		xmem_free(buf_zip);
	}
	else if (xsicmp(pmi->type, GDI_ATTR_IMAGE_TYPE_PNG) == 0)
	{
		len = xslen(pmi->source);
		len_zip = xbas_decode(pmi->source, len, NULL, MAX_LONG);
		buf_zip = (byte_t*)xmem_alloc(len_zip);
		xbas_decode(pmi->source, len, buf_zip, len_zip);

		len_bmp = xpng_decompress(buf_zip, len_zip, NULL, MAX_LONG);
		buf_bmp = (byte_t*)xmem_alloc(len_bmp);
		xpng_decompress(buf_zip, len_zip, buf_bmp, len_bmp);

		xmem_free(buf_zip);
	}
	else if (xsicmp(pmi->type, GDI_ATTR_IMAGE_TYPE_BMP) == 0)
	{
		len = xslen(pmi->source);
		len_bmp = xbas_decode(pmi->source, len, NULL, MAX_LONG);
		buf_bmp = (byte_t*)xmem_alloc(len_bmp);
		xbas_decode(pmi->source, len, buf_bmp, len_bmp);
	}
	else
	{
		len_zip = load_image_file(pmi->source, itype, NULL, MAX_LONG);
		buf_zip = (byte_t*)xmem_alloc(len_zip);
		load_image_file(pmi->source, NULL, buf_zip, len_zip);

		if (xsicmp(itype, GDI_ATTR_IMAGE_TYPE_JPG) == 0)
		{
			len_bmp = xjpg_decompress(buf_zip, len_zip, NULL, MAX_LONG);
			buf_bmp = (byte_t*)xmem_alloc(len_bmp);
			xjpg_decompress(buf_zip, len_zip, buf_bmp, len_bmp);

			xmem_free(buf_zip);
		}
		else if (xsicmp(pmi->type, GDI_ATTR_IMAGE_TYPE_PNG) == 0)
		{
			len_bmp = xpng_decompress(buf_zip, len_zip, NULL, MAX_LONG);
			buf_bmp = (byte_t*)xmem_alloc(len_bmp);
			xpng_decompress(buf_zip, len_zip, buf_bmp, len_bmp);

			xmem_free(buf_zip);
		}
		else
		{
			len_bmp = len_zip;
			buf_bmp = buf_zip;
		}
	}

	if (RGB_GRAY(xc.r, xc.g, xc.b) < 248)
	{
		buf_zip = buf_bmp;
		len_zip = len_bmp;

		len_bmp = xbmp_convgray(buf_zip, len_zip, NULL, MAX_LONG);
		buf_bmp = (byte_t*)xmem_alloc(len_bmp);
		xbmp_convgray(buf_zip, len_zip, buf_bmp, len_bmp);

		xmem_free(buf_zip);
	}

	xbmp_get_size(buf_bmp, len_bmp, &xs);
	xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));
	pt_adjust_rect(&xr, xs.w, xs.h, GDI_ATTR_TEXT_ALIGN_CENTER, GDI_ATTR_TEXT_ALIGN_CENTER);

	(*(pgc->device->drawBitmap))(pgc->handle, xr.x, xr.y, xr.w, xr.h, buf_bmp, pgc->rop);

	xmem_free(buf_bmp);
}


void mgc_draw_image(canvas_t canv, const ximage_t *pxi, const xrect_t *pxr)
{
	visual_t view;
	xrect_t xr;

	if (is_null(pxi->source))
		return;

	view = mgc_get_canvas_visual(canv);

	xr.fx = pxr->fx;
	xr.fy = pxr->fy;
	xr.fw = pxr->fw;
	xr.fh = pxr->fh;

	mgc_rect_tm_to_pt(canv, &xr);

	mgc_draw_image_raw(view, pxi, &xr);
}
