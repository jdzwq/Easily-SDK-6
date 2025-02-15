/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc mgc canvas document

	@module	mgccanv.c | implement file

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

#include "../xdkimp.h"
#include "../xdkstd.h"
#include "../xdkinit.h"

typedef struct _mgc_canvas_t{
	handle_head head;

	visual_t view;
}mgc_canvas_t;

canvas_t create_mgc_canvas(visual_t view)
{
	mgc_canvas_t* pcanv;

	pcanv = (mgc_canvas_t*)xmem_alloc(sizeof(mgc_canvas_t));

	pcanv->view = view;
	pcanv->head.tag = _CANVAS_PRINTER;

	return &pcanv->head;
}

void destroy_mgc_canvas(canvas_t canv)
{
	mgc_canvas_t* pcanv = TypePtrFromHead(mgc_canvas_t, canv);

	XDK_ASSERT(canv && canv->tag == _CANVAS_PRINTER);

	xmem_free(pcanv);
}

visual_t mgc_get_canvas_visual(canvas_t canv)
{
	mgc_canvas_t* pcanv = TypePtrFromHead(mgc_canvas_t, canv);

	XDK_ASSERT(canv && canv->tag == _CANVAS_PRINTER);

	return pcanv->view;
}

void mgc_rect_tm_to_pt(canvas_t canv, xrect_t* pxr)
{
	int left, right, top, bottom;

	if (pxr->fw < 0)
	{
		left = mgc_tm_to_pt(canv, pxr->fx + pxr->fw, 1);
		right = mgc_tm_to_pt(canv, pxr->fx, 1);
	}
	else
	{
		left = mgc_tm_to_pt(canv, pxr->fx, 1);
		right = mgc_tm_to_pt(canv, pxr->fx + pxr->fw, 1);
	}

	if (pxr->fh < 0)
	{
		top = mgc_tm_to_pt(canv, pxr->fy + pxr->fh, 0);
		bottom = mgc_tm_to_pt(canv, pxr->fy, 0);
	}
	else
	{
		top = mgc_tm_to_pt(canv, pxr->fy, 0);
		bottom = mgc_tm_to_pt(canv, pxr->fy + pxr->fh, 0);
	}

	pxr->x = left;
	pxr->y = top;
	pxr->w = right - left;
	pxr->h = bottom - top;
}

void mgc_rect_pt_to_tm(canvas_t canv, xrect_t* pxr)
{
	float left, right, top, bottom;

	if (pxr->w < 0)
	{
		left = mgc_pt_to_tm(canv, pxr->x + pxr->w, 1);
		right = mgc_pt_to_tm(canv, pxr->x, 1);
	}
	else
	{
		left = mgc_pt_to_tm(canv, pxr->x, 1);
		right = mgc_pt_to_tm(canv, pxr->x + pxr->w, 1);
	}

	if (pxr->h < 0)
	{
		top = mgc_pt_to_tm(canv, pxr->y + pxr->h, 0);
		bottom = mgc_pt_to_tm(canv, pxr->y, 0);
	}
	else
	{
		top = mgc_pt_to_tm(canv, pxr->y, 0);
		bottom = mgc_pt_to_tm(canv, pxr->y + pxr->h, 0);
	}

	pxr->fx = left;
	pxr->fy = top;
	pxr->fw = right - left;
	pxr->fh = bottom - top;
}

void mgc_size_tm_to_pt(canvas_t canv, xsize_t* pxs)
{
	int cx, cy;

	cx = mgc_tm_to_pt(canv, pxs->fw, 1) - mgc_tm_to_pt(canv, 0, 1);
	cy = mgc_tm_to_pt(canv, pxs->fh, 0) - mgc_tm_to_pt(canv, 0, 0);

	pxs->w = cx;
	pxs->h = cy;
}

void mgc_size_pt_to_tm(canvas_t canv, xsize_t* pxs)
{
	float cx, cy;

	cx = mgc_pt_to_tm(canv, pxs->w, 1) - mgc_pt_to_tm(canv, 0, 1);
	cy = mgc_pt_to_tm(canv, pxs->h, 0) - mgc_pt_to_tm(canv, 0, 0);

	pxs->fw = cx;
	pxs->fh = cy;
}

void mgc_point_tm_to_pt(canvas_t canv, xpoint_t* ppt)
{
	int x, y;

	x = mgc_tm_to_pt(canv, ppt->fx, 1);
	y = mgc_tm_to_pt(canv, ppt->fy, 0);

	ppt->x = x;
	ppt->y = y;
}

void mgc_point_pt_to_tm(canvas_t canv, xpoint_t* ppt)
{
	float x, y;

	x = mgc_pt_to_tm(canv, ppt->x, 1);
	y = mgc_pt_to_tm(canv, ppt->y, 0);

	ppt->fx = x;
	ppt->fy = y;
}

void mgc_span_tm_to_pt(canvas_t canv, xspan_t* ppn)
{
	ppn->s = mgc_tm_to_pt(canv, ppn->fs, 1) - mgc_tm_to_pt(canv, 0, 1);
}

void mgc_span_pt_to_tm(canvas_t canv, xspan_t* ppn)
{
	ppn->fs = mgc_pt_to_tm(canv, ppn->s, 1) - mgc_pt_to_tm(canv, 0, 1);
}

