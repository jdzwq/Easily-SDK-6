/***********************************************************************
	Easily SDK v6.0

	(c) 2005-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc 2D coordinate space document

	@module	g2_trans.c | implement file

	@devnote 张文权 2021.01 - 2021.12 v6.0
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

#include "g2.h"

#include "../xdkstd.h"
#include "../xdkinit.h"


bool_t pt_inside(int x, int y, int x1, int y1, int x2, int y2)
{
	int minx, maxx, miny, maxy;

	minx = (x1 < x2) ? x1 : x2;
	maxx = (x1 > x2) ? x1 : x2;
	miny = (y1 < y2) ? y1 : y2;
	maxy = (y1 > y2) ? y1 : y2;

	return (x >= minx && x <= maxx && y >= miny && y <= maxy) ? 1 : 0;
}

bool_t ft_inside(float x, float y, float x1, float y1, float x2, float y2)
{
	float minx, maxx, miny, maxy;

	minx = (x1 < x2) ? x1 : x2;
	maxx = (x1 > x2) ? x1 : x2;
	miny = (y1 < y2) ? y1 : y2;
	maxy = (y1 > y2) ? y1 : y2;

	return (x >= minx && x <= maxx && y >= miny && y <= maxy) ? 1 : 0;
}

bool_t pt_in_rect(const xpoint_t* ppt, const xrect_t* pxr)
{
	return pt_inside(ppt->x, ppt->y, pxr->x, pxr->y, pxr->x + pxr->w, pxr->y + pxr->h);
}


bool_t ft_in_rect(const xpoint_t* ppt, const xrect_t* pxr)
{
	return ft_inside(ppt->fx, ppt->fy, pxr->fx, pxr->fy, pxr->fx + pxr->fw, pxr->fy + pxr->fh);
}

void ft_offset_point(xpoint_t* ppt, float cx, float cy)
{
	ppt->fx += cx;
	ppt->fy += cy;
}

void pt_offset_point(xpoint_t* ppt, int cx, int cy)
{
	ppt->x += cx;
	ppt->y += cy;
}

void ft_center_rect(xrect_t* pxr, float cx, float cy)
{
	pxr->fx += (pxr->fw - cx) / 2;
	pxr->fw = cx;
	pxr->fy += (pxr->fh - cy) / 2;
	pxr->fh = cy;
}

void pt_center_rect(xrect_t* pxr, int cx, int cy)
{
	pxr->x += (pxr->w - cx) / 2;
	pxr->w = cx;
	pxr->y += (pxr->h - cy) / 2;
	pxr->h = cy;
}

void pt_expand_rect(xrect_t* pxr, int cx, int cy)
{
	pxr->x -= cx;
	pxr->w += cx * 2;
	pxr->y -= cy;
	pxr->h += cy * 2;
}

void ft_expand_rect(xrect_t* pxr, float cx, float cy)
{
	pxr->fx -= cx;
	pxr->fw += cx * 2;
	pxr->fy -= cy;
	pxr->fh += cy * 2;
}

void pt_offset_rect(xrect_t* pxr, int cx, int cy)
{
	pxr->x += cx;
	pxr->y += cy;
}

void ft_offset_rect(xrect_t* pxr, float cx, float cy)
{
	pxr->fx += cx;
	pxr->fy += cy;
}

void ft_merge_rect(xrect_t* pxr, const xrect_t* pxr_nxt)
{
	float left, top, right, bottom;

	left = (pxr->fx < pxr_nxt->fx) ? pxr->fx : pxr_nxt->fx;
	top = (pxr->fy < pxr_nxt->fy) ? pxr->fy : pxr_nxt->fy;
	right = (pxr->fx + pxr->fw > pxr_nxt->fx + pxr_nxt->fw) ? (pxr->fx + pxr->fw) : (pxr_nxt->fx + pxr_nxt->fw);
	bottom = (pxr->fy + pxr->fh > pxr_nxt->fy + pxr_nxt->fh) ? (pxr->fy + pxr->fh) : (pxr_nxt->fy + pxr_nxt->fh);

	pxr->fx = left;
	pxr->fy = top;
	pxr->fw = right - left;
	pxr->fh = bottom - top;
}

void pt_merge_rect(xrect_t* pxr, const xrect_t* pxr_nxt)
{
	int left, top, right, bottom;

	left = (pxr->x < pxr_nxt->x) ? pxr->x : pxr_nxt->x;
	top = (pxr->y < pxr_nxt->y) ? pxr->y : pxr_nxt->y;
	right = (pxr->x + pxr->w > pxr_nxt->x + pxr_nxt->w) ? (pxr->x + pxr->w) : (pxr_nxt->x + pxr_nxt->w);
	bottom = (pxr->y + pxr->h > pxr_nxt->y + pxr_nxt->h) ? (pxr->y + pxr->h) : (pxr_nxt->y + pxr_nxt->h);

	pxr->x = left;
	pxr->y = top;
	pxr->w = right - left;
	pxr->h = bottom - top;
}

bool_t ft_clip_rect(xrect_t* pxr, const xrect_t* pxrClp)
{
	if (pxr->fx == pxrClp->fx && pxr->fy == pxrClp->fy)
	{
		if (pxr->fh == pxrClp->fh && pxr->fw > pxrClp->fw)
		{
			pxr->fx += pxrClp->fw;
			return 1;
		}
		else if (pxr->fw == pxrClp->fw && pxr->fh > pxrClp->fh)
		{
			pxr->fy += pxrClp->fh;
			return 1;
		}
	}
	else if (pxr->fx + pxr->fw == pxrClp->fx + pxrClp->fw && pxr->fy + pxr->fh == pxrClp->fy + pxrClp->fh)
	{
		if (pxr->fh == pxrClp->fh && pxr->fw > pxrClp->fw)
		{
			pxr->fw -= pxrClp->fw;
			return 1;
		}
		else if (pxr->fw == pxrClp->fw && pxr->fh > pxrClp->fh)
		{
			pxr->fh -= pxrClp->fh;
			return 1;
		}
	}

	return 0;
}

bool_t pt_clip_rect(xrect_t* pxr, const xrect_t* pxrClp)
{
	if (pxr->x == pxrClp->x && pxr->y == pxrClp->y)
	{
		if (pxr->h == pxrClp->h && pxr->w > pxrClp->w)
		{
			pxr->x += pxrClp->w;
			return 1;
		}
		else if (pxr->w == pxrClp->w && pxr->h > pxrClp->h)
		{
			pxr->y += pxrClp->h;
			return 1;
		}
	}
	else if (pxr->x + pxr->w == pxrClp->x + pxrClp->w && pxr->y + pxr->h == pxrClp->y + pxrClp->h)
	{
		if (pxr->h == pxrClp->h && pxr->w > pxrClp->w)
		{
			pxr->w -= pxrClp->w;
			return 1;
		}
		else if (pxr->w == pxrClp->w && pxr->h > pxrClp->h)
		{
			pxr->h -= pxrClp->h;
			return 1;
		}
	}

	return 0;
}

void ft_inter_rect(xrect_t* pxr, const xrect_t* pxr_sub)
{
	if (pxr->fx < pxr_sub->fx)
	{
		pxr->fx = pxr_sub->fx;
		pxr->fw -= (pxr_sub->fx - pxr->fx);
	}
	else
	{
		pxr->fw += (pxr_sub->fx - pxr->fx);
	}

	if (pxr->fy < pxr_sub->fy)
	{
		pxr->fy = pxr_sub->fy;
		pxr->fh -= (pxr_sub->fy - pxr->fy);
	}
	else
	{
		pxr->fh += (pxr_sub->fy - pxr->fy);
	}
}

void pt_inter_rect(xrect_t* pxr, const xrect_t* pxr_sub)
{
	if (pxr->x < pxr_sub->x)
	{
		pxr->x = pxr_sub->x;
		pxr->w -= (pxr_sub->x - pxr->x);
	}
	else
	{
		pxr->w += (pxr_sub->x - pxr->x);
	}

	if (pxr->y < pxr_sub->y)
	{
		pxr->y = pxr_sub->y;
		pxr->h -= (pxr_sub->y - pxr->y);
	}
	else
	{
		pxr->h += (pxr_sub->y - pxr->y);
	}
}

void ft_inter_square(xrect_t* pxr, const xrect_t* pxr_org)
{
	xpoint_t pt;
	float r;

	pt.fx = pxr_org->fx + pxr_org->fw / 2;
	pt.fy = pxr_org->fy + pxr_org->fh / 2;

	r = (pxr_org->fw < pxr_org->fh) ? pxr_org->fw / 2 : pxr_org->fh / 2;

	pxr->fx = pt.fx - r;
	pxr->fy = pt.fy - r;
	pxr->fw = 2 * r;
	pxr->fh = 2 * r;
}

void pt_inter_square(xrect_t* pxr, const xrect_t* pxr_org)
{
	xpoint_t pt;
	int r;

	pt.x = pxr_org->x + pxr_org->w / 2;
	pt.y = pxr_org->y + pxr_org->h / 2;

	r = (pxr_org->w < pxr_org->h) ? pxr_org->w / 2 : pxr_org->h / 2;

	pxr->x = pt.x - r;
	pxr->y = pt.y - r;
	pxr->w = 2 * r;
	pxr->h = 2 * r;
}

void ft_cell_rect(xrect_t* pxr, bool_t horz, int rows, int cols, int index)
{
	int row, col;

	if (horz)
	{
		row = index / cols;
		col = index % cols;
	}
	else
	{
		col = index / rows;
		row = index % rows;
	}

	pxr->fx += pxr->fw * col / cols;
	pxr->fw = pxr->fw / cols;
	pxr->fy += pxr->fh * row / rows;
	pxr->fh = pxr->fh / rows;
}

void pt_cell_rect(xrect_t* pxr, bool_t horz, int rows, int cols, int index)
{
	int row, col;

	if (horz)
	{
		row = index / cols;
		col = index % cols;
	}
	else
	{
		col = index / rows;
		row = index % rows;
	}

	pxr->x += pxr->w * col / cols;
	pxr->w = pxr->w / cols;
	pxr->y += pxr->h * row / rows;
	pxr->h = pxr->h / rows;
}

void empty_rect(xrect_t* pxr)
{
	pxr->fx = pxr->fy = pxr->fw = pxr->fh = 0;
}

bool_t rect_is_empty(const xrect_t* pxr)
{
	return (!pxr->w || !pxr->h) ? 1 : 0;
}

void pt_adjust_rect(xrect_t* pxr, int src_width, int src_height, const tchar_t* horz_align, const tchar_t* vert_align)
{
	if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		pxr->w = (pxr->w < src_width) ? pxr->w : src_width;
	}
	else if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		pxr->x = (pxr->w < src_width) ? pxr->x : (pxr->x + (pxr->w - src_width) / 2);
	}
	else if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		pxr->x = (pxr->w < src_width) ? pxr->x : (pxr->x + pxr->w - src_width);
	}

	if (xscmp(vert_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		pxr->h = (pxr->h < src_height) ? pxr->h : src_height;
	}
	else if (xscmp(vert_align, GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		pxr->y = (pxr->h < src_height) ? pxr->y : (pxr->y + (pxr->h - src_height) / 2);
	}
	else if (xscmp(vert_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		pxr->y = (pxr->h < src_height) ? pxr->y : (pxr->y + pxr->h - src_height);
	}
}

void ft_adjust_rect(xrect_t* pxr, float src_width, float src_height, const tchar_t* horz_align, const tchar_t* vert_align)
{
	if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		pxr->fw = (pxr->fw < src_width) ? pxr->fw : src_width;
	}
	else if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		pxr->fx = (pxr->fw < src_width) ? pxr->fx : (pxr->fx + (pxr->fw - src_width) / 2);
	}
	else if (xscmp(horz_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		pxr->fx = (pxr->fw < src_width) ? pxr->fx : (pxr->fx + pxr->fw - src_width);
	}

	if (xscmp(vert_align, GDI_ATTR_TEXT_ALIGN_NEAR) == 0)
	{
		pxr->fh = (pxr->fh < src_height) ? pxr->fh : src_height;
	}
	else if (xscmp(vert_align, GDI_ATTR_TEXT_ALIGN_CENTER) == 0)
	{
		pxr->fy = (pxr->fh < src_height) ? pxr->fy : (pxr->fy + (pxr->fh - src_height) / 2);
	}
	else if (xscmp(vert_align, GDI_ATTR_TEXT_ALIGN_FAR) == 0)
	{
		pxr->fy = (pxr->fh < src_height) ? pxr->fy : (pxr->fy + pxr->fh - src_height);
	}
}

void pt_gravity_point(const xpoint_t* ppt, int n, xpoint_t* pg)
{
	int i;
	int x = 0, y = 0;

	for (i = 0; i < n; i++)
	{
		x += ppt[i].x;
		y += ppt[i].y;
	}

	pg->x = x / n;
	pg->y = y / n;
}

void ft_gravity_point(const xpoint_t* ppt, int n, xpoint_t* pg)
{
	int i;
	float fx = 0, fy = 0;

	for (i = 0; i < n; i++)
	{
		fx += ppt[i].fx;
		fy += ppt[i].fy;
	}

	pg->fx = (float)(fx / n);
	pg->fy = (float)(fy / n);
}

void pt_polygon_rect(const xpoint_t* ppt, int n, xrect_t* pr)
{
	int i;
	int minx = MAX_LONG, miny = MAX_LONG, maxx = -MAX_LONG, maxy = -MAX_LONG;

	for (i = 0; i < n; i++)
	{
		minx = (minx < ppt[i].x) ? minx : ppt[i].x;
		miny = (miny < ppt[i].y) ? miny : ppt[i].y;
		maxx = (maxx > ppt[i].x) ? maxx : ppt[i].x;
		maxy = (maxy > ppt[i].y) ? maxy : ppt[i].y;
	}

	pr->x = minx;
	pr->y = miny;
	pr->w = maxx - minx;
	pr->h = maxy - miny;
}


void ft_polygon_rect(const xpoint_t* ppt, int n, xrect_t* pr)
{
	int i;
	float minx = MAXFLT, miny = MAXFLT, maxx = MINFLT, maxy = MINFLT;

	for (i = 0; i < n; i++)
	{
		minx = (minx < ppt[i].fx) ? minx : ppt[i].fx;
		miny = (miny < ppt[i].fy) ? miny : ppt[i].fy;
		maxx = (maxx > ppt[i].fx) ? maxx : ppt[i].fx;
		maxy = (maxy > ppt[i].fy) ? maxy : ppt[i].fy;
	}

	pr->fx = minx;
	pr->fy = miny;
	pr->fw = maxx - minx;
	pr->fh = maxy - miny;
}