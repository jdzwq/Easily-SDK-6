/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc focus document

	@module	focusing.c | implement file

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

#include "focusing.h"

#include "../xdlgdi.h"

void draw_select_raw(const drawing_interface* pvi, const xcolor_t* pxc, const xrect_t* prt, int deep)
{
	xpen_t xp;

	default_xpen(&xp);
	format_xcolor(pxc, xp.color);
	xsprintf(xp.opacity, _T("%d"), deep);
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_DASH);

	(*pvi->drw->pf_draw_rect)(pvi->ctx, &xp, NULL, prt);
}

void draw_focus_raw(const drawing_interface* pvi, const xcolor_t* pxc, const xrect_t* prt, int deep)
{
	(*pvi->drw->pf_alphablend_rect)(pvi->ctx, pxc, prt, deep);
}

void draw_sizing_raw(const drawing_interface* pvi, const xcolor_t* pxc, const xrect_t* prt, int deep, dword_t pos)
{
	xrect_t xr;
	xpen_t xp;
	xbrush_t xb;

	default_xpen(&xp);
	default_xbrush(&xb);
	format_xcolor(pxc, xp.color);
	format_xcolor(pxc, xb.color);
	xsprintf(xp.opacity, _T("%d"), deep);
	xscpy(xp.style, GDI_ATTR_STROKE_STYLE_DASHDASH);

	xr.x = prt->x - 4;
	xr.y = prt->y - 4;
	xr.w = prt->w + 8;
	xr.h = prt->h + 8;

	//(*pvi->drw->pf_draw_rect)(pvi->ctx, &xp, NULL, &xr);

	if (pos & SIZING_TOPLEFT)
	{
		xr.x = prt->x - 4;
		xr.y = prt->y - 4;
		xr.w = 8;
		xr.h = 8;

		(*pvi->drw->pf_draw_rect)(pvi->ctx, &xp, &xb, &xr);
	}

	if (pos & SIZING_TOPCENTER)
	{
		xr.x = prt->x + prt->w / 2 - 4;
		xr.y = prt->y - 4;
		xr.w = 8;
		xr.h = 8;

		(*pvi->drw->pf_draw_rect)(pvi->ctx, &xp, &xb, &xr);
	}

	if (pos & SIZING_TOPRIGHT)
	{
		xr.x = prt->x + prt->w - 4;
		xr.y = prt->y - 4;
		xr.w = 8;
		xr.h = 8;

		(*pvi->drw->pf_draw_rect)(pvi->ctx, &xp, &xb, &xr);
	}

	if (pos & SIZING_BOTTOMLEFT)
	{
		xr.x = prt->x - 4;
		xr.y = prt->y + prt->h - 4;
		xr.w = 8;
		xr.h = 8;

		(*pvi->drw->pf_draw_rect)(pvi->ctx, &xp, &xb, &xr);
	}

	if (pos & SIZING_BOTTOMCENTER)
	{
		xr.x = prt->x + prt->w / 2 - 4;
		xr.y = prt->y + prt->h - 4;
		xr.w = 8;
		xr.h = 8;

		(*pvi->drw->pf_draw_rect)(pvi->ctx, &xp, &xb, &xr);
	}

	if (pos & SIZING_BOTTOMRIGHT)
	{
		xr.x = prt->x + prt->w - 4;
		xr.y = prt->y + prt->h - 4;
		xr.w = 8;
		xr.h = 8;

		(*pvi->drw->pf_draw_rect)(pvi->ctx, &xp, &xb, &xr);
	}

	if (pos & SIZING_LEFTCENTER)
	{
		xr.x = prt->x - 4;
		xr.y = prt->y + prt->h / 2 - 4;
		xr.w = 8;
		xr.h = 8;

		(*pvi->drw->pf_draw_rect)(pvi->ctx, &xp, &xb, &xr);
	}

	if (pos & SIZING_RIGHTCENTER)
	{
		xr.x = prt->x + prt->w - 4;
		xr.y = prt->y + prt->h / 2 - 4;
		xr.w = 8;
		xr.h = 8;

		(*pvi->drw->pf_draw_rect)(pvi->ctx, &xp, &xb, &xr);
	}
}

void draw_feed_raw(const drawing_interface* pvi, const xcolor_t* pxc, const xrect_t* prt, int deep)
{
	xpoint_t pt[2];
	xpen_t xp;

	default_xpen(&xp);
	format_xcolor(pxc, xp.color);

	xsprintf(xp.opacity, _T("%d"), deep);
	//xp.adorn.feed = 2;
	//xp.adorn.size = 2;

	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x;
	pt[1].y = prt->y + 5;
	(*pvi->drw->pf_draw_line)(pvi->ctx, &xp, &pt[0], &pt[1]);

	pt[0].x = prt->x;
	pt[0].y = prt->y;
	pt[1].x = prt->x + 5;
	pt[1].y = prt->y;
	(*pvi->drw->pf_draw_line)(pvi->ctx, &xp, &pt[0], &pt[1]);

	pt[0].x = prt->x + prt->w;
	pt[0].y = prt->y + prt->h;
	pt[1].x = prt->x + prt->w - 5;
	pt[1].y = prt->y + prt->h;
	(*pvi->drw->pf_draw_line)(pvi->ctx, &xp, &pt[0], &pt[1]);

	pt[0].x = prt->x + prt->w;
	pt[0].y = prt->y + prt->h;
	pt[1].x = prt->x + prt->w;
	pt[1].y = prt->y + prt->h - 5;
	(*pvi->drw->pf_draw_line)(pvi->ctx, &xp, &pt[0], &pt[1]);
}

