﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc docker document

	@module	docker.c | implement file

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

#include "docker.h"

#include "../xdcimp.h"
#include "../xdcinit.h"

#define DOCKER_SPLIT_SPAN		(int)10 //pt


static int _docker_calc_hint(docker_t* ptd, const xpoint_t* pxp)
{
	xrect_t xr,xr_cli;
	int top, bottom, left, right;
	int span;
	int i;

	widget_get_client_rect(ptd->widget, &xr_cli);

	span = DOCKER_SPLIT_SPAN;
	top = bottom = left = right = 0;

	for (i = 0; i < 4; i++)
	{
		if (ptd->dock[i].style & WS_DOCK_LEFT)
		{
			xr.x = xr_cli.x;
			xr.w = ptd->dock[i].cx;
			xr.y = xr_cli.y + top;
			xr.h = xr_cli.h - top - bottom;

			if ((ptd->dock[i].style & WS_DOCK_DYNA) && pt_inside(pxp->x, pxp->y, xr.x + xr.w, xr.y, xr.x + xr.w + span, xr.y + xr.h))
				return i;

			if (ptd->dock[i].style & WS_DOCK_DYNA)
				left += (ptd->dock[i].cx + span);
			else
				left += ptd->dock[i].cx;
		}
		else if (ptd->dock[i].style & WS_DOCK_TOP)
		{
			xr.x = xr_cli.x + left;
			xr.w = xr_cli.w - left - right;
			xr.y = xr_cli.y;
			xr.h = ptd->dock[i].cy;

			if ((ptd->dock[i].style & WS_DOCK_DYNA) && pt_inside(pxp->x, pxp->y, xr.x, xr.y + xr.h, xr.x + xr.w, xr.y + xr.h + span))
				return i;

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
				top += (ptd->dock[i].cy + span);
			else
				top += ptd->dock[i].cy;
		}
		else if (ptd->dock[i].style & WS_DOCK_RIGHT)
		{
			xr.x = xr_cli.x + xr_cli.w - ptd->dock[i].cx;
			xr.w = ptd->dock[i].cx;
			xr.y = xr_cli.y + top;
			xr.h = xr_cli.h - top - bottom;

			if ((ptd->dock[i].style & WS_DOCK_DYNA) && pt_inside(pxp->x, pxp->y, xr.x - span, xr.y, xr.x, xr.y + xr.h))
				return i;

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
				right += (ptd->dock[i].cx + span);
			else
				right += ptd->dock[i].cx;
		}
		else if (ptd->dock[i].style & WS_DOCK_BOTTOM)
		{
			xr.x = xr_cli.x + left;
			xr.w = xr_cli.w - left - right;
			xr.y = xr_cli.y + xr_cli.h - ptd->dock[i].cy;
			xr.h = ptd->dock[i].cy;

			if ((ptd->dock[i].style & WS_DOCK_DYNA)  && pt_inside(pxp->x, pxp->y, xr.x, xr.y - span, xr.x + xr.w, xr.y))
				return i;

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
				bottom += (ptd->dock[i].cy + span);
			else
				bottom += ptd->dock[i].cy;
		}
	}

	return -1;
}

void _docker_calc_rect(docker_t* ptd, dword_t style, xrect_t* pxr)
{
	xrect_t xr, xr_cli;
	int top, bottom, left, right, span;
	int i;

	if (!ptd)
		return;

	xmem_zero((void*)pxr, sizeof(xrect_t));

	if (widget_is_minimized(ptd->widget))
		return;

	widget_get_client_rect(ptd->widget, &xr_cli);

	span = DOCKER_SPLIT_SPAN;
	top = bottom = left = right = 0;

	for (i = 0; i < 4; i++)
	{
		if (ptd->dock[i].style & WS_DOCK_LEFT)
		{
			xr.x = xr_cli.x;
			xr.w = ptd->dock[i].cx;
			xr.y = xr_cli.y + top;
			xr.h = xr_cli.h - top - bottom;

			if (ptd->dock[i].style & style)
			{
				xmem_copy((void*)pxr, (void*)&xr, sizeof(xrect_t));
				return;
			}

			if (ptd->dock[i].style & WS_DOCK_DYNA)
				left += (ptd->dock[i].cx + span);
			else
				left += ptd->dock[i].cx;
		}
		else if (ptd->dock[i].style & WS_DOCK_TOP)
		{
			xr.x = xr_cli.x + left;
			xr.w = xr_cli.w - left - right;
			xr.y = xr_cli.y;
			xr.h = ptd->dock[i].cy;

			if (ptd->dock[i].style & style)
			{
				xmem_copy((void*)pxr, (void*)&xr, sizeof(xrect_t));
				return;
			}

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
				top += (ptd->dock[i].cy + span);
			else
				top += ptd->dock[i].cy;
		}
		else if (ptd->dock[i].style & WS_DOCK_RIGHT)
		{
			xr.x = xr_cli.x + xr_cli.w - ptd->dock[i].cx;
			xr.w = ptd->dock[i].cx;
			xr.y = xr_cli.y + top;
			xr.h = xr_cli.h - top - bottom;

			if (ptd->dock[i].style & style)
			{
				xmem_copy((void*)pxr, (void*)&xr, sizeof(xrect_t));
				return;
			}

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
				right += (ptd->dock[i].cx + span);
			else
				right += ptd->dock[i].cx;
		}
		else if (ptd->dock[i].style & WS_DOCK_BOTTOM)
		{
			xr.x = xr_cli.x + left;
			xr.w = xr_cli.w - left - right;
			xr.y = xr_cli.y + xr_cli.h - ptd->dock[i].cy;
			xr.h = ptd->dock[i].cy;

			if (ptd->dock[i].style & style)
			{
				xmem_copy((void*)pxr, (void*)&xr, sizeof(xrect_t));
				return;
			}

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
				bottom += (ptd->dock[i].cy + span);
			else
				bottom += ptd->dock[i].cy;
		}
	}

	pxr->x = xr_cli.x + left;
	pxr->y = xr_cli.y + top ;
	pxr->w = xr_cli.w - left - right;
	pxr->h = xr_cli.h - top - bottom ;
}

/*************************************************************************************************/

void hand_docker_mouse_move(docker_t* ptd, dword_t dw, const xpoint_t* pxp)
{
	int hint;

	if (ptd->drag)
		return;

	hint = _docker_calc_hint(ptd, pxp);

	if (hint >= 0)
		widget_set_cursor(ptd->widget, CURSOR_HAND);
	else
		widget_set_cursor(ptd->widget, CURSOR_ARROW);
}

void hand_docker_lbutton_down(docker_t* ptd, const xpoint_t* pxp)
{
	ptd->ind = _docker_calc_hint(ptd, pxp);

	if (ptd->ind >= 0)
	{
		ptd->drag = 1;
		ptd->x = pxp->x;
		ptd->y = pxp->y;

		switch (ptd->dock[ptd->ind].style & 0x0000FFFF)
		{
		case WS_DOCK_LEFT:
		case WS_DOCK_RIGHT:
			widget_set_cursor(ptd->widget, CURSOR_SIZEWE);
			break;
		case WS_DOCK_TOP:
		case WS_DOCK_BOTTOM:
			widget_set_cursor(ptd->widget, CURSOR_SIZENS);
			break;
		}

		widget_set_capture(ptd->widget, 1);
	}

}

void hand_docker_lbutton_up(docker_t* ptd, const xpoint_t* pxp)
{
	xrect_t xr;
	int span = DOCKER_SPLIT_SPAN;

	if (ptd->drag)
	{
		widget_set_capture(ptd->widget, 0);

		switch (ptd->dock[ptd->ind].style & 0x0000FFFF)
		{
		case WS_DOCK_LEFT:
			ptd->dock[ptd->ind].cx += (pxp->x - ptd->x);
			break;
		case WS_DOCK_RIGHT:
			ptd->dock[ptd->ind].cx -= (pxp->x - ptd->x);
			break;
		case WS_DOCK_TOP:
			ptd->dock[ptd->ind].cy += (pxp->y - ptd->y);
			break;
		case WS_DOCK_BOTTOM:
			ptd->dock[ptd->ind].cy -= (pxp->y - ptd->y);
			break;
		}

		widget_get_client_rect(ptd->widget, &xr);

		if (ptd->dock[ptd->ind].cx < 0)
			ptd->dock[ptd->ind].cx = 0;
		if (ptd->dock[ptd->ind].cx > xr.w - span)
			ptd->dock[ptd->ind].cx = xr.w - span;

		if (ptd->dock[ptd->ind].cy < 0)
			ptd->dock[ptd->ind].cy = 0;
		if (ptd->dock[ptd->ind].cy > xr.h - span)
			ptd->dock[ptd->ind].cy = xr.h - span;

		ptd->drag = 0;
		ptd->x = pxp->x;
		ptd->y = pxp->y;
		ptd->ind = -1;

		widget_layout(ptd->widget);
	}
}

void hand_docker_paint(docker_t* ptd, visual_t dc, const xrect_t* pxr)
{
	xrect_t xr, xr_cli, xr_bar;
	int top, bottom, left, right, span;
	xbrush_t xb = { 0 };
	xcolor_t xc_brim, xc_core;
	int i;

	visual_t rdc;
	canvas_t canv;
	drawing_interface ifv = {0};

	widget_get_xbrush(ptd->widget, &xb);

	parse_xcolor(&xc_brim, xb.color);
	parse_xcolor(&xc_core, xb.color);
	lighten_xcolor(&xc_core, DEF_SOFT_DARKEN);

	widget_get_client_rect(ptd->widget, &xr_cli);

	canv = widget_get_canvas(ptd->widget);

	XDK_ASSERT(canv != NULL);

	rdc = begin_canvas_paint(canv, dc, xr_cli.w, xr_cli.h);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr_cli);

	span = DOCKER_SPLIT_SPAN;
	top = bottom = left = right = 0;

	for (i = 0; i < 4; i++)
	{
		if (ptd->dock[i].style & WS_DOCK_LEFT)
		{
			xr.x = xr_cli.x;
			xr.w = ptd->dock[i].cx;
			xr.y = xr_cli.y + top;
			xr.h = xr_cli.h - top - bottom;

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
			{
				xr_bar.x = xr.x + xr.w;
				xr_bar.w = span;
				xr_bar.y = xr.y;
				xr_bar.h = xr.h;

				(*ifv.pf_gradient_rect)(ifv.ctx, &xc_brim, &xc_core, GDI_ATTR_GRADIENT_HORZ, &xr_bar);
			}

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
				left += (ptd->dock[i].cx + span);
			else
				left += ptd->dock[i].cx;
		}
		else if (ptd->dock[i].style & WS_DOCK_TOP)
		{
			xr.x = xr_cli.x + left;
			xr.w = xr_cli.w - left - right;
			xr.y = xr_cli.y;
			xr.h = ptd->dock[i].cy;

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
			{
				xr_bar.x = xr.x;
				xr_bar.w = xr.w;
				xr_bar.y = xr.y + xr.h;
				xr_bar.h = span;

				(*ifv.pf_gradient_rect)(ifv.ctx, &xc_brim, &xc_core, GDI_ATTR_GRADIENT_VERT, &xr_bar);
			}

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
				top += (ptd->dock[i].cy + span);
			else
				top += ptd->dock[i].cy;
		}
		else if (ptd->dock[i].style & WS_DOCK_RIGHT)
		{
			xr.x = xr_cli.x + xr_cli.w - ptd->dock[i].cx;
			xr.w = ptd->dock[i].cx;
			xr.y = xr_cli.y + top;
			xr.h = xr_cli.h - top - bottom;

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
			{
				xr_bar.x = xr.x - span;
				xr_bar.w = span;
				xr_bar.y = xr.y;
				xr_bar.h = xr.h;

				(*ifv.pf_gradient_rect)(ifv.ctx, &xc_brim, &xc_core, GDI_ATTR_GRADIENT_HORZ, &xr_bar);
			}

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
				right += (ptd->dock[i].cx + span);
			else
				right += ptd->dock[i].cx;
		}
		else if (ptd->dock[i].style & WS_DOCK_BOTTOM)
		{
			xr.x = xr_cli.x + left;
			xr.w = xr_cli.w - left - right;
			xr.y = xr_cli.y + xr_cli.h - ptd->dock[i].cy;
			xr.h = ptd->dock[i].cy;

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
			{
				xr_bar.x = xr.x;
				xr_bar.w = xr.w;
				xr_bar.y = xr.y - span;
				xr_bar.h = span;

				(*ifv.pf_gradient_rect)(ifv.ctx, &xc_brim, &xc_core, GDI_ATTR_GRADIENT_VERT, &xr_bar);
			}

			if ((ptd->dock[i].style & WS_DOCK_DYNA))
				bottom += (ptd->dock[i].cy + span);
			else
				bottom += ptd->dock[i].cy;
		}
	}

	

	end_canvas_paint(canv, dc, pxr);
}

void hand_docker_calc_rect(docker_t* ptd, dword_t style, xrect_t* pxr)
{
	_docker_calc_rect(ptd, style, pxr);
}

