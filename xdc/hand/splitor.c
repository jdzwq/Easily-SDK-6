﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc splitor document

	@module	splitor.c | implement file

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

#include "splitor.h"

#include "../xdcimp.h"
#include "../xdcinit.h"

static bool_t _splitor_item_resize(link_t_ptr ilk, void* pv)
{
	res_win_t owner, win;
	xrect_t xr;

	if (get_split_item_splited(ilk))
		return 1;

	owner = (res_win_t)(pv);

	xr.fx = get_split_item_x(ilk);
	xr.fw = get_split_item_width(ilk);
	xr.fy = get_split_item_y(ilk);
	xr.fh = get_split_item_height(ilk);

	widget_rect_to_pt(owner, &xr);

	win = (res_win_t)get_split_item_delta(ilk);

	if (widget_is_valid(win))
	{
		widget_move(win, RECTPOINT(&xr));
		widget_size(win, RECTSIZE(&xr));
		widget_update(win);
	}

	return 1;
}

/************************************************************************************/

void noti_splitor_item_sizing(splitor_t* ptd, link_t_ptr ilk, const xpoint_t* pxp)
{
	bool_t bHorz;

	ptd->item = ilk;
	ptd->x = pxp->x;
	ptd->y = pxp->y;

	bHorz = (compare_text(get_split_item_layer_ptr(ptd->item), -1, ATTR_LAYER_HORZ, -1, 1) == 0) ? 1 : 0;

	if (bHorz)
		widget_set_cursor(ptd->widget, CURSOR_SIZENS);
	else
		widget_set_cursor(ptd->widget, CURSOR_SIZEWE);

}

void noti_splitor_item_sized(splitor_t* ptd, const xpoint_t* pxp)
{
	bool_t bHorz;
	xrect_t xr;
	xsize_t xs;
	xpoint_t pt_org, pt_cur;
	link_t_ptr ilk;

	ilk = ptd->item;
	ptd->item = NULL;

	pt_org.x = ptd->x;
	pt_org.y = ptd->y;
	pt_cur.x = pxp->x;
	pt_cur.y = pxp->y;

	bHorz = (compare_text(get_split_item_layer_ptr(ilk), -1, ATTR_LAYER_HORZ, -1, 1) == 0) ? 1 : 0;

	if (bHorz)
	{
		if (pxp->y == ptd->y)
			return;

		xs.w = 0;
		xs.h = pt_cur.y - pt_org.y;
		widget_size_to_tm(ptd->widget, &xs);

		adjust_split_item(ilk, xs.fh);
	}
	else
	{
		if (pxp->x == ptd->x)
			return;

		xs.w = pt_cur.x - pt_org.x;
		xs.h = 0;
		widget_size_to_tm(ptd->widget, &xs);

		adjust_split_item(ilk, xs.fw);
	}

	calc_split_item_rect(ptd->split, ilk, &xr);
	widget_rect_to_pt(ptd->widget, &xr);

	enum_split_item(ilk, (CALLBACK_ENUMLINK)_splitor_item_resize, ptd->widget);

	widget_erase(ptd->widget, &xr);
}

/*************************************************************************************************/

bool_t hand_splitor_mouse_move(splitor_t* ptd, dword_t dw, const xpoint_t* pxp)
{
	bool_t bHorz;
	link_t_ptr plk;
	int nHint;
	xpoint_t pt;

	XDK_ASSERT(ptd != NULL);

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(ptd->widget, &pt);

	nHint = calc_split_hint(ptd->split, &pt, &plk);

	if (plk && get_split_item_fixed(plk))
	{
		return 1;
	}

	if (nHint == SPLIT_HINT_BAR)
	{
		bHorz = (compare_text(get_split_item_layer_ptr(plk), -1, ATTR_LAYER_HORZ, -1, 1) == 0) ? 1 : 0;
		if (bHorz)
			widget_set_cursor(ptd->widget, CURSOR_SIZENS);
		else
			widget_set_cursor(ptd->widget, CURSOR_SIZEWE);
		
		return 1;
	}
	else
	{
		widget_set_cursor(ptd->widget, CURSOR_ARROW);
		return 0;
	}
}

bool_t hand_splitor_lbutton_down(splitor_t* ptd, const xpoint_t* pxp)
{
	xpoint_t pt;
	int nHint;
	link_t_ptr ilk;

	XDK_ASSERT(ptd != NULL);

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(ptd->widget, &pt);

	nHint = calc_split_hint(ptd->split, &pt, &ilk);

	if (nHint == SPLIT_HINT_BAR)
	{
		if (get_split_item_fixed(ilk))
			return 1;

		widget_set_capture(ptd->widget, 1);

		noti_splitor_item_sizing(ptd, ilk, pxp);

		return 1;
	}

	return 0;
}

bool_t hand_splitor_lbutton_up(splitor_t* ptd, const xpoint_t* pxp)
{
	XDK_ASSERT(ptd != NULL);

	if (ptd->item)
	{ 
		widget_set_capture(ptd->widget, 0);
		noti_splitor_item_sized(ptd, pxp);
		return 1;
	}

	return 0;
}

void hand_splitor_size(splitor_t* ptd, const xrect_t* pxr)
{
	xrect_t xr;

	XDK_ASSERT(ptd->split != NULL);

	xmem_copy((void*)&xr, (void*)pxr, sizeof(xrect_t));
	widget_rect_to_tm(ptd->widget, &xr);

	set_split_item_x(ptd->split, xr.fx);
	set_split_item_y(ptd->split, xr.fy);
	set_split_item_width(ptd->split, xr.fw);
	set_split_item_height(ptd->split, xr.fh);

	resize_split_item(ptd->split);
	enum_split_item(ptd->split, (CALLBACK_ENUMLINK)_splitor_item_resize, ptd->widget);

	widget_erase(ptd->widget, pxr);
}

void hand_splitor_paint(splitor_t* ptd, visual_t rdc)
{
	link_t_ptr ilk;
	link_t_ptr st = NULL;
	xrect_t xr;
	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };
	xcolor_t xc_brim, xc_core;
	drawing_interface ifv = {0};

	XDK_ASSERT(ptd != NULL);

	widget_get_xbrush(ptd->widget, &xb);

	parse_xcolor(&xc_brim, xb.color);
	parse_xcolor(&xc_core, xb.color);
	lighten_xcolor(&xc_core, DEF_SOFT_DARKEN);

	default_xpen(&xp);
	format_xcolor(&xc_brim, xp.color);
	xscpy(xp.size, _T("2"));

	widget_get_client_rect(ptd->widget, &xr);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, &xp, NULL, &xr);

	ilk = ptd->split;
	while (ilk)
	{
		if (get_split_item_splited(ilk))
		{
			calc_split_span_rect(ptd->split, ilk, &xr);
			widget_rect_to_pt(ptd->widget, &xr);

			if (compare_text(get_split_item_layer_ptr(ilk), -1, ATTR_LAYER_HORZ, -1, 1) == 0)
			{
				(*ifv.pf_gradient_rect)(ifv.ctx, &xc_brim, &xc_core, GDI_ATTR_GRADIENT_VERT, &xr);
			}
			else
			{
				(*ifv.pf_gradient_rect)(ifv.ctx, &xc_brim, &xc_core, GDI_ATTR_GRADIENT_HORZ, &xr);
			}
		}

		if (get_split_item_splited(ilk))
		{
			if (!st)
				st = create_stack_table();

			push_stack_node(st, (void*)ilk);

			ilk = get_split_first_child_item(ilk);
			continue;
		}

		while (ilk)
		{
			ilk = get_split_next_sibling_item(ilk);
			if (ilk)
			{
				break;
			}

			ilk = (st) ? (link_t_ptr)pop_stack_node(st) : NULL;
		}
	}

	if (st)
		destroy_stack_table(st);

	
}

