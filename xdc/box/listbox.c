﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc listbox control document

	@module	listbox.c | implement file

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

#include "box.h"

#include "../xdcimp.h"
#include "../xdcinit.h"

typedef struct _listbox_delta_t{
	link_t_ptr string;
	link_t_ptr entity;
}listbox_delta_t;

#define GETLISTBOXDELTA(ph) 	(listbox_delta_t*)widget_get_user_delta(ph)
#define SETLISTBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/***************************************************************************************/
void _listbox_item_rect(res_win_t widget, link_t_ptr ent, xrect_t* pxr)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	xrect_t xr;
	xfont_t xf;
	measure_interface im = { 0 };

	get_canvas_measure(widget_get_canvas(widget), &im);

	widget_get_xfont(widget, &xf);

	calc_listbox_item_rect(&im, &xf, ptd->string, ent, pxr);
	widget_rect_to_pt(widget, pxr);

	widget_get_client_rect(widget, &xr);
	pxr->w = xr.w;
}

void _listbox_reset_page(res_win_t widget)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	int vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;
	xfont_t xf;

	canvas_t canv;
	const drawing_interface* pif = NULL;
	measure_interface im = { 0 };

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);

	(pif->pf_get_measure)(pif->ctx, &im);

	widget_get_xfont(widget, &xf);

	(pif->pf_text_metric)(pif->ctx, &xf, &xs);

	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	calc_listbox_size(&im, &xf, ptd->string, &xs);
	widget_size_to_pt(widget, &xs);
	vw = xs.w;
	vh = xs.h;

	widget_get_client_rect(widget, &xr);

	widget_reset_paging(widget, xr.w, xr.h, vw, vh, lw, lh);

	widget_reset_scroll(widget, 0);

	
}

void _listbox_reset_visible(res_win_t widget)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	xrect_t xr;
	
	if (!ptd->entity)
		return;

	_listbox_item_rect(widget, ptd->entity, &xr);

	widget_ensure_visible(widget, &xr, 1);
}

static link_t_ptr _listbox_get_next_entity(res_win_t widget, link_t_ptr pos)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	link_t_ptr ent;

	if (pos == LINK_LAST)
		return NULL;

	ent = get_string_next_entity(ptd->string, LINK_FIRST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_next_entity(ptd->string, ent);
			continue;
		}

		if (pos == LINK_FIRST)
			return ent;
		else if (pos == ent)
			pos = LINK_FIRST;

		ent = get_string_next_entity(ptd->string, ent);
	}

	return NULL;
}

static link_t_ptr _listbox_get_prev_entity(res_win_t widget, link_t_ptr pos)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	link_t_ptr ent;

	if (pos == LINK_LAST)
		return NULL;

	ent = get_string_prev_entity(ptd->string, LINK_LAST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_prev_entity(ptd->string, ent);
			continue;
		}

		if (pos == LINK_LAST)
			return ent;
		else if (pos == ent)
			pos = LINK_LAST;

		ent = get_string_prev_entity(ptd->string, ent);
	}

	return NULL;
}
/*************************************************************************/

void noti_listbox_command(res_win_t widget, int code, vword_t data)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	if (widget_has_subproc(widget))
		widget_post_command(widget, code, IDC_SELF, data);
	else
		widget_post_command(widget_get_owner(widget), code, widget_get_user_id(widget), data);
}

void listbox_on_item_changing(res_win_t widget)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->entity != NULL);

	_listbox_item_rect(widget, ptd->entity, &xr);

	ptd->entity = NULL;

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

void listbox_on_item_changed(res_win_t widget, link_t_ptr ent)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->entity == NULL);

	ptd->entity = ent;

	_listbox_item_rect(widget, ptd->entity, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);

	noti_listbox_command(widget, COMMAND_UPDATE, (vword_t)NULL);
}

/********************************************************************************************/
int hand_listbox_create(res_win_t widget, void* data)
{
	listbox_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (listbox_delta_t*)xmem_alloc(sizeof(listbox_delta_t));

	ptd->string = create_string_table(0);
	ptd->entity = NULL;

	SETLISTBOXDELTA(widget, ptd);

	return 0;
}

void hand_listbox_destroy(res_win_t widget)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	destroy_string_table(ptd->string);

	xmem_free(ptd);

	SETLISTBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_listbox_keydown(res_win_t widget, dword_t ks, int key)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	if (!ptd->string)
		return;

	switch (key)
	{
	case KEY_ENTER:
		noti_listbox_command(widget, COMMAND_CHANGE, (vword_t)NULL);
		break;
	case KEY_SPACE:
		noti_listbox_command(widget, COMMAND_CHANGE, (vword_t)NULL);
		break;
	case KEY_LEFT:
		listbox_tabskip(widget,TABORDER_LEFT);
		break;
	case KEY_RIGHT:
		listbox_tabskip(widget,TABORDER_RIGHT);
		break;
	case KEY_HOME:
		listbox_tabskip(widget,TABORDER_HOME);
		break;
	case KEY_END:
		listbox_tabskip(widget,TABORDER_END);
		break;
	}
}

void hand_listbox_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	if (!ptd)
		return;

}

void hand_listbox_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	xfont_t xf = { 0 };
	measure_interface im = { 0 };
	link_t_ptr ilk = NULL;
	int hint;
	xpoint_t pt;

	if (!ptd->string)
		return;

	get_canvas_measure(widget_get_canvas(widget), &im);

	widget_get_xfont(widget, &xf);

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(widget, &pt);

	hint = calc_listbox_hint(&im, &xf, &pt, ptd->string, &ilk);

	if (ilk != ptd->entity)
	{
		if (ptd->entity)
			listbox_on_item_changing(widget);

		if (ilk)
			listbox_on_item_changed(widget, ilk);
	}

	noti_listbox_command(widget, COMMAND_CHANGE, (vword_t)NULL);
}

void hand_listbox_size(res_win_t widget, int code, const xsize_t* prs)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	if (!ptd->string)
		return;

	listbox_redraw(widget);
}

void hand_listbox_scroll(res_win_t widget, bool_t bHorz, int nLine)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	if (!ptd->string)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_listbox_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	visual_t rdc;
	xrect_t xr;
	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	xfont_t xf;
	xbrush_t xb;
	xpen_t xp;
	xcolor_t xc;

	if (!ptd->string)
		return;

	widget_get_xfont(widget, &xf);
	widget_get_xbrush(widget, &xb);
	widget_get_xpen(widget, &xp);

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);
	

	
	
	
	
	

	widget_get_client_rect(widget, &xr);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	draw_listbox(pif, &xf, ptd->string);

	//draw focus
	if (ptd->entity)
	{
		_listbox_item_rect(widget, ptd->entity, &xr);

		parse_xcolor(&xc, DEF_ALPHA_COLOR);
		(*ifv.pf_alphablend_rect)(ifv.ctx, &xc, &xr, ALPHA_SOFT);
	}

	

	end_canvas_paint(canv, dc, pxr);
	
}

/************************************************************************************************/
res_win_t listbox_create(res_win_t widget, dword_t style, const xrect_t* pxr)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_listbox_create)
		EVENT_ON_DESTROY(hand_listbox_destroy)

		EVENT_ON_PAINT(hand_listbox_paint)

		EVENT_ON_SIZE(hand_listbox_size)

		EVENT_ON_SCROLL(hand_listbox_scroll)

		EVENT_ON_KEYDOWN(hand_listbox_keydown)

		EVENT_ON_LBUTTON_DOWN(hand_listbox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_listbox_lbutton_up)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(NULL,style, pxr, widget, &ev);
}

void listbox_set_options(res_win_t widget, const tchar_t* options, int len)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	clear_string_table(ptd->string);
	string_table_parse_options(ptd->string, options, len, OPT_ITEMFEED, OPT_LINEFEED);

	listbox_redraw(widget);
}

const tchar_t* listbox_get_cur_key(res_win_t widget)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->entity)
		return NULL;

	return get_string_entity_key_ptr(ptd->entity);
}

int listbox_get_cur_val(res_win_t widget, tchar_t* val, int max)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->entity)
		return 0;

	return get_string_entity_val(ptd->entity, val, max);
}

void listbox_redraw(res_win_t widget)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	link_t_ptr ent;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->string)
		return;

	ent = get_string_next_entity(ptd->string, LINK_FIRST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_next_entity(ptd->string, ent);
			continue;
		}

		if (ent == ptd->entity)
			break;

		ent = get_string_next_entity(ptd->string, ent);
	}

	ptd->entity = ent;
	_listbox_reset_page(widget);

	widget_erase(widget, NULL);
}

void listbox_set_focus_item(res_win_t widget, link_t_ptr ilk)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->string)
		return;

	if (ilk != ptd->entity)
	{
		if (ptd->entity)
			listbox_on_item_changing(widget);

		if (ilk)
			listbox_on_item_changed(widget, ilk);

		_listbox_reset_visible(widget);
	}
}

void listbox_tabskip(res_win_t widget, int nSkip)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	link_t_ptr ilk;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->string)
		return;

	ilk = (ptd->entity)? ptd->entity : NULL;

	switch (nSkip)
	{
	case TABORDER_LEFT:
	case TABORDER_DOWN:
		ilk = _listbox_get_next_entity(widget, ilk);
		break;
	case TABORDER_RIGHT:
	case TABORDER_UP:
		ilk = _listbox_get_prev_entity(widget, ilk);
		break;
	}

	if (ilk)
		listbox_set_focus_item(widget, ilk);
}

void listbox_popup_size(res_win_t widget, xsize_t* pxs)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	xfont_t xf;
	measure_interface im = { 0 };

	get_canvas_measure(widget_get_canvas(widget), &im);

	widget_get_xfont(widget, &xf);

	calc_listbox_size(&im, &xf, ptd->string, pxs);

	if (pxs->fh > 7 * DEF_TOUCH_SPAN)
		pxs->fh = 7 * DEF_TOUCH_SPAN;

	widget_size_to_pt(widget, pxs);

	widget_adjust_size(widget_get_style(widget), pxs);
}

void listbox_find(res_win_t widget, const tchar_t* token)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	link_t_ptr ent;
	int tlen;

	if (is_null(token))
	{
		listbox_set_focus_item(widget, NULL);
		return;
	}

	tlen = xslen(token);

	ent = get_string_next_entity(ptd->string, LINK_FIRST);
	while (ent)
	{
		if (get_string_entity_delta(ent))
		{
			ent = get_string_next_entity(ptd->string, ent);
			continue;
		}

		if (xsnicmp(get_string_entity_key_ptr(ent), token, tlen) == 0)
			break;

		ent = get_string_next_entity(ptd->string, ent);
	}

	listbox_set_focus_item(widget, ent);
}

void listbox_filter(res_win_t widget, const tchar_t* token)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	link_t_ptr ent;
	int tlen;

	tlen = xslen(token);

	ent = get_string_next_entity(ptd->string, LINK_FIRST);
	while (ent)
	{
		if (xsnicmp(get_string_entity_key_ptr(ent), token, tlen) == 0)
			set_string_entity_delta(ent, 0);
		else
			set_string_entity_delta(ent, 1);

		ent = get_string_next_entity(ptd->string, ent);
	}

	ptd->entity = NULL;
	listbox_redraw(widget);
}
