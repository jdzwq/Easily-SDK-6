/***********************************************************************
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

#include "../xdcobj.h"


typedef struct _listbox_delta_t{
	link_t_ptr string;
	link_t_ptr entity;

}listbox_delta_t;

#define GETLISTBOXDELTA(ph) 	(listbox_delta_t*)widget_get_user_delta(ph)
#define SETLISTBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/***************************************************************************************/
void _listbox_item_rect(widget_t widget, link_t_ptr ent, xrect_t* pxr)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	xrect_t xr;
	measure_interface im = { 0 };

	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_listbox_item_rect(&im, ptd->string, ent, pxr);
	widget_rect_to_pt(widget, pxr);

	widget_get_client_rect(widget, &xr);
	pxr->w = xr.w;
}

static void _listbox_reset_page(widget_t widget)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	int pw, ph, vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	canvas_t canv;
	const drawing_interface* pif = NULL;
	measure_interface im = { 0 };

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);

	(pif->pf_get_measure)(pif->ctx, &im);
	(pif->pf_font_size)(pif->ctx, &xs);
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	if (ptd->string)
	{
		calc_listbox_size(&im, ptd->string, &xs);
		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}
	else
	{
		vw = pw;
		vh = ph;
	}

	widget_reset_paging(widget, pw, ph, vw, vh, lw, lh);

	widget_reset_scroll(widget, 0);
}

void _listbox_reset_visible(widget_t widget)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	xrect_t xr;
	
	if (!ptd->entity)
		return;

	_listbox_item_rect(widget, ptd->entity, &xr);

	widget_ensure_visible(widget, &xr, 1);
}

static link_t_ptr _listbox_get_next_entity(widget_t widget, link_t_ptr pos)
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

static link_t_ptr _listbox_get_prev_entity(widget_t widget, link_t_ptr pos)
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

void noti_listbox_command(widget_t widget, int code, vword_t data)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	if (widget_has_subproc(widget))
		widget_post_command(widget, code, IDC_SELF, data);
	else
		widget_post_command(widget_get_owner(widget), code, widget_get_user_id(widget), data);
}

void listbox_on_item_changing(widget_t widget)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->entity != NULL);

	_listbox_item_rect(widget, ptd->entity, &xr);

	ptd->entity = NULL;

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

void listbox_on_item_changed(widget_t widget, link_t_ptr ent)
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
int hand_listbox_create(widget_t widget, void* data)
{
	listbox_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (listbox_delta_t*)xmem_alloc(sizeof(listbox_delta_t));

	ptd->string = create_string_table(0);
	ptd->entity = NULL;

	SETLISTBOXDELTA(widget, ptd);

	return 0;
}

void hand_listbox_destroy(widget_t widget)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	destroy_string_table(ptd->string);

	xmem_free(ptd);

	SETLISTBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_listbox_keydown(widget_t widget, dword_t ks, int key)
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

void hand_listbox_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	if (!ptd)
		return;

}

void hand_listbox_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	measure_interface im = { 0 };
	link_t_ptr ilk = NULL;
	int hint;
	xpoint_t pt;

	if (!ptd->string)
		return;

	get_canvas_measure(widget_get_canvas(widget), &im);

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_mm(widget, &pt);

	hint = calc_listbox_hint(&im, &pt, ptd->string, &ilk);

	if (ilk != ptd->entity)
	{
		if (ptd->entity)
			listbox_on_item_changing(widget);

		if (ilk)
			listbox_on_item_changed(widget, ilk);
	}

	noti_listbox_command(widget, COMMAND_CHANGE, (vword_t)NULL);
}

void hand_listbox_size(widget_t widget, int code, const xsize_t* prs)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	switch(code)
	{
	case WS_SIZE_FULLSCREEN:
		break;
	case WS_SIZE_MAXIMIZED:
		break;
	case WS_SIZE_MINIMIZED:
		break;
	case WS_SIZE_LAYOUT:
		_listbox_reset_page(widget);
		break;
	}
}

void hand_listbox_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	if (!ptd->string)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_listbox_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);
	visual_t rdc;
	xrect_t xr;
	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	color_mod_t clrs;
	xbrush_t xb;
	xcolor_t xc;

	if (!ptd->string) return;

	widget_get_color_mode(widget, &clrs);
	default_xbrush(&xb);
	format_xcolor(&clrs.clr_bkg, xb.color);

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);

	widget_get_client_rect(widget, &xr);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	draw_listbox(pif, ptd->string);

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
widget_t listbox_create(widget_t widget, dword_t style, const xrect_t* pxr)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_listbox_create)
		EVENT_ON_DESTROY(hand_listbox_destroy)

		EVENT_ON_PAINT(hand_listbox_paint)

		EVENT_ON_SIZE(hand_listbox_size)

		EVENT_ON_SCROLL(hand_listbox_scroll)

		EVENT_ON_KEYDOWN(hand_listbox_keydown)

		EVENT_ON_LBUTTON_DOWN(hand_listbox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_listbox_lbutton_up)

	EVENT_END_DISPATH

	return widget_create(NULL,style, pxr, widget, &ev);
}

void listbox_set_options(widget_t widget, const tchar_t* options, int len)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	clear_string_table(ptd->string);
	string_table_parse_options(ptd->string, options, len, OPT_ITEMFEED, OPT_LINEFEED);

	listbox_redraw(widget);
}

const tchar_t* listbox_get_cur_key(widget_t widget)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->entity)
		return NULL;

	return get_string_entity_key_ptr(ptd->entity);
}

int listbox_get_cur_val(widget_t widget, tchar_t* val, int max)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->entity)
		return 0;

	return get_string_entity_val(ptd->entity, val, max);
}

void listbox_redraw(widget_t widget)
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

void listbox_set_focus_item(widget_t widget, link_t_ptr ilk)
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

void listbox_tabskip(widget_t widget, int nSkip)
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

void listbox_popup_size(widget_t widget, xsize_t* pxs)
{
	listbox_delta_t* ptd = GETLISTBOXDELTA(widget);

	measure_interface im = { 0 };

	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_listbox_size(&im, ptd->string, pxs);

	if (pxs->fh > 7 * DEF_TOUCH_SPAN)
		pxs->fh = 7 * DEF_TOUCH_SPAN;

	widget_size_to_pt(widget, pxs);

	adjust_widget_size(widget_get_style(widget), pxs);
}

void listbox_find(widget_t widget, const tchar_t* token)
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

void listbox_filter(widget_t widget, const tchar_t* token)
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
