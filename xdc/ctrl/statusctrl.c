﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc status control document

	@module	statusctrl.c | implement file

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

#include "ctrl.h"

#include "../xdcimp.h"
#include "../xdcinit.h"

typedef struct _status_delta_t{
	link_t_ptr status;
	link_t_ptr item;
	link_t_ptr hover;

	bool_t b_step;
	int n_step;
}status_delta_t;

#define GETSTATUSDELTA(ph) 		(status_delta_t*)widget_get_user_delta(ph)
#define SETSTATUSDELTA(ph,ptd)	 widget_set_user_delta(ph,(vword_t)ptd)

/**************************************************************************************************/
static void _statusctrl_title_rect(res_win_t widget, xrect_t* pxr)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	calc_status_title_rect(ptd->status, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _statusctrl_item_rect(res_win_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	calc_status_item_rect(ptd->status, ilk, pxr);

	widget_rect_to_pt(widget, pxr);
}

void _statusctrl_reset_page(res_win_t widget)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	int pw, ph;
	xrect_t xr;

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	widget_reset_paging(widget, pw, ph, pw, ph, 0, 0);
}

/**************************************************************************************************/
int noti_status_owner(res_win_t widget, unsigned int code, link_t_ptr status, link_t_ptr ilk, void* data)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	NOTICE_STATUS nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;
	nf.data = data;
	nf.ret = 0;

	nf.status = status;
	nf.item = ilk;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);
	return nf.ret;
}

void noti_status_item_enter(res_win_t widget, link_t_ptr plk)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	XDK_ASSERT(plk);
	XDK_ASSERT(!ptd->hover);

	ptd->hover = plk;

	if (widget_is_hotvoer(widget))
	{
		widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
	}
}

void noti_status_item_leave(res_win_t widget)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	ptd->hover = NULL;

	if (widget_is_hotvoer(widget))
	{
		widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
	}
}

void noti_status_item_hover(res_win_t widget, int x, int y)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	xpoint_t xp;

	XDK_ASSERT(ptd->hover != NULL);

	xp.x = x;
	xp.y = y;
	noti_status_owner(widget, NC_STATUSITEMHOVER, ptd->status, ptd->hover, (void*)&xp);
}

bool_t noti_status_item_changing(res_win_t widget)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->item);

	_statusctrl_item_rect(widget, ptd->item, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	ptd->item = NULL;

	widget_erase(widget, &xr);

	return 1;
}

void noti_status_item_changed(res_win_t widget, link_t_ptr plk)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(!ptd->item);

	ptd->item = plk;

	_statusctrl_item_rect(widget, ptd->item, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

/****************************************************************************************/

int hand_status_create(res_win_t widget, void* data)
{
	status_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (status_delta_t*)xmem_alloc(sizeof(status_delta_t));
	xmem_zero((void*)ptd, sizeof(status_delta_t));

	SETSTATUSDELTA(widget, ptd);

	return 0;
}

void hand_status_destroy(res_win_t widget)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETSTATUSDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_status_size(res_win_t widget, int code, const xsize_t* prs)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	xrect_t xr;

	if (!ptd->status)
		return;

	widget_get_client_rect(widget, &xr);
	widget_rect_to_tm(widget, &xr);

	set_status_width(ptd->status, xr.fw);
	set_status_height(ptd->status, xr.fh);

	statusctrl_redraw(widget);
}

void hand_status_mouse_move(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	int nHint;
	link_t_ptr plk;
	xpoint_t pt;

	if (!ptd->status)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(widget, &pt);

	plk = NULL;
	nHint = calc_status_hint(&pt, ptd->status, &plk);

	if (nHint == STATUS_HINT_ITEM && !ptd->hover && plk)
	{
		noti_status_item_enter(widget, plk);
	}
	else if (nHint == STATUS_HINT_ITEM && ptd->hover && ptd->hover != plk)
	{
		noti_status_item_leave(widget);
	}
	else if (nHint != STATUS_HINT_ITEM && ptd->hover)
	{
		noti_status_item_leave(widget);
	}
}

void hand_status_mouse_hover(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	if (!ptd->status)
		return;

	if (ptd->hover)
		noti_status_item_hover(widget, pxp->x, pxp->y);
}

void hand_status_mouse_leave(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	if (!ptd->status)
		return;

	if (ptd->hover)
		noti_status_item_leave(widget);
}

void hand_status_lbutton_dbclick(res_win_t widget, const xpoint_t* pxp)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	if (!ptd->status)
		return;

	noti_status_owner(widget, NC_STATUSDBCLK,ptd->status, ptd->item, (void*)pxp);
}

void hand_status_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	int nHint;
	link_t_ptr plk;
	bool_t bRe;
	xpoint_t pt;

	if (!ptd->status)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(widget, &pt);

	plk = NULL;
	nHint = calc_status_hint(&pt, ptd->status, &plk);
	bRe = (plk == ptd->item) ? 1 : 0;

	if (bRe)
		return;

	if (nHint == STATUS_HINT_ITEM)
		statusctrl_set_focus_item(widget, plk);
	else
		statusctrl_set_focus_item(widget, NULL);
}

void hand_status_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	if (!ptd->status)
		return;

	noti_status_owner(widget, NC_STATUSLBCLK,ptd->status, ptd->item, (void*)pxp);
}

void hand_status_rbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	if (!ptd->status)
		return;
}

void hand_status_rbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	if (!ptd->status)
		return;

	noti_status_owner(widget, NC_STATUSRBCLK, ptd->status, ptd->item, (void*)pxp);
}

void hand_status_keydown(res_win_t widget, dword_t ks, int nKey)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	if (!ptd->status)
		return;

	switch (nKey)
	{
	case KEY_LEFT:
	case KEY_PAGEDOWN:
		statusctrl_tabskip(widget,TABORDER_LEFT);
		break;
	case KEY_RIGHT:
	case KEY_PAGEUP:
		statusctrl_tabskip(widget,TABORDER_RIGHT);
		break;
	case KEY_HOME:
		statusctrl_tabskip(widget,TABORDER_HOME);
		break;
	case KEY_END:
		statusctrl_tabskip(widget,TABORDER_END);
		break;
	}
}

void hand_status_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	visual_t rdc;
	xfont_t xf = { 0 };
	xface_t xa = { 0 };
	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };
	xcolor_t xc = { 0 };
	xcolor_t xc_brim = { 0 };
	xcolor_t xc_core = { 0 };
	xrect_t xr_step,xr = { 0 };

	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	if (!ptd->status)
		return;

	widget_get_xfont(widget, &xf);
	widget_get_xface(widget, &xa);
	widget_get_xbrush(widget, &xb);
	widget_get_xpen(widget, &xp);

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);
	
	widget_get_client_rect(widget, &xr);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	parse_xcolor(&xc_brim, xb.color);
	parse_xcolor(&xc_core, xb.color);
	lighten_xcolor(&xc_brim, DEF_SOFT_DARKEN);

	(*ifv.pf_gradient_rect)(ifv.ctx, &xc_brim, &xc_core, GDI_ATTR_GRADIENT_VERT, &xr);

	draw_status(pif, ptd->status);

	calc_status_title_rect(ptd->status, &xr);

	if (ptd->b_step)
	{
		xr_step.fx = xr.fx;
		xr_step.fy = xr.fy;
		xr_step.fw = xr.fw / 2;
		xr_step.fh = xr.fh;

		parse_xcolor(&xc, xp.color);
		draw_progress(pif, &xc, &xr_step, ptd->n_step);

		xr.fx += xr_step.fw;
		(pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, get_status_title_ptr(ptd->status), -1);
	}
	else
	{
		(pif->pf_draw_text)(pif->ctx, &xf, &xa, &xr, get_status_title_ptr(ptd->status), -1);
	}

	end_canvas_paint(canv, dc, pxr);
	
}

/*******************************************************************************************/

res_win_t statusctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, res_win_t wparent)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_status_create)
		EVENT_ON_DESTROY(hand_status_destroy)

		EVENT_ON_PAINT(hand_status_paint)

		EVENT_ON_SIZE(hand_status_size)

		EVENT_ON_MOUSE_MOVE(hand_status_mouse_move)
		EVENT_ON_MOUSE_HOVER(hand_status_mouse_hover)
		EVENT_ON_MOUSE_LEAVE(hand_status_mouse_leave)

		EVENT_ON_LBUTTON_DBCLICK(hand_status_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_status_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_status_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_status_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_status_rbutton_up)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void statusctrl_attach(res_win_t widget, link_t_ptr ptr)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(ptr && is_status_doc(ptr));

	ptd->item = NULL;
	ptd->status = ptr;
	
	widget_get_client_rect(widget, &xr);
	widget_rect_to_tm(widget, &xr);

	set_status_width(ptd->status, xr.fw);
	set_status_height(ptd->status, xr.fh);

	statusctrl_redraw(widget);
}

link_t_ptr statusctrl_detach(res_win_t widget)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	link_t_ptr data;

	XDK_ASSERT(ptd != NULL);

	if (ptd->status)
	{
		data = ptd->status;
		ptd->status = NULL;
	}
	else
		data = NULL;

	return data;
}

link_t_ptr statusctrl_fetch(res_win_t widget)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->status;
}

void statusctrl_redraw(res_win_t widget)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	link_t_ptr ilk;
	bool_t b_valid;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->status)
		return;

	b_valid = 0;
	ilk = get_status_next_item(ptd->status, LINK_FIRST);
	while (ilk)
	{
		if (ilk == ptd->item)
			b_valid = 1;

		noti_status_owner(widget, NC_STATUSITEMCALCED, ptd->status, ilk, NULL);

		ilk = get_status_next_item(ptd->status, ilk);
	}

	noti_status_owner(widget, NC_STATUSCALCED, ptd->status, NULL, NULL);

	if (!b_valid)
	{
		ptd->item = NULL;
	}
	ptd->hover = NULL;

	_statusctrl_reset_page(widget);

	widget_erase(widget, NULL);
}

void statusctrl_tabskip(res_win_t widget, int nSkip)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	link_t_ptr plk = NULL;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->status)
		return;

	plk = ptd->item;

	switch (nSkip)
	{
	case TABORDER_RIGHT:
	case TABORDER_DOWN:
		if (plk == NULL)
			plk = get_status_next_item(ptd->status, LINK_FIRST);
		else
			plk = get_status_next_item(ptd->status, plk);

		if (plk)
			statusctrl_set_focus_item(widget, plk);
		break;
	case TABORDER_LEFT:
	case TABORDER_UP:
		if (plk == NULL)
			plk = get_status_prev_item(ptd->status, LINK_LAST);
		else
			plk = get_status_prev_item(ptd->status, plk);

		if (plk)
			statusctrl_set_focus_item(widget, plk);
		break;
	case TABORDER_HOME:
		plk = get_status_next_item(ptd->status, LINK_FIRST);

		if (plk)
			statusctrl_set_focus_item(widget, plk);
		break;
	case TABORDER_END:
		plk = get_status_prev_item(ptd->status, LINK_LAST);

		if (plk)
			statusctrl_set_focus_item(widget, plk);
		break;
	}
}

void statusctrl_redraw_title(res_win_t widget)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->status)
		return;

	_statusctrl_title_rect(widget, &xr);

	widget_erase(widget, &xr);
}

void statusctrl_redraw_item(res_win_t widget, link_t_ptr plk)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->status)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_status_item(ptd->status, plk));
#endif

	noti_status_owner(widget, NC_STATUSITEMCALCED, ptd->status, plk, NULL);

	_statusctrl_item_rect(widget, plk, &xr);

	widget_erase(widget, &xr);
}

bool_t statusctrl_set_focus_item(res_win_t widget, link_t_ptr ilk)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	bool_t bRe;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->status)
		return 0;

	if (ilk == LINK_FIRST)
		ilk = get_status_next_item(ptd->status, LINK_FIRST);
	else if (ilk == LINK_LAST)
		ilk = get_status_prev_item(ptd->status, LINK_LAST);

	bRe = (ilk == ptd->item) ? 1 : 0;
	if (bRe)
		return 1;

	if (ptd->item && !bRe)
	{
		if (!noti_status_item_changing(widget))
			return 0;
	}

	if (ilk && !bRe)
	{
		noti_status_item_changed(widget, ilk);
	}

	return 1;
}

link_t_ptr statusctrl_get_focus_item(res_win_t widget)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->status)
		return NULL;

	return ptd->item;
}

void statusctrl_get_item_rect(res_win_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	if (!ptd->status)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_status_item(ptd->status, ilk));
#endif

	_statusctrl_item_rect(widget, ilk, pxr);
}

void statusctrl_show_step(res_win_t widget, bool_t b_show)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->status)
		return;

	ptd->b_step = b_show;
	ptd->n_step = 0;
	set_status_title(ptd->status, NULL);
	
	widget_erase(widget, NULL);
	widget_paint(widget);
}

void statusctrl_step_it(res_win_t widget, int steps, const tchar_t* sz_step)
{
	status_delta_t* ptd = GETSTATUSDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->status)
		return;

	if (!ptd->b_step)
		return;

	ptd->n_step += steps;
	set_status_title(ptd->status, sz_step);

	widget_erase(widget, NULL);
	widget_paint(widget);
}
