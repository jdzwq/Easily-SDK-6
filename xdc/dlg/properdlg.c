﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc proper dialog document

	@module	properdlg.c | implement file

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

#include "dlg.h"

#include "../xdcimp.h"
#include "../xdcinit.h"

#define IDC_PROPERDLG_PROPER			10
#define IDC_PROPERDLG_PUSHBOX_OK		11

#define PROPERDLG_BUTTON_HEIGHT		(float)8 //tm
#define PROPERDLG_BUTTON_WIDTH		(float)12 //tm

typedef struct _properdlg_delta_t{
	link_t_ptr proper;
}properdlg_delta_t;

#define GETPROPERDLGDELTA(ph) 	(properdlg_delta_t*)widget_get_user_delta(ph)
#define SETPROPERDLGDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/**********************************************************************************/
void properdlg_on_ok(res_win_t widget)
{
	res_win_t ctrl;

	ctrl = widget_get_child(widget, IDC_PROPERDLG_PROPER);
	properctrl_accept(ctrl, 1);

	widget_close(widget, 1);
}
/**********************************************************************************/
int hand_properdlg_create(res_win_t widget, void* data)
{
	properdlg_delta_t* ptd;

	xrect_t xr;
	xsize_t xs;
	res_win_t properctrl, pushbox;

	widget_hand_create(widget);

	ptd = (properdlg_delta_t*)xmem_alloc(sizeof(properdlg_delta_t));
	xmem_zero((void*)ptd, sizeof(properdlg_delta_t));
	ptd->proper = (link_t_ptr)data;

	xs.fw = PROPERDLG_BUTTON_WIDTH;
	xs.fh = PROPERDLG_BUTTON_HEIGHT;
	widget_size_to_pt(widget, &xs);

	widget_get_client_rect(widget, &xr);
	xr.h -= xs.h;

	properctrl = properctrl_create(NULL, WD_STYLE_CONTROL | WD_STYLE_VSCROLL, &xr, widget);
	widget_set_owner(properctrl, widget);
	widget_set_user_id(properctrl, IDC_PROPERDLG_PROPER);

	properctrl_attach(properctrl, ptd->proper);
	properctrl_set_lock(properctrl, 0);

	widget_show(properctrl, WS_SHOW_NORMAL);

	widget_get_client_rect(widget, &xr);
	xr.y = xr.y + xr.h - xs.h;
	xr.h = xs.h;
	xr.x = xr.x + xr.w - xs.w;
	xr.w = xs.w;

	xs.fw = DEF_SPLIT_FEED;
	xs.fh = DEF_SPLIT_FEED;
	widget_size_to_pt(widget, &xs);

	pt_expand_rect(&xr, -xs.w, -xs.h);

	pushbox = pushbox_create(widget, WD_STYLE_CONTROL | WD_PUSHBOX_TEXT, &xr);
	widget_set_user_id(pushbox, IDC_PROPERDLG_PUSHBOX_OK);
	widget_set_owner(pushbox, widget);
	pushbox_set_text(pushbox, PROPERDLG_PUSHBOX_OK, -1);
	widget_show(pushbox, WS_SHOW_NORMAL);

	SETPROPERDLGDELTA(widget, ptd);

	return 0;
}

void hand_properdlg_destroy(res_win_t widget)
{
	properdlg_delta_t* ptd = GETPROPERDLGDELTA(widget);
	res_win_t ctrl;

	XDK_ASSERT(ptd != NULL);

	ctrl = widget_get_child(widget, IDC_PROPERDLG_PROPER);
	if (ctrl)
		widget_destroy(ctrl);

	ctrl = widget_get_child(widget, IDC_PROPERDLG_PUSHBOX_OK);
	if (ctrl)
		widget_destroy(ctrl);

	xmem_free(ptd);

	SETPROPERDLGDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_properdlg_menu_command(res_win_t widget, int code, int cid, vword_t data)
{
	properdlg_delta_t* ptd = GETPROPERDLGDELTA(widget);

	if (cid == IDC_PROPERDLG_PUSHBOX_OK)
	{
		properdlg_on_ok(widget);
	}
}

void hand_properdlg_size(res_win_t widget, int code, const xsize_t* prs)
{
	properdlg_delta_t* ptd = GETPROPERDLGDELTA(widget);
	xsize_t xs;
	xrect_t xr;
	res_win_t ctrl;

	xs.fw = PROPERDLG_BUTTON_WIDTH;
	xs.fh = PROPERDLG_BUTTON_HEIGHT;
	widget_size_to_pt(widget, &xs);

	widget_get_client_rect(widget, &xr);
	xr.h -= xs.h;

	ctrl = widget_get_child(widget, IDC_PROPERDLG_PROPER);
	if (widget_is_valid(ctrl))
	{
		widget_move(ctrl, RECTPOINT(&xr));
		widget_size(ctrl, RECTSIZE(&xr));
		widget_update(ctrl);
	}

	widget_get_client_rect(widget, &xr);
	xr.y = xr.y + xr.h - xs.h;
	xr.h = xs.h;
	xr.x = xr.x + xr.w - xs.w;
	xr.w = xs.w;

	xs.fw = DEF_SPLIT_FEED;
	xs.fh = DEF_SPLIT_FEED;
	widget_size_to_pt(widget, &xs);

	pt_expand_rect(&xr, -xs.w, -xs.h);

	ctrl = widget_get_child(widget, IDC_PROPERDLG_PUSHBOX_OK);
	if (widget_is_valid(ctrl))
	{
		widget_move(ctrl, RECTPOINT(&xr));
		widget_size(ctrl, RECTSIZE(&xr));
		widget_update(ctrl);
	}

	widget_erase(widget, NULL);
}

void hand_properdlg_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	properdlg_delta_t* ptd = GETPROPERDLGDELTA(widget);
	visual_t rdc;
	xfont_t xf = { 0 };
	xface_t xa = { 0 };
	xpen_t xp = { 0 };
	xbrush_t xb = { 0 };
	xcolor_t xc_brim, xc_core;
	xrect_t xr,xr_bar;
	xsize_t xs;
	canvas_t canv;
	drawing_interface ifv = {0};

	widget_get_xfont(widget, &xf);
	widget_get_xface(widget, &xa);

	widget_get_xbrush(widget, &xb);
	widget_get_xpen(widget, &xp);

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	xs.fw = PROPERDLG_BUTTON_WIDTH;
	xs.fh = PROPERDLG_BUTTON_HEIGHT;
	widget_size_to_pt(widget, &xs);

	xr_bar.x = xr.x;
	xr_bar.y = xr.y + xr.h - xs.h;
	xr_bar.w = xr.w;
	xr_bar.h = xs.h;

	parse_xcolor(&xc_brim, xb.color);
	parse_xcolor(&xc_core, xb.color);
	lighten_xcolor(&xc_brim, DEF_MIDD_DARKEN);

	(*ifv.pf_gradient_rect)(ifv.ctx, &xc_brim, &xc_core, GDI_ATTR_GRADIENT_HORZ, &xr_bar);

	

	end_canvas_paint(canv, dc, pxr);
}

/***************************************************************************************/
res_win_t properdlg_create(const tchar_t* title, link_t_ptr ptr, res_win_t owner)
{
	if_event_t ev = { 0 };
	res_win_t dlg;
	xrect_t xr = { 0 };
	clr_mod_t clr;

	ev.param = (void*)ptr;

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_properdlg_create)
		EVENT_ON_DESTROY(hand_properdlg_destroy)

		EVENT_ON_PAINT(hand_properdlg_paint)

		EVENT_ON_SIZE(hand_properdlg_size)

		EVENT_ON_MENU_COMMAND(hand_properdlg_menu_command)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	dlg = widget_create(NULL, WD_STYLE_DIALOG, &xr, owner, &ev);
	widget_set_owner(dlg, owner);
	widget_set_user_id(dlg, IDC_PROPERDLG);
	widget_set_title(dlg, title);

	properdlg_popup_size(dlg, RECTSIZE(&xr));
	widget_size(dlg, RECTSIZE(&xr));
	widget_update(dlg);
	widget_center_window(dlg, owner);

	if (widget_is_valid(owner))
	{
		widget_get_color_mode(owner, &clr);
		widget_set_color_mode(dlg, &clr);
	}

	return dlg;
}

void properdlg_popup_size(res_win_t widget, xsize_t* pxs)
{
	properdlg_delta_t* ptd = GETPROPERDLGDELTA(widget);

	XDK_ASSERT(ptd->proper != NULL);

	pxs->fw = calc_proper_width(ptd->proper) + PROPERDLG_BUTTON_WIDTH;
	pxs->fh = calc_proper_height(ptd->proper) + PROPERDLG_BUTTON_HEIGHT;

	if (pxs->fh > get_proper_item_height(ptd->proper) * 15)
		pxs->fh = get_proper_item_height(ptd->proper) * 15 + PROPERDLG_BUTTON_HEIGHT;
	else if (pxs->fh < get_proper_item_height(ptd->proper) * 7)
		pxs->fh = get_proper_item_height(ptd->proper) * 7 + PROPERDLG_BUTTON_HEIGHT;

	widget_size_to_pt(widget, pxs);

	widget_adjust_size(widget_get_style(widget), pxs);
}

