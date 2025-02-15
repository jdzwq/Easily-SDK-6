﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc horz control document

	@module	horzbox.c | implement file

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

typedef struct _horzbox_delta_t{
	res_win_t target;

	bool_t b_drag;
	int org_x, org_y;
}horzbox_delta_t;

#define GETHORZBOXDELTA(ph) 	(horzbox_delta_t*)widget_get_user_delta(ph)
#define SETHORZBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

#define HORZBOX_BAR_WIDTH		16
#define HORZBOX_BAR_FEED		3
#define HORZBOX_LINE_DELTA		10
/*********************************************************************************/

static void _horzbox_bar_rect(res_win_t widget, xrect_t* pxr)
{
	horzbox_delta_t* ptd = GETHORZBOXDELTA(widget);
	viewbox_t vb;
	xrect_t xr;
	int bw, off;
	float f;

	widget_get_client_rect(widget, &xr);
	widget_get_view_rect(ptd->target, &vb);
	
	f = (float)((float)xr.w / (float)vb.pw);
	bw = (int)(f * (float)xr.w);
	off = xr.x -(int)(f * (float)vb.px);

	pxr->x = off;
	pxr->y = HORZBOX_BAR_FEED;
	pxr->w = bw;
	pxr->h = xr.h - HORZBOX_BAR_FEED * 2;
}

static int _horzbox_hint_bar(res_win_t widget, const xpoint_t* pxp)
{
	horzbox_delta_t* ptd = GETHORZBOXDELTA(widget);
	xrect_t xr, xr2;
	viewbox_t vb;
	float f;

	_horzbox_bar_rect(widget, &xr);

	if (pt_in_rect(pxp, &xr))
		return 0;

	widget_get_client_rect(widget, &xr2);
	widget_get_view_rect(ptd->target, &vb);

	f = (float)((float)vb.pw / (float)(xr2.w));

	if (pxp->x < xr.x)
		return (int)(f * (float)(pxp->x - xr.x));

	if (pxp->x > xr.x + xr.w)
		return (int)(f * (float)(pxp->x - (xr.x + xr.w)));
	
	return 0;
}

/*********************************************************************************/
int hand_horzbox_create(res_win_t widget, void* data)
{
	horzbox_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (horzbox_delta_t*)xmem_alloc(sizeof(horzbox_delta_t));
	xmem_zero((void*)ptd, sizeof(horzbox_delta_t));

	SETHORZBOXDELTA(widget, ptd);

	return 0;
}

void hand_horzbox_destroy(res_win_t widget)
{
	horzbox_delta_t* ptd = GETHORZBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETHORZBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_horzbox_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	horzbox_delta_t* ptd = GETHORZBOXDELTA(widget);
	int delta; 

	widget_kill_timer(widget, 0);

	delta = _horzbox_hint_bar(widget, pxp);

	if (!delta)
	{
		ptd->b_drag = 1;
		ptd->org_x = pxp->x;
		ptd->org_y = pxp->y;

		widget_set_cursor(widget, CURSOR_HAND);
		widget_set_capture(widget, 1);
	}
	else
	{
		widget_scroll(ptd->target, 1, delta);
		widget_erase(widget, NULL);
	}
}

void hand_horzbox_mouse_move(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	horzbox_delta_t* ptd = GETHORZBOXDELTA(widget);
	int delta;

	xrect_t xr;
	viewbox_t vb;
	float f;

	if (ptd->b_drag)
	{
		_horzbox_bar_rect(widget, &xr);

		widget_get_view_rect(ptd->target, &vb);

		f = (float)((float)vb.pw / (float)(vb.pw - xr.w));

		delta = (int)(f * (float)(pxp->x - ptd->org_x));

		ptd->org_x = pxp->x;
		ptd->org_y = pxp->y;

		widget_scroll(ptd->target, 1, delta);
		widget_erase(widget, NULL);
	}
}

void hand_horzbox_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	horzbox_delta_t* ptd = GETHORZBOXDELTA(widget);

	if (ptd->b_drag)
	{
		ptd->b_drag = 0;
		widget_set_capture(widget, 0);
		widget_set_cursor(widget, CURSOR_ARROW);
	}

	if (!widget_is_valid(ptd->target))
		return;

	widget_set_timer(widget, DEF_TIPTIME);
}

void hand_horzbox_size(res_win_t widget, int code, const xsize_t* prs)
{
	horzbox_delta_t* ptd = GETHORZBOXDELTA(widget);
	
	widget_erase(widget, NULL);
}

void hand_horzbox_timer(res_win_t widget, vword_t tid)
{
	horzbox_delta_t* ptd = GETHORZBOXDELTA(widget);

	xpoint_t pt;
	xrect_t xr;

	message_position(&pt);

	widget_get_window_rect(widget, &xr);

	if (!pt_in_rect(&pt, &xr))
	{
		widget_kill_timer(widget, tid);

		widget_close(widget, 0);
	}
}

void hand_horzbox_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	horzbox_delta_t* ptd = GETHORZBOXDELTA(widget);
	visual_t rdc;
	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	xbrush_t xb;
	xpen_t xp;
	xcolor_t xc_brim, xc_core;
	xrect_t xr;

	widget_get_xbrush(widget, &xb);
	default_xpen(&xp);
	xscpy(xp.color, xb.color);

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);
	
	widget_get_client_rect(widget, &xr);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	lighten_xbrush(&xb, DEF_MIDD_DARKEN);
	(*ifv.pf_draw_rect)(ifv.ctx, &xp, &xb, &xr);

	_horzbox_bar_rect(widget, &xr);

	parse_xcolor(&xc_brim, xb.color);
	lighten_xcolor(&xc_brim, DEF_MIDD_LIGHTEN);
	parse_xcolor(&xc_core, xb.color);

	(*ifv.pf_gradient_rect)(ifv.ctx, &xc_brim, &xc_core, GDI_ATTR_GRADIENT_VERT, &xr);

	end_canvas_paint(canv, dc, pxr);
}

/***************************************************************************************/
res_win_t horzbox_create(res_win_t widget, dword_t style, const xrect_t* pxr)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_horzbox_create)
		EVENT_ON_DESTROY(hand_horzbox_destroy)

		EVENT_ON_PAINT(hand_horzbox_paint)

		EVENT_ON_SIZE(hand_horzbox_size)

		EVENT_ON_LBUTTON_DOWN(hand_horzbox_lbutton_down)
		EVENT_ON_MOUSE_MOVE(hand_horzbox_mouse_move)
		EVENT_ON_LBUTTON_UP(hand_horzbox_lbutton_up)

		EVENT_ON_TIMER(hand_horzbox_timer)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void horzbox_popup_size(res_win_t widget, xsize_t* pxs)
{
	horzbox_delta_t* ptd = GETHORZBOXDELTA(widget);
	measure_interface im = { 0 };
	xfont_t xf = { 0 };

	XDK_ASSERT(ptd != NULL);

	widget_get_xfont(widget, &xf);

	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_horzbox_size(&im, &xf, pxs);

	widget_size_to_pt(widget, pxs);

	widget_adjust_size(widget_get_style(widget), pxs);
}

void horzbox_set_target(res_win_t widget, res_win_t target)
{
	horzbox_delta_t* ptd = GETHORZBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->target = target;
}

res_win_t show_horzbox(res_win_t owner)
{
	res_win_t wt;
	xrect_t xr = { 0 };
	xsize_t xs = { 0 };
	clr_mod_t clr = { 0 };

	wt = horzbox_create(owner, WD_STYLE_POPUP | WD_STYLE_NOACTIVE, &xr);

	XDK_ASSERT(wt != NULL);

	widget_get_color_mode(owner, &clr);

	widget_set_user_id(wt, IDC_HORZBOX);
	widget_set_color_mode(wt, &clr);
	horzbox_set_target(wt, owner);

	widget_get_client_rect(owner, &xr);
	xr.y = xr.h - HORZBOX_BAR_WIDTH;
	xr.h = HORZBOX_BAR_WIDTH;
	widget_client_to_screen(owner, RECTPOINT(&xr));

	widget_move(wt, RECTPOINT(&xr));
	widget_size(wt, RECTSIZE(&xr));
	widget_set_alpha(wt, 250);

	widget_set_timer(wt, DEF_TIPTIME);

	widget_show(wt, WS_SHOW_NORMAL);

	return wt;
}