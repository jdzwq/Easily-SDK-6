﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc navi control document

	@module	navibox.c | implement file

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

typedef struct _navibox_delta_t{
	res_win_t target;
	res_win_t keybox;
}navibox_delta_t;

#define GETNAVIBOXDELTA(ph) 	(navibox_delta_t*)widget_get_user_delta(ph)
#define SETNAVIBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/*********************************************************************************/
void navibox_on_home(res_win_t widget)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);

	widget_post_key(ptd->target, KEY_HOME);

	widget_erase(widget, NULL);
}

void navibox_on_end(res_win_t widget)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);

	widget_post_key(ptd->target, KEY_END);

	widget_erase(widget, NULL);
}

void navibox_on_prev(res_win_t widget)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);

	widget_post_key(ptd->target, KEY_PAGEUP);

	widget_erase(widget, NULL);
}

void navibox_on_next(res_win_t widget)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);

	widget_post_key(ptd->target, KEY_PAGEDOWN);

	widget_erase(widget, NULL);
}

void navibox_on_keyboard(res_win_t widget)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);
	xrect_t xr_owner, xr = { 0 };
	clr_mod_t clr;
	res_win_t owner;

	if (widget_is_valid(ptd->keybox))
	{
		widget_destroy(ptd->keybox);
		ptd->keybox = NULL;

		widget_erase(widget, NULL);
		return;
	}

	owner = widget_get_owner(widget);
	if (!widget_is_valid(owner))
		return;

	ptd->keybox = keybox_create(widget, WD_STYLE_POPUP | WD_STYLE_NOACTIVE, &xr);
	
	widget_get_color_mode(widget, &clr);

	widget_set_color_mode(ptd->keybox, &clr);

	widget_get_window_rect(owner, &xr_owner);
	widget_get_window_rect(widget, &xr);

	xr_owner.x = xr.x;
	xr_owner.w = xr.w;
	if (xr.y - xr_owner.y < (xr_owner.y + xr_owner.h) - (xr.y + xr.h))
	{
		xr.y += (xr.h + 1);
		keybox_popup_size(ptd->keybox, RECTSIZE(&xr));
	}
	else
	{
		keybox_popup_size(ptd->keybox, RECTSIZE(&xr));
		xr.y -= (xr.h + 1);
	}
	if (xr.x + xr.w > xr_owner.x + xr_owner.w)
	{
		xr.x = xr_owner.x + xr_owner.w - xr.w;
	}
	
	widget_move(ptd->keybox, RECTPOINT(&xr));
	widget_size(ptd->keybox, RECTSIZE(&xr));
	widget_take(ptd->keybox, (int)WS_TAKE_TOPMOST);
	widget_update(ptd->keybox);
	widget_show(ptd->keybox, WS_SHOW_NORMAL);

	widget_erase(widget, NULL);
}

/*********************************************************************************/

int hand_navibox_create(res_win_t widget, void* data)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);

	widget_hand_create(widget);

	ptd = (navibox_delta_t*)xmem_alloc(sizeof(navibox_delta_t));
	xmem_zero((void*)ptd, sizeof(navibox_delta_t));

	SETNAVIBOXDELTA(widget, ptd);

	return 0;
}

void hand_navibox_destroy(res_win_t widget)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETNAVIBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_navibox_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);
	
}

void hand_navibox_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);
	measure_interface im = { 0 };
	xfont_t xf = { 0 };
	xpoint_t pt;
	int hint;

	pt.x = pxp->x;
	pt.y = pxp->y;

	widget_point_to_tm(widget, &pt);

	widget_get_xfont(widget, &xf);

	get_canvas_measure(widget_get_canvas(widget), &im);

	hint = calc_navibox_hint(&im, &xf, &pt);

	if (hint == NAVIBOX_HINT_HOME)
		navibox_on_home(widget);
	else if(hint == NAVIBOX_HINT_PREV)
		navibox_on_prev(widget);
	else if (hint == NAVIBOX_HINT_NEXT)
		navibox_on_next(widget);
	else if (hint == NAVIBOX_HINT_END)
		navibox_on_end(widget);
	else if (hint == NAVIBOX_HINT_KEYBOARD)
		navibox_on_keyboard(widget);
}

void hand_navibox_size(res_win_t widget, int code, const xsize_t* prs)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);
	
	widget_erase(widget, NULL);
}

void hand_navibox_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);
	visual_t rdc;
	xrect_t xr;
	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	NAVISTATE ns = { 0 };
	xfont_t xf;
	xbrush_t xb;
	xpen_t xp;
	xcolor_t xc_brim, xc_core;

	widget_get_xfont(widget, &xf);
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

	ns.keyboxed = widget_is_valid(ptd->keybox);

	draw_navibox(pif, &xf, &ns);

	

	end_canvas_paint(canv, dc, pxr);
	
}

/***************************************************************************************/
res_win_t navibox_create(res_win_t widget, dword_t style, const xrect_t* pxr)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_navibox_create)
		EVENT_ON_DESTROY(hand_navibox_destroy)

		EVENT_ON_PAINT(hand_navibox_paint)

		EVENT_ON_SIZE(hand_navibox_size)

		EVENT_ON_LBUTTON_DOWN(hand_navibox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_navibox_lbutton_up)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void navibox_set_target(res_win_t widget, res_win_t target)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);

	ptd->target = target;
}

void navibox_popup_size(res_win_t widget, xsize_t* pxs)
{
	navibox_delta_t* ptd = GETNAVIBOXDELTA(widget);
	measure_interface im = { 0 };
	xfont_t xf = { 0 };

	XDK_ASSERT(ptd != NULL);

	widget_get_xfont(widget, &xf);

	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_navibox_size(&im, &xf, pxs);

	widget_size_to_pt(widget, pxs);

	widget_adjust_size(widget_get_style(widget), pxs);
}

