﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc radio control document

	@module	radiobox.c | implement file

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

typedef struct _radiobox_delta_t{
	bool_t on;
}radiobox_delta_t;

#define GETRADIOBOXDELTA(ph) 	(radiobox_delta_t*)widget_get_user_delta(ph)
#define SETRADIOBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/********************************************************************************/
void noti_radiobox_command(res_win_t widget, int code, vword_t data)
{
	radiobox_delta_t* ptd = GETRADIOBOXDELTA(widget);

	if (widget_has_subproc(widget))
		widget_post_command(widget, code, IDC_SELF, data);
	else
		widget_post_command(widget_get_owner(widget), code, widget_get_user_id(widget), data);
}
/*********************************************************************************/
int hand_radiobox_create(res_win_t widget, void* data)
{
	radiobox_delta_t* ptd = GETRADIOBOXDELTA(widget);

	widget_hand_create(widget);

	ptd = (radiobox_delta_t*)xmem_alloc(sizeof(radiobox_delta_t));
	xmem_zero((void*)ptd, sizeof(radiobox_delta_t));

	SETRADIOBOXDELTA(widget, ptd);

	return 0;
}

void hand_radiobox_destroy(res_win_t widget)
{
	radiobox_delta_t* ptd = GETRADIOBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETRADIOBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_radiobox_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	radiobox_delta_t* ptd = GETRADIOBOXDELTA(widget);
	
}

void hand_radiobox_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	radiobox_delta_t* ptd = GETRADIOBOXDELTA(widget);
	
	measure_interface im = { 0 };
	xfont_t xf = { 0 };
	xpoint_t pt;
	int hint;

	pt.x = pxp->x;
	pt.y = pxp->y;

	widget_point_to_tm(widget, &pt);

	widget_get_xfont(widget, &xf);

	get_canvas_measure(widget_get_canvas(widget), &im);

	hint = calc_radiobox_hint(&im, &xf, &pt);

	if (hint == RADIOBOX_HINT_ON)
	{
		ptd->on = 1;
		widget_erase(widget, NULL);

		noti_radiobox_command(widget, COMMAND_UPDATE, (vword_t)NULL);
	}
	else if (hint == RADIOBOX_HINT_OFF)
	{
		ptd->on = 0;
		widget_erase(widget, NULL);

		noti_radiobox_command(widget, COMMAND_UPDATE, (vword_t)NULL);
	}
}

void hand_radiobox_size(res_win_t widget, int code, const xsize_t* prs)
{
	radiobox_delta_t* ptd = GETRADIOBOXDELTA(widget);
	
	widget_erase(widget, NULL);
}

void hand_radiobox_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	radiobox_delta_t* ptd = GETRADIOBOXDELTA(widget);
	visual_t rdc;
	xrect_t xr;
	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	xfont_t xf;
	xbrush_t xb;
	xpen_t xp;

	widget_get_xfont(widget, &xf);
	widget_get_xbrush(widget, &xb);
	widget_get_xpen(widget, &xp);

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);
	

	
	
	
	
	

	widget_get_client_rect(widget, &xr);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	draw_radiobox(pif, &xf, ptd->on);

	

	end_canvas_paint(canv, dc, pxr);
	
}

/***************************************************************************************/
res_win_t radiobox_create(res_win_t widget, dword_t style, const xrect_t* pxr)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_radiobox_create)
		EVENT_ON_DESTROY(hand_radiobox_destroy)

		EVENT_ON_PAINT(hand_radiobox_paint)

		EVENT_ON_SIZE(hand_radiobox_size)

		EVENT_ON_LBUTTON_DOWN(hand_radiobox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_radiobox_lbutton_up)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void radiobox_popup_size(res_win_t widget, xsize_t* pxs)
{
	radiobox_delta_t* ptd = GETRADIOBOXDELTA(widget);
	measure_interface im = { 0 };
	xfont_t xf = { 0 };

	XDK_ASSERT(ptd != NULL);

	widget_get_xfont(widget, &xf);

	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_radiobox_size(&im, &xf, pxs);

	widget_size_to_pt(widget, pxs);

	widget_adjust_size(widget_get_style(widget), pxs);
}

void radiobox_set_state(res_win_t widget, bool_t cur)
{
	radiobox_delta_t* ptd = GETRADIOBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->on = cur;

	widget_erase(widget, NULL);
}

bool_t radiobox_get_state(res_win_t widget)
{
	radiobox_delta_t* ptd = GETRADIOBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->on;
}
