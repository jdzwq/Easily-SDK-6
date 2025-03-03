﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc check control document

	@module	checkbox.c | implement file

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

typedef struct _checkbox_delta_t{
	bool_t on;
}checkbox_delta_t;

#define GETCHECKBOXDELTA(ph) 	(checkbox_delta_t*)widget_get_user_delta(ph)
#define SETCHECKBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/********************************************************************************/
void _checkbox_reset_page(res_win_t widget)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);
	xrect_t xr;

	widget_get_client_rect(widget, &xr);

	widget_reset_paging(widget, xr.w, xr.h, xr.w, xr.h, 0, 0);

	widget_reset_scroll(widget, 0);
}
////////////////////////////////////////////////////////////////////////////////////////
void noti_checkbox_command(res_win_t widget, int code, vword_t data)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);

	if (widget_has_subproc(widget))
		widget_post_command(widget, code, IDC_SELF, data);
	else
		widget_post_command(widget_get_owner(widget), code, widget_get_user_id(widget), data);
}

void checkbox_on_switch(res_win_t widget)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);

	if (ptd->on)
		ptd->on = 0;
	else
		ptd->on = 1;

	widget_erase(widget, NULL);

	noti_checkbox_command(widget, COMMAND_UPDATE, (vword_t)NULL);
}

/*********************************************************************************/
int hand_checkbox_create(res_win_t widget, void* data)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);

	widget_hand_create(widget);

	ptd = (checkbox_delta_t*)xmem_alloc(sizeof(checkbox_delta_t));
	xmem_zero((void*)ptd, sizeof(checkbox_delta_t));

	SETCHECKBOXDELTA(widget, ptd);

	return 0;
}

void hand_checkbox_destroy(res_win_t widget)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETCHECKBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_checkbox_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);
	
}

void hand_checkbox_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);

	checkbox_on_switch(widget);
}

void hand_checkbox_keydown(res_win_t widget, dword_t ks, int key)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);

	switch (key)
	{
	case KEY_SPACE:
		checkbox_on_switch(widget);
		break;
	}
}

void hand_checkbox_size(res_win_t widget, int code, const xsize_t* prs)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);
	
	_checkbox_reset_page(widget);

	widget_erase(widget, NULL);
}

void hand_checkbox_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);

	xrect_t xr;	
	xfont_t xf;
	xbrush_t xb;
	xpen_t xp;

	visual_t rdc;
	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	widget_get_xfont(widget, &xf);
	widget_get_xbrush(widget, &xb);
	widget_get_xpen(widget, &xp);

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);
	

	
	
	
	
	

	widget_get_client_rect(widget, &xr);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	draw_checkbox(pif, &xf, ptd->on);

	

	end_canvas_paint(canv, dc, pxr);
	
}

/***************************************************************************************/
res_win_t checkbox_create(res_win_t widget, dword_t style, const xrect_t* pxr)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_checkbox_create)
		EVENT_ON_DESTROY(hand_checkbox_destroy)

		EVENT_ON_PAINT(hand_checkbox_paint)

		EVENT_ON_SIZE(hand_checkbox_size)

		EVENT_ON_KEYDOWN(hand_checkbox_keydown)

		EVENT_ON_LBUTTON_DOWN(hand_checkbox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_checkbox_lbutton_up)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void checkbox_popup_size(res_win_t widget, xsize_t* pxs)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);
	measure_interface im = { 0 };
	xfont_t xf = { 0 };

	XDK_ASSERT(ptd != NULL);

	widget_get_xfont(widget, &xf);

	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_checkbox_size(&im, &xf, pxs);

	widget_size_to_pt(widget, pxs);

	widget_adjust_size(widget_get_style(widget), pxs);
}

void checkbox_set_state(res_win_t widget, bool_t cur)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->on = cur;

	widget_erase(widget, NULL);
}

bool_t checkbox_get_state(res_win_t widget)
{
	checkbox_delta_t* ptd = GETCHECKBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->on;
}
