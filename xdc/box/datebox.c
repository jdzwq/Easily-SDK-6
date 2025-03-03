﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc number control document

	@module	datebox.c | implement file

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

typedef struct _datebox_delta_t{
	xdate_t dt;
}datebox_delta_t;

#define GETDATEBOXDELTA(ph) 	(datebox_delta_t*)widget_get_user_delta(ph)
#define SETDATEBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/**************************************************************************************************/
void noti_datebox_command(res_win_t widget, int code, vword_t data)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);

	if (widget_has_subproc(widget))
		widget_post_command(widget, code, IDC_SELF, data);
	else
		widget_post_command(widget_get_owner(widget), code, widget_get_user_id(widget), data);
}

void datebox_on_prev_month(res_win_t widget)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);

	ptd->dt.mon--;

	if (!ptd->dt.mon)
	{
		ptd->dt.year--;
		ptd->dt.mon = 12;
	}

	widget_erase(widget, NULL);
}

void datebox_on_next_month(res_win_t widget)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);

	ptd->dt.mon++;

	if (ptd->dt.mon > 12)
	{
		ptd->dt.year++;
		ptd->dt.mon = 1;
	}

	widget_erase(widget, NULL);
}

void datebox_on_select_day(res_win_t widget, int day)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);

	ptd->dt.day = day;

	widget_erase(widget, NULL);

	noti_datebox_command(widget, COMMAND_UPDATE, (vword_t)NULL);
}
/**************************************************************************************************/
int hand_datebox_create(res_win_t widget, void* data)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);

	widget_hand_create(widget);

	ptd = (datebox_delta_t*)xmem_alloc(sizeof(datebox_delta_t));

	SETDATEBOXDELTA(widget, ptd);

	get_loc_date(&ptd->dt);

	return 0;
}

void hand_datebox_destroy(res_win_t widget)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);

	xmem_free(ptd);

	SETDATEBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_datebox_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);

}

void hand_datebox_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);

	measure_interface im = { 0 };
	xfont_t xf = { 0 };
	xpoint_t pt;
	int hint;
	int day;

	pt.x = pxp->x;
	pt.y = pxp->y;

	widget_point_to_tm(widget, &pt);

	widget_get_xfont(widget, &xf);

	get_canvas_measure(widget_get_canvas(widget), &im);

	day = 0;
	hint = calc_datebox_hint(&im, &xf, &pt, &ptd->dt, &day);

	if (hint == DATEBOX_HINT_PREV)
		datebox_on_prev_month(widget);
	else if (hint == DATEBOX_HINT_NEXT)
		datebox_on_next_month(widget);
	else if (hint == DATEBOX_HINT_DAYS)
	{
		datebox_on_select_day(widget, day);

		noti_datebox_command(widget, COMMAND_CHANGE, (vword_t)NULL);
	}
}

void hand_datebox_size(res_win_t widget, int code, const xsize_t* prs)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);
	
	widget_erase(widget, NULL);
}

void hand_datebox_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);
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

	draw_datebox(pif, &xf, &ptd->dt);

	

	end_canvas_paint(canv, dc, pxr);
	
}

/*******************************************************************************************************/
res_win_t datebox_create(res_win_t widget, dword_t style, const xrect_t* pxr)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_datebox_create)
		EVENT_ON_DESTROY(hand_datebox_destroy)

		EVENT_ON_PAINT(hand_datebox_paint)

		EVENT_ON_SIZE(hand_datebox_size)

		EVENT_ON_LBUTTON_DOWN(hand_datebox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_datebox_lbutton_up)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void datebox_popup_size(res_win_t widget, xsize_t* pxs)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);
	measure_interface im = { 0 };
	xfont_t xf = { 0 };

	XDK_ASSERT(ptd != NULL);

	widget_get_xfont(widget, &xf);

	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_datebox_size(&im, &xf, pxs);

	widget_size_to_pt(widget, pxs);

	widget_adjust_size(widget_get_style(widget), pxs);
}

void datebox_set_date(res_win_t widget, const xdate_t* pxd)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (pxd)
		xmem_copy((void*)&ptd->dt, (void*)pxd, sizeof(xdate_t));
	else
		get_loc_date(&ptd->dt);

	widget_erase(widget, NULL);
}

void datebox_get_date(res_win_t widget, xdate_t* pxd)
{
	datebox_delta_t* ptd = GETDATEBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (pxd)
		xmem_copy((void*)pxd, (void*)&ptd->dt, sizeof(xdate_t));
}
