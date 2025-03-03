﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc calendar control document

	@module	calendarctrl.c | implement file

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

#define CALENDAR_LINE_FEED		(float)50
#define CALENDAR_DAILY_MIN_WIDTH	(float)10
#define CALENDAR_DAILY_MIN_HEIGHT	(float)10

typedef struct _calendar_delta_t{
	link_t_ptr calendar;
	link_t_ptr daily;
	link_t_ptr hover;

	int org_hint;
	int org_x, org_y;
	int cur_x, cur_y;

}calendar_delta_t;

#define GETCALENDARDELTA(ph) 	(calendar_delta_t*)widget_get_user_delta(ph)
#define SETCALENDARDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/******************************************calendar event********************************************************/

static void _calendarctrl_daily_rect(res_win_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	calc_calendar_daily_rect(ptd->calendar, ilk, pxr);

	widget_rect_to_pt(widget, pxr);
}

static void _calendarctrl_reset_page(res_win_t widget)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	int pw, ph, fw, fh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	xs.fw = get_calendar_width(ptd->calendar);
	xs.fh = get_calendar_height(ptd->calendar);

	widget_size_to_pt(widget, &xs);
	fw = xs.w;
	fh = xs.h;

	xs.fw = (float)10;
	xs.fh = (float)10;
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	widget_reset_paging(widget, pw, ph, fw, fh, lw, lh);

	widget_reset_scroll(widget, 1);

	widget_reset_scroll(widget, 0);
}

static void _calendarctrl_ensure_visible(res_win_t widget)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	xrect_t xr = { 0 };

	if (!ptd->daily)
		return;

	_calendarctrl_daily_rect(widget, ptd->daily, &xr);

	widget_ensure_visible(widget, &xr, 1);
}
/*********************************************************************************************************/
int noti_calendar_owner(res_win_t widget, unsigned int code, link_t_ptr ptr, link_t_ptr ilk, void* data)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	NOTICE_CALENDAR nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;

	nf.data = data;

	nf.calendar = ptr;
	nf.daily = ilk;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);
	return nf.ret;
}

void noti_calendar_reset_select(res_win_t widget)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	link_t_ptr ilk;
	int count = 0;

	ilk = get_calendar_next_daily(ptd->calendar, LINK_FIRST);
	while (ilk)
	{
		if (get_calendar_daily_selected(ilk))
		{
			set_calendar_daily_selected(ilk, 0);
			noti_calendar_owner(widget, NC_CALENDARDAILYSELECTED, ptd->calendar, ilk, NULL);

			count++;
		}

		ilk = get_calendar_next_daily(ptd->calendar, ilk);
	}

	if (count)
	{
		widget_erase(widget, NULL);
	}
}

void noti_calendar_daily_selected(res_win_t widget, link_t_ptr ilk)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	xrect_t xr;
	bool_t b_check;

	b_check = get_calendar_daily_selected(ilk);

	if (b_check)
		set_calendar_daily_selected(ilk, 0);
	else
		set_calendar_daily_selected(ilk, 1);

	noti_calendar_owner(widget, NC_CALENDARDAILYSELECTED, ptd->calendar, ilk, NULL);

	_calendarctrl_daily_rect(widget, ilk, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

bool_t noti_calendar_daily_changing(res_win_t widget)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd->daily);

	if (noti_calendar_owner(widget, NC_CALENDARDAILYCHANGING, ptd->calendar, ptd->daily, NULL))
		return (bool_t)0;

	_calendarctrl_daily_rect(widget, ptd->daily, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	ptd->daily = NULL;

	widget_erase(widget, &xr);

	return (bool_t)1;
}

void noti_calendar_daily_changed(res_win_t widget, link_t_ptr ilk)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ilk);
	XDK_ASSERT(!ptd->daily);

	ptd->daily = ilk;

	_calendarctrl_daily_rect(widget, ptd->daily, &xr);

	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);

	noti_calendar_owner(widget, NC_CALENDARDAILYCHANGED, ptd->calendar, ilk, NULL);
}

void noti_calendar_daily_enter(res_win_t widget, link_t_ptr ilk)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	XDK_ASSERT(ilk);
	XDK_ASSERT(!ptd->hover);

	ptd->hover = ilk;

	widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
}

void noti_calendar_daily_leave(res_win_t widget)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	XDK_ASSERT(ptd->hover != NULL);

	ptd->hover = NULL;

	widget_track_mouse(widget, MS_TRACK_HOVER | MS_TRACK_LEAVE);
}

void noti_calendar_daily_hover(res_win_t widget, int x, int y)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	xpoint_t pt;

	XDK_ASSERT(ptd->hover != NULL);

	pt.x = x;
	pt.y = y;
	noti_calendar_owner(widget, NC_CALENDARDAILYHOVER, ptd->calendar, ptd->hover, (void*)&pt);
}

/*******************************************************************************/
int hand_calendar_create(res_win_t widget, void* data)
{
	calendar_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (calendar_delta_t*)xmem_alloc(sizeof(calendar_delta_t));
	xmem_zero((void*)ptd, sizeof(calendar_delta_t));

	SETCALENDARDELTA(widget, ptd);

	return 0;
}

void hand_calendar_destroy(res_win_t widget)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETCALENDARDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_calendar_size(res_win_t widget, int code, const xsize_t* prs)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	if (!ptd->calendar)
		return;

	calendarctrl_redraw(widget);
}

void hand_calendar_scroll(res_win_t widget, bool_t bHorz, int nLine)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	if (!ptd->calendar)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_calendar_wheel(res_win_t widget, bool_t bHorz, int nDelta)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	scroll_t scr = { 0 };
	int nLine;
	res_win_t win;

	if (!ptd->calendar)
		return;

	widget_get_scroll_info(widget, bHorz, &scr);

	if (bHorz)
		nLine = (nDelta > 0) ? scr.min : -scr.min;
	else
		nLine = (nDelta < 0) ? scr.min : -scr.min;

	if (widget_hand_scroll(widget, bHorz, nLine))
		return;

	win = widget_get_parent(widget);

	if (widget_is_valid(win))
	{
		widget_scroll(win, bHorz, nLine);
	}
}

void hand_calendar_mouse_move(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	int nHint;
	link_t_ptr ilk;
	xpoint_t pt;

	if (!ptd->calendar)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(widget, &pt);

	ilk = NULL;
	nHint = calc_calendar_hint(ptd->calendar, &pt, &ilk);

	if (widget_is_hotvoer(widget))
	{
		if (nHint == CALENDAR_HINT_DAILY && !ptd->hover && ilk)
		{
			noti_calendar_daily_enter(widget, ilk);
			return;
		}

		if (nHint == CALENDAR_HINT_DAILY && ptd->hover && ptd->hover != ilk)
		{
			noti_calendar_daily_leave(widget);
			return;
		}

		if (nHint != CALENDAR_HINT_DAILY && ptd->hover)
		{
			noti_calendar_daily_leave(widget);
		}
	}
}

void hand_calendar_mouse_hover(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	if (!ptd->calendar)
		return;

	if (ptd->hover)
		noti_calendar_daily_hover(widget, pxp->x, pxp->y);
}

void hand_calendar_mouse_leave(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	if (!ptd->calendar)
		return;

	if (ptd->hover)
		noti_calendar_daily_leave(widget);
}

void hand_calendar_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	int nHint;
	link_t_ptr ilk;
	bool_t bRe;
	xpoint_t pt;

	if (!ptd->calendar)
		return;

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(widget, &pt);

	ilk = NULL;
	nHint = calc_calendar_hint(ptd->calendar, &pt, &ilk);
	bRe = (ilk == ptd->daily) ? 1 : 0;

	switch (nHint)
	{
	case CALENDAR_HINT_DAILY:
		if (widget_key_state(widget, KEY_CONTROL))
		{
			noti_calendar_daily_selected(widget, ilk);
		}
		break;
	case CALENDAR_HINT_NONE:
		noti_calendar_reset_select(widget);
		break;
	}
}

void hand_calendar_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	int nHint;
	link_t_ptr ilk;
	bool_t bRe;
	xpoint_t pt;

	if (!ptd->calendar)
		return;

	pt.x = pxp->x;
	pt.y = pxp->y;
	widget_point_to_tm(widget, &pt);

	ilk = NULL;
	nHint = calc_calendar_hint(ptd->calendar, &pt, &ilk);

	noti_calendar_owner(widget, NC_CALENDARLBCLK, ptd->calendar, ilk, (void*)pxp);

	bRe = (ilk == ptd->daily) ? 1 : 0;

	if (ptd->daily && !bRe)
	{
		if (!noti_calendar_daily_changing(widget))
			return;
	}

	if (ilk && !bRe)
	{
		noti_calendar_daily_changed(widget, ilk);
	}
}

void hand_calendar_lbutton_dbclick(res_win_t widget, const xpoint_t* pxp)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	if (!ptd->calendar)
		return;

	noti_calendar_owner(widget, NC_CALENDARDBCLK, ptd->calendar, ptd->daily, (void*)pxp);
}

void hand_calendar_rbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	if (!ptd->calendar)
		return;
}

void hand_calendar_rbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	if (!ptd->calendar)
		return;

	noti_calendar_owner(widget, NC_CALENDARRBCLK, ptd->calendar, ptd->daily, (void*)pxp);
}

void hand_calendar_keydown(res_win_t widget, dword_t ks, int key)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	if (!ptd->calendar)
		return;

}

void hand_calendar_char(res_win_t widget, tchar_t nChar)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	if (!ptd->calendar)
		return;
}

void hand_calendar_notice(res_win_t widget, NOTICE* pnt)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	if (!ptd->calendar)
		return;
}

void hand_calendar_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	xrect_t xr = { 0 };
	xfont_t xf = { 0 };
	xbrush_t xb = { 0 };
	xpen_t xp = { 0 };
	xcolor_t xc = { 0 };
	visual_t rdc;
	link_t_ptr ilk;

	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	if (!ptd->calendar)
		return;

	widget_get_xfont(widget, &xf);
	widget_get_xbrush(widget, &xb);
	widget_get_xpen(widget, &xp);

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);
	

	
	
	
	
	

	widget_get_client_rect(widget, &xr);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
	get_visual_interface(rdc, &ifv);
	widget_get_view_rect(widget, (viewbox_t*)(&ifv.rect));

	widget_get_xbrush(widget, &xb);
	widget_get_xpen(widget, &xp);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	draw_calendar(pif, ptd->calendar);

	//draw focus
	if (ptd->daily)
	{
		_calendarctrl_daily_rect(widget, ptd->daily, &xr);

		parse_xcolor(&xc, DEF_ENABLE_COLOR);

		draw_focus_raw(&ifv, &xc, &xr, ALPHA_SOLID);
	}

	//draw check
	parse_xcolor(&xc, DEF_ALPHA_COLOR);

	ilk = get_calendar_next_daily(ptd->calendar, LINK_FIRST);
	while (ilk)
	{
		if (get_calendar_daily_selected(ilk))
		{
			_calendarctrl_daily_rect(widget, ilk, &xr);
			(*ifv.pf_alphablend_rect)(ifv.ctx, &xc, &xr, ALPHA_TRANS);
		}
		ilk = get_calendar_next_daily(ptd->calendar, ilk);
	}

	

	end_canvas_paint(canv, dc, pxr);
	
}

/***********************************************function********************************************************/

res_win_t calendarctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, res_win_t wparent)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_calendar_create)
		EVENT_ON_DESTROY(hand_calendar_destroy)

		EVENT_ON_PAINT(hand_calendar_paint)

		EVENT_ON_SIZE(hand_calendar_size)

		EVENT_ON_SCROLL(hand_calendar_scroll)
		EVENT_ON_WHEEL(hand_calendar_wheel)

		EVENT_ON_KEYDOWN(hand_calendar_keydown)
		EVENT_ON_CHAR(hand_calendar_char)

		EVENT_ON_MOUSE_MOVE(hand_calendar_mouse_move)
		EVENT_ON_MOUSE_HOVER(hand_calendar_mouse_hover)
		EVENT_ON_MOUSE_LEAVE(hand_calendar_mouse_leave)

		EVENT_ON_LBUTTON_DBCLICK(hand_calendar_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_calendar_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_calendar_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_calendar_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_calendar_rbutton_up)

		EVENT_ON_NOTICE(hand_calendar_notice)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void calendarctrl_attach(res_win_t widget, link_t_ptr ptr)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(ptr && is_calendar_doc(ptr));

	ptd->calendar = ptr;
	ptd->daily = NULL;

	calendarctrl_redraw(widget);
}

link_t_ptr calendarctrl_detach(res_win_t widget)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	link_t_ptr data;

	XDK_ASSERT(ptd != NULL);

	data = ptd->calendar;
	ptd->calendar = NULL;
	ptd->daily = NULL;

	widget_erase(widget, NULL);

	return data;
}

link_t_ptr calendarctrl_fetch(res_win_t widget)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->calendar;
}

void calendarctrl_redraw(res_win_t widget)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	link_t_ptr ilk;
	bool_t b_valid;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->calendar)
		return;

	b_valid = 0;
	ilk = get_calendar_next_daily(ptd->calendar, LINK_FIRST);
	while (ilk)
	{
		if (ilk == ptd->daily)
			b_valid = 1;

		noti_calendar_owner(widget, NC_CALENDARDAILYCALCED, ptd->calendar, ilk, NULL);

		ilk = get_calendar_next_daily(ptd->calendar, ilk);
	}
	
	noti_calendar_owner(widget, NC_CALENDARCALCED, ptd->calendar, NULL, NULL);

	if (!b_valid)
	{
		ptd->daily = NULL;
	}
	ptd->hover = NULL;

	_calendarctrl_reset_page(widget);

	widget_update(widget);
}

void calendarctrl_redraw_daily(res_win_t widget, link_t_ptr ilk)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	xrect_t xr;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->calendar)
		return;

#ifdef _DEBUG
	if(!is_calendar_daily(ptd->calendar, ilk))
		return;
#endif

	noti_calendar_owner(widget, NC_CALENDARDAILYCALCED, ptd->calendar, ilk, NULL);

	_calendarctrl_daily_rect(widget, ilk, &xr);
	pt_expand_rect(&xr, DEF_OUTER_FEED, DEF_OUTER_FEED);

	widget_erase(widget, &xr);
}

void calendarctrl_tabskip(res_win_t widget, int nSkip)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	link_t_ptr ilk = NULL;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->calendar)
		return;

	switch (nSkip)
	{
	case TABORDER_LEFT:
	case TABORDER_UP:
		if (ptd->daily == NULL)
			ilk = get_calendar_prev_daily(ptd->calendar, LINK_LAST);
		else
			ilk = get_calendar_prev_daily(ptd->calendar, ptd->daily);
		break;
	case TABORDER_RIGHT:
	case TABORDER_DOWN:
		if (ptd->daily == NULL)
			ilk = get_calendar_next_daily(ptd->calendar, LINK_FIRST);
		else
			ilk = get_calendar_next_daily(ptd->calendar, ptd->daily);
		break;
	case TABORDER_HOME:
		ilk = get_calendar_next_daily(ptd->calendar, LINK_FIRST);
		break;
	case TABORDER_END:
		ilk = get_calendar_prev_daily(ptd->calendar, LINK_LAST);
		break;
	}

	calendarctrl_set_focus_daily(widget, ilk);
}

bool_t calendarctrl_set_focus_daily(res_win_t widget, link_t_ptr ilk)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	bool_t bRe;

	XDK_ASSERT(ptd != NULL);

	if (!ptd->calendar)
		return 0;

	if (ilk == LINK_FIRST)
		ilk = get_calendar_next_daily(ptd->calendar, LINK_FIRST);
	else if (ilk == LINK_LAST)
		ilk = get_calendar_prev_daily(ptd->calendar, LINK_LAST);

	bRe = (ilk == ptd->daily) ? (bool_t)1 : (bool_t)0;
	if (bRe)
		return (bool_t)1;

	if (ptd->daily && !bRe)
	{
		if (!noti_calendar_daily_changing(widget))
			return (bool_t)0;
	}

	if (ilk && !bRe)
	{
		noti_calendar_daily_changed(widget, ilk);

		_calendarctrl_ensure_visible(widget);
	}

	return (bool_t)1;
}

link_t_ptr calendarctrl_get_focus_daily(res_win_t widget)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->calendar)
		return NULL;

	return ptd->daily;
}

void calendarctrl_get_calendar_daily_rect(res_win_t widget, link_t_ptr ilk, xrect_t* pxr)
{
	calendar_delta_t* ptd = GETCALENDARDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	if (!ptd->calendar)
		return;

#ifdef _DEBUG
	XDK_ASSERT(is_calendar_daily(ptd->calendar, ilk));
#endif

	_calendarctrl_daily_rect(widget, ilk, pxr);
}
