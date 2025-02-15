﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc owner control documilk

	@module	ownerctrl.c | implement file

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

typedef struct _owner_delta_t{
	vword_t var;

	res_win_t hsc;
	res_win_t vsc;
}owner_delta_t;

#define GETOWNERDELTA(ph) 	(owner_delta_t*)widget_get_user_delta(ph)
#define SETOWNERDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/***************************************************************************************/

static int noti_owner_owner(res_win_t widget, unsigned int code, void* data)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	NOTICE_OWNER nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;
	nf.data = data;
	nf.ret = 0;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);
	return nf.ret;
}

void noti_owner_reset_scroll(res_win_t widget, bool_t bUpdate)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	if (widget_is_valid(ptd->vsc))
	{
		if (bUpdate)
			widget_update(ptd->vsc);
		else
			widget_close(ptd->vsc, 0);
	}

	if (widget_is_valid(ptd->hsc))
	{
		if (bUpdate)
			widget_update(ptd->hsc);
		else
			widget_close(ptd->hsc, 0);
	}
}

static void _ownerctrl_reset_page(res_win_t widget)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	xrect_t xr;
	PAGEINFO pc = { 0 };

	noti_owner_owner(widget, NC_OWNERCALC, (void*)&pc);

	widget_get_client_rect(widget, &xr);

	widget_reset_paging(widget, xr.w, xr.h, pc.total_width, pc.total_height, pc.line_width, pc.line_height);
}

/********************************************************************************************/
int hand_owner_create(res_win_t widget, void* data)
{
	owner_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (owner_delta_t*)xmem_alloc(sizeof(owner_delta_t));

	SETOWNERDELTA(widget, ptd);

	return 0;
}

void hand_owner_destroy(res_win_t widget)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (widget_is_valid(ptd->hsc))
		widget_destroy(ptd->hsc);

	if (widget_is_valid(ptd->vsc))
		widget_destroy(ptd->vsc);

	xmem_free(ptd);

	SETOWNERDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_owner_keydown(res_win_t widget, dword_t ks, int key)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);
	int ch;

	XDK_ASSERT(ptd != NULL);

	ch = key;

	noti_owner_owner(widget, NC_OWNERKEY, (void*)&ch);
}

void hand_owner_mouse_move(res_win_t widget, dword_t dw, const xpoint_t* pxp)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	noti_owner_owner(widget, NC_OWNERMOVE, (void*)pxp);
}

void hand_owner_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (widget_is_valid(ptd->hsc))
	{
		widget_destroy(ptd->hsc);
	}

	if (widget_is_valid(ptd->vsc))
	{
		widget_destroy(ptd->vsc);
	}

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}
}

void hand_owner_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	noti_owner_owner(widget, NC_OWNERLBCLK, (void*)pxp);
}

void hand_owner_lbutton_dbclick(res_win_t widget, const xpoint_t* pxp)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	noti_owner_owner(widget, NC_OWNERDBCLK, (void*)pxp);
}

void hand_owner_rbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (widget_is_valid(ptd->hsc))
	{
		widget_destroy(ptd->hsc);
	}

	if (widget_is_valid(ptd->vsc))
	{
		widget_destroy(ptd->vsc);
	}
}

void hand_owner_rbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	noti_owner_owner(widget, NC_OWNERRBCLK, (void*)pxp);
}

void hand_owner_size(res_win_t widget, int code, const xsize_t* prs)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	noti_owner_reset_scroll(widget, 0);

	ownerctrl_redraw(widget);
}

void hand_owner_scroll(res_win_t widget, bool_t bHorz, int nLine)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_owner_wheel(res_win_t widget, bool_t bHorz, int nDelta)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	scroll_t scr = { 0 };
	int nLine;
	res_win_t win;

	XDK_ASSERT(ptd != NULL);

	widget_get_scroll_info(widget, bHorz, &scr);

	if (bHorz)
		nLine = (nDelta > 0) ? scr.min : -scr.min;
	else
		nLine = (nDelta < 0) ? scr.min : -scr.min;

	if (widget_hand_scroll(widget, bHorz, nLine))
	{
		if (!bHorz && !(widget_get_style(widget) & WD_STYLE_VSCROLL))
		{
			if (!widget_is_valid(ptd->vsc))
			{
				ptd->vsc = show_vertbox(widget);
			}
			else
			{
				widget_update(ptd->vsc);
			}
		}

		if (bHorz && !(widget_get_style(widget) & WD_STYLE_HSCROLL))
		{
			if (!widget_is_valid(ptd->hsc))
			{
				ptd->hsc = show_horzbox(widget);
			}
			else
			{
				widget_update(ptd->hsc);
			}
		}

		return;
	}

	win = widget_get_parent(widget);

	if (widget_is_valid(win))
	{
		widget_scroll(win, bHorz, nLine);
	}
}

void hand_owner_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	visual_t rdc;
	canvas_t canv;
	xrect_t xr = { 0 };
	viewbox_t vb = { 0 };
	xbrush_t xb = { 0 };

	drawing_interface ifv = {0};

	XDK_ASSERT(ptd != NULL);

	widget_get_xbrush(widget, &xb);
	
	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	

	widget_get_view_rect(widget, &vb);

	noti_owner_owner(widget, NC_OWNERDRAW, (void*)rdc);

	end_canvas_paint(canv, dc, pxr);
}

/************************************************************************************************/
res_win_t ownerctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, res_win_t wparent)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_owner_create)
		EVENT_ON_DESTROY(hand_owner_destroy)

		EVENT_ON_PAINT(hand_owner_paint)

		EVENT_ON_SIZE(hand_owner_size)

		EVENT_ON_SCROLL(hand_owner_scroll)
		EVENT_ON_WHEEL(hand_owner_wheel)

		EVENT_ON_KEYDOWN(hand_owner_keydown)

		EVENT_ON_MOUSE_MOVE(hand_owner_mouse_move)

		EVENT_ON_LBUTTON_DOWN(hand_owner_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_owner_lbutton_up)
		EVENT_ON_LBUTTON_DBCLICK(hand_owner_lbutton_dbclick)
		EVENT_ON_RBUTTON_DOWN(hand_owner_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_owner_rbutton_up)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void ownerctrl_redraw(res_win_t widget)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	_ownerctrl_reset_page(widget);

	widget_update(widget);

	widget_erase(widget, NULL);
}

void ownerctrl_set_delta(res_win_t widget, vword_t var)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->var = var;
}

vword_t ownerctrl_get_delta(res_win_t widget)
{
	owner_delta_t* ptd = GETOWNERDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->var;
}