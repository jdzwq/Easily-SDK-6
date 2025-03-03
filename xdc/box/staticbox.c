﻿/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc static control document

	@module	staticbox.c | implement file

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

typedef struct _staticbox_delta_t{
	tchar_t* text;

	int bw,bh;
}staticbox_delta_t;

#define GETSTATICBOXDELTA(ph) 	(staticbox_delta_t*)widget_get_user_delta(ph)
#define SETSTATICBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/*********************************************************************************/
int hand_staticbox_create(res_win_t widget, void* data)
{
	staticbox_delta_t* ptd = GETSTATICBOXDELTA(widget);
	xsize_t xs;

	widget_hand_create(widget);

	ptd = (staticbox_delta_t*)xmem_alloc(sizeof(staticbox_delta_t));
	xmem_zero((void*)ptd, sizeof(staticbox_delta_t));

	SETSTATICBOXDELTA(widget, ptd);

	xs.fw = DEF_TOUCH_SPAN;
	xs.fh = DEF_TOUCH_SPAN;

	widget_size_to_pt(widget, &xs);

	ptd->bw = xs.w;
	ptd->bh = xs.h;

	return 0;
}

void hand_staticbox_destroy(res_win_t widget)
{
	staticbox_delta_t* ptd = GETSTATICBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETSTATICBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_staticbox_lbutton_down(res_win_t widget, const xpoint_t* pxp)
{
	staticbox_delta_t* ptd = GETSTATICBOXDELTA(widget);
	
}

void hand_staticbox_lbutton_up(res_win_t widget, const xpoint_t* pxp)
{
	staticbox_delta_t* ptd = GETSTATICBOXDELTA(widget);
	
	widget_send_command(widget, COMMAND_UPDATE, IDC_SELF, (vword_t)NULL);

	widget_post_command(widget, COMMAND_CHANGE, IDC_SELF, (vword_t)NULL);
}

void hand_staticbox_size(res_win_t widget, int code, const xsize_t* prs)
{
	staticbox_delta_t* ptd = GETSTATICBOXDELTA(widget);
	
	widget_erase(widget, NULL);
}

void hand_staticbox_paint(res_win_t widget, visual_t dc, const xrect_t* pxr)
{
	staticbox_delta_t* ptd = GETSTATICBOXDELTA(widget);
	visual_t rdc;

	xrect_t xr;
	xfont_t xf;
	xface_t xa;
	xbrush_t xb;

	canvas_t canv;
	drawing_interface ifv = {0};

	widget_get_xfont(widget, &xf);
	widget_get_xface(widget, &xa);
	widget_get_xbrush(widget, &xb);

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	widget_get_client_rect(widget, &xr);
	(*ifv.pf_draw_text)(ifv.ctx, &xf, &xa, &xr, ptd->text, -1);

	

	end_canvas_paint(canv, dc, pxr);
}

/***************************************************************************************/
res_win_t staticbox_create(res_win_t widget, dword_t style, const xrect_t* pxr)
{
	if_event_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_staticbox_create)
		EVENT_ON_DESTROY(hand_staticbox_destroy)

		EVENT_ON_PAINT(hand_staticbox_paint)

		EVENT_ON_SIZE(hand_staticbox_size)

		EVENT_ON_LBUTTON_DOWN(hand_staticbox_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_staticbox_lbutton_up)

		EVENT_ON_NC_IMPLEMENT

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void staticbox_popup_size(res_win_t widget, xsize_t* pxs)
{
	staticbox_delta_t* ptd = GETSTATICBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	pxs->w = ptd->bw * 3;
	pxs->h = ptd->bh * 2;
	
	widget_adjust_size(widget_get_style(widget), pxs);
}

void staticbox_set_text(res_win_t widget, const tchar_t* text)
{
	staticbox_delta_t* ptd = GETSTATICBOXDELTA(widget);
	int len;

	XDK_ASSERT(ptd != NULL);

	xsfree(ptd->text);
	
	len = xslen(text);

	ptd->text = xsalloc(len + 1);
	xsncpy(ptd->text, text, len);

	widget_erase(widget, NULL);
}
