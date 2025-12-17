/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc tip control document

	@module	tipbox.c | implement file

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

#include "../xdcobj.h"


typedef struct _TIPBOX_DATA{
	int type;
	const tchar_t* text;
}TIPBOX_DATA;

typedef struct _tipbox_delta_t{
	int n_type;
	tchar_t* sz_text;

}tipbox_delta_t;

#define GETTIPBOXDELTA(ph) 	(tipbox_delta_t*)widget_get_user_delta(ph)
#define SETTIPBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

/*********************************************************************************/
int hand_tipbox_create(widget_t widget, void* data)
{
	tipbox_delta_t* ptd = GETTIPBOXDELTA(widget);
	TIPBOX_DATA* ppd;

	widget_hand_create(widget);

	ptd = (tipbox_delta_t*)xmem_alloc(sizeof(tipbox_delta_t));
	xmem_zero((void*)ptd, sizeof(tipbox_delta_t));

	ppd = (TIPBOX_DATA*)data;
	ptd->n_type = ppd->type;
	ptd->sz_text = xsalloc(xslen(ppd->text) + 1);
	xscpy(ptd->sz_text, ppd->text);

	SETTIPBOXDELTA(widget, ptd);

	widget_set_timer(widget, DEF_TIPTIME);

	return 0;
}

void hand_tipbox_destroy(widget_t widget)
{
	tipbox_delta_t* ptd = GETTIPBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (ptd->sz_text)
		xsfree(ptd->sz_text);

	xmem_free(ptd);

	SETTIPBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_tipbox_mouse_move(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	tipbox_delta_t* ptd = GETTIPBOXDELTA(widget);

	widget_close(widget, 0);
}

void hand_tipbox_size(widget_t widget, int code, const xsize_t* prs)
{
	tipbox_delta_t* ptd = GETTIPBOXDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	switch(code)
	{
	case WS_SIZE_FULLSCREEN:
		break;
	case WS_SIZE_MAXIMIZED:
		break;
	case WS_SIZE_MINIMIZED:
		break;
	case WS_SIZE_LAYOUT:
		break;
	}
}

void hand_tipbox_timer(widget_t widget, vword_t tid)
{
	tipbox_delta_t* ptd = GETTIPBOXDELTA(widget);

	widget_kill_timer(widget, tid);

	widget_close(widget, 0);
}

void hand_tipbox_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	tipbox_delta_t* ptd = GETTIPBOXDELTA(widget);
	visual_t rdc;

	xrect_t xr;
	const tchar_t *token;

	canvas_t canv;
	const drawing_interface* pif = NULL;
	drawing_interface ifv = {0};

	color_mod_t clrs;
	xbrush_t xb;
	xface_t xa;

	widget_get_color_mode(widget, &clrs);
	default_xbrush(&xb);
	format_xcolor(&clrs.clr_bkg, xb.color);

	default_xface(&xa);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);
	pif = widget_get_canvas_interface(widget);

	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	token = ptd->sz_text;

	(*ifv.pf_draw_text)(ifv.ctx, &xa, &xr, token, -1);

	end_canvas_paint(canv, dc, pxr);
}

/***************************************************************************************/
widget_t tipbox_create(widget_t widget, dword_t style, const xrect_t* pxr, int type, const tchar_t* text)
{
	if_dispatch_t ev = { 0 };
	TIPBOX_DATA pd = { 0 };

	pd.type = type;
	pd.text = text;

	ev.param = (void*)&pd;

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_tipbox_create)
		EVENT_ON_DESTROY(hand_tipbox_destroy)

		EVENT_ON_PAINT(hand_tipbox_paint)

		EVENT_ON_SIZE(hand_tipbox_size)

		EVENT_ON_MOUSE_MOVE(hand_tipbox_mouse_move)

		EVENT_ON_TIMER(hand_tipbox_timer)

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void tipbox_set_text(widget_t widget, const tchar_t* sz_text)
{
	tipbox_delta_t* ptd = GETTIPBOXDELTA(widget);

	XDK_ASSERT(ptd);

	xmem_free(ptd->sz_text);
	ptd->sz_text = xsalloc(xslen(sz_text) + 1);
	xscpy(ptd->sz_text, sz_text);
}

void tipbox_popup_size(widget_t widget, xsize_t* pxs)
{
	tipbox_delta_t* ptd = GETTIPBOXDELTA(widget);

	visual_t rdc;
	xrect_t xr = { 0 };
	xface_t xa;
	drawing_interface ifv = {0};

	default_xface(&xa);
	xscpy(xa.text_wrap, GDI_ATTR_TEXT_WRAP_WORDBREAK);
	
	rdc = widget_client_context(widget);

	get_visual_interface(rdc, &ifv);

	(*ifv.pf_text_rect)(ifv.ctx, &xa, ptd->sz_text, -1, &xr);

	widget_release_context(widget, rdc);

	pxs->w = xr.w + 10;
	pxs->h = xr.h + 4;

	adjust_widget_size(widget_get_style(widget), pxs);
}

/////////////////////////////////////////////////////////////////////////////////////////////
widget_t show_toolbox(const xpoint_t* ppt, const tchar_t* sz_text)
{
	widget_t wt;
	xrect_t xr = { 0 };
	xsize_t xs = { 0 };
	color_mod_t clr;

	wt = tipbox_create((widget_t)0, WD_STYLE_POPUP | WD_STYLE_NOACTIVE, &xr, 1, sz_text);
	if (!wt) return (widget_t)0;

	tipbox_popup_size(wt, RECTSIZE(&xr));

	if (ppt)
	{
		xr.x = ppt->x;
		xr.y = ppt->y;
	}
	else
	{
		get_screen_size(&xs);
		xr.x = xs.w - xr.w - 1;
		xr.y = xs.h - xr.h;
	}

	widget_get_color_mode(wt, &clr);
	parse_xcolor(&clr.clr_bkg, GDI_ATTR_RGB_SOFTWHITE);
	parse_xcolor(&clr.clr_txt, GDI_ATTR_RGB_DARKCYAN);
	widget_set_color_mode(wt, &clr);

	widget_move(wt, RECTPOINT(&xr));
	widget_size(wt, RECTSIZE(&xr));
	widget_take(wt, (int)WS_TAKE_TOPMOST);

	widget_set_timer(wt, DEF_TIPTIME);

	widget_show(wt, WS_SHOW_NORMAL);

	return wt;
}

bool_t reset_toolbox(widget_t widget, const xpoint_t* ppt, const tchar_t* sz_text)
{
	xrect_t xr;
	xsize_t xs;

	if (!widget_is_valid(widget))
		return 0;

	widget_show(widget, WS_SHOW_HIDE);

	widget_kill_timer(widget, 0);

	tipbox_set_text(widget, sz_text);

	tipbox_popup_size(widget, RECTSIZE(&xr));

	if (ppt)
	{
		xr.x = ppt->x;
		xr.y = ppt->y;
	}
	else
	{
		get_screen_size(&xs);
		xr.x = xs.w - xr.w - 1;
		xr.y = xs.h - xr.h;
	}

	widget_move(widget, RECTPOINT(&xr));
	widget_size(widget, RECTSIZE(&xr));
	widget_take(widget, (int)WS_TAKE_TOPMOST);

	widget_set_timer(widget, DEF_TIPTIME);

	widget_show(widget, WS_SHOW_NORMAL);

	return 1;
}
