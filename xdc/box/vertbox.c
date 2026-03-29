/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc vert control document

	@module	vertbox.c | implement file

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


typedef struct _vertbox_delta_t{
	widget_t target;

	bool_t b_drag;
	int org_x, org_y;
}vertbox_delta_t;

#define GETVERTBOXDELTA(ph) 	(vertbox_delta_t*)widget_get_user_delta(ph)
#define SETVERTBOXDELTA(ph,ptd) widget_set_user_delta(ph,(vword_t)ptd)

#define VERTBOX_BAR_WIDTH		16
#define VERTBOX_BAR_FEED		3
#define VERTBOX_LINE_DELTA		10
/*********************************************************************************/

static void _vertbox_bar_rect(widget_t widget, xrect_t* pxr)
{
	vertbox_delta_t* ptd = GETVERTBOXDELTA(widget);
	viewbox_t vb;
	xrect_t xr;
	int bh, off;
	float f;

	widget_get_client_rect(widget, &xr);
	widget_get_view_rect(ptd->target, &vb);
	
	f = (float)((float)xr.h / (float)vb.ph);
	bh = (int)(f * (float)xr.h);
	off = xr.y - (int)(f * (float)vb.py);

	pxr->x = VERTBOX_BAR_FEED;
	pxr->y = off;
	pxr->w = xr.w - VERTBOX_BAR_FEED * 2;
	pxr->h = bh;
}

static int _vertbox_hint_bar(widget_t widget, const xpoint_t* pxp)
{
	vertbox_delta_t* ptd = GETVERTBOXDELTA(widget);
	xrect_t xr, xr2;
	viewbox_t vb;
	float f;

	_vertbox_bar_rect(widget, &xr);

	if (pt_in_rect(pxp, &xr))
		return 0;

	widget_get_client_rect(widget, &xr2);
	widget_get_view_rect(ptd->target, &vb);

	f = (float)((float)vb.ph / (float)(xr2.h));

	if (pxp->y < xr.y)
		return (int)(f * (float)(pxp->y - xr.y));

	if (pxp->y > xr.y + xr.h)
		return (int)(f * (float)(pxp->y - (xr.y + xr.h)));
	
	return 0;
}

/*********************************************************************************/
int hand_vertbox_create(widget_t widget, void* data)
{
	vertbox_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (vertbox_delta_t*)xmem_alloc(sizeof(vertbox_delta_t));
	xmem_zero((void*)ptd, sizeof(vertbox_delta_t));

	SETVERTBOXDELTA(widget, ptd);

	return 0;
}

void hand_vertbox_destroy(widget_t widget)
{
	vertbox_delta_t* ptd = GETVERTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETVERTBOXDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_vertbox_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	vertbox_delta_t* ptd = GETVERTBOXDELTA(widget);
	int delta; 

	widget_kill_timer(widget, 0);

	delta = _vertbox_hint_bar(widget, pxp);

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
		widget_scroll(ptd->target, 0, delta);
		widget_erase(widget, NULL);
	}
}

void hand_vertbox_mouse_move(widget_t widget, dword_t dw, const xpoint_t* pxp)
{
	vertbox_delta_t* ptd = GETVERTBOXDELTA(widget);
	int delta;

	xrect_t xr;
	viewbox_t vb;
	float f;

	if (ptd->b_drag)
	{
		_vertbox_bar_rect(widget, &xr);

		widget_get_view_rect(ptd->target, &vb);

		f = (float)((float)vb.ph / (float)(vb.ph - xr.h));

		delta = (int)(f * (float)(pxp->y - ptd->org_y));

		ptd->org_x = pxp->x;
		ptd->org_y = pxp->y;

		widget_scroll(ptd->target, 0, delta);
		widget_erase(widget, NULL);
	}
}

void hand_vertbox_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	vertbox_delta_t* ptd = GETVERTBOXDELTA(widget);

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

void hand_vertbox_size(widget_t widget, int code, const xsize_t* prs)
{
	vertbox_delta_t* ptd = GETVERTBOXDELTA(widget);
	
	XDK_ASSERT(ptd != NULL);

	switch(code)
	{
	case WS_SIZE_FULLSCREEN:
		break;
	case WS_SIZE_MAXIMIZED:
		break;
	case WS_SIZE_MINIMIZED:
		break;
	case WS_SIZE_MAXSHOW:
		break;
	case WS_SIZE_RESTORE:
		break;
	case WS_SIZE_LAYOUT:
		break;
	}
}

void hand_vertbox_timer(widget_t widget, vword_t tid)
{
	vertbox_delta_t* ptd = GETVERTBOXDELTA(widget);

	xpoint_t pt;
	xrect_t xr;

	//message_position(&pt);

	widget_get_window_rect(widget, &xr);

	if (!pt_in_rect(&pt, &xr))
	{
		widget_kill_timer(widget, tid);

		widget_close(widget, 0);
	}
}

void hand_vertbox_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	vertbox_delta_t* ptd = GETVERTBOXDELTA(widget);
	visual_t rdc;
	canvas_t canv;
	drawing_interface ifc = {0};
	drawing_interface ifv = {0};

	xrect_t xr;

	const color_mod_t *pclrs;
	const xfont_t *pxf;
	xbrush_t xb;
	xcolor_t xc_brim, xc_core;

	pxf = widget_get_xfont_ptr(widget);
	pclrs = widget_get_color_mode_ptr(widget);
	default_xbrush(&xb);
	format_xcolor(&(pclrs->clr_bkg), xb.color);
	xmem_copy((void*)&xc_brim, (void*)&(pclrs->clr_bkg), sizeof(xcolor_t));
	xmem_copy((void*)&xc_core, (void*)&(pclrs->clr_bkg), sizeof(xcolor_t));

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);
	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
	
	get_visual_interface(rdc, &ifv);
	widget_get_view_rect(widget, (viewbox_t*)&(ifv.rect));

	get_canvas_interface(canv, &ifc);
	widget_get_canv_rect(widget, (canvbox_t*)&(ifc.rect));
	ifc.pclrs = pclrs;

	(*ifv.drw->pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	_vertbox_bar_rect(widget, &xr);

	lighten_xcolor(&xc_brim, DEF_MIDD_LIGHTEN);

	(*ifv.drw->pf_gradient_rect)(ifv.ctx, &xc_brim, &xc_core, GDI_ATTR_GRADIENT_HORZ, &xr);

	end_canvas_paint(canv, dc, pxr);
}

/***************************************************************************************/
widget_t vertbox_create(widget_t widget, dword_t style, const xrect_t* pxr)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_vertbox_create)
		EVENT_ON_DESTROY(hand_vertbox_destroy)

		EVENT_ON_PAINT(hand_vertbox_paint)

		EVENT_ON_SIZE(hand_vertbox_size)

		EVENT_ON_LBUTTON_DOWN(hand_vertbox_lbutton_down)
		EVENT_ON_MOUSE_MOVE(hand_vertbox_mouse_move)
		EVENT_ON_LBUTTON_UP(hand_vertbox_lbutton_up)

		EVENT_ON_TIMER(hand_vertbox_timer)

	EVENT_END_DISPATH

	return widget_create(NULL, style, pxr, widget, &ev);
}

void vertbox_popup_size(widget_t widget, xsize_t* pxs)
{
	vertbox_delta_t* ptd = GETVERTBOXDELTA(widget);
	measure_interface im = { 0 };
	const xfont_t* pxf;

	XDK_ASSERT(ptd != NULL);

	pxf = widget_get_xfont_ptr(widget);
	get_canvas_measure(widget_get_canvas(widget), &im);

	calc_vertbox_size(&im, pxf, pxs);

	widget_size_to_pt(widget, pxs);

	adjust_widget_size(widget_get_style(widget), pxs);
}

void vertbox_set_target(widget_t widget, widget_t target)
{
	vertbox_delta_t* ptd = GETVERTBOXDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	ptd->target = target;
}

widget_t show_vertbox(widget_t owner)
{
	widget_t wt;
	xrect_t xr = { 0 };
	xsize_t xs = { 0 };
	color_mod_t clr = { 0 };

	wt = vertbox_create(owner, WD_STYLE_POPUP | WD_STYLE_NOACTIVE, &xr);

	XDK_ASSERT(wt != NULL);

	widget_get_color_mode(owner, &clr);

	widget_set_user_id(wt, IDC_VERTBOX);
	widget_set_color_mode(wt, &clr);
	vertbox_set_target(wt, owner);

	widget_get_client_rect(owner, &xr);
	xr.x = xr.w - VERTBOX_BAR_WIDTH;
	xr.w = VERTBOX_BAR_WIDTH;
	widget_client_to_screen(owner, RECTPOINT(&xr));

	widget_move(wt, RECTPOINT(&xr));
	widget_size(wt, RECTSIZE(&xr));
	widget_set_diaph(wt, 0.9f);

	widget_set_timer(wt, DEF_TIPTIME);

	widget_show(wt, WS_SHOW_NORMAL);

	return wt;
}