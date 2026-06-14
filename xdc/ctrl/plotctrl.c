/***********************************************************************
	Easily SDK v6.0

	(c) 2013-2016 JianDe LiFang Technology Corporation.  All Rights Reserved.

	@author ZhangWenQuan, JianDe HangZhou ZheJiang China, Mail: powersuite@hotmaol.com

	@doc plot control document

	@module	plotctrl.c | implement file

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

#include "../xdcobj.h"


#define PLOT_LINE_FEED		(int)100

typedef struct _plot_delta_t{
	link_t_ptr plot;

}plot_delta_t;

#define GETPLOTDELTA(ph) 		(plot_delta_t*)widget_get_user_delta(ph)
#define SETPLOTDELTA(ph,ptd)		widget_set_user_delta(ph,(vword_t)ptd)

/***********************************************************************/

static void _plotctrl_reset_page(widget_t widget)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);
	int pw, ph, vw, vh, lw, lh;
	xrect_t xr;
	xsize_t xs;

	widget_get_client_rect(widget, &xr);
	pw = xr.w;
	ph = xr.h;

	if (ptd->plot)
	{
		xs.fw = get_plot_width(ptd->plot);
		xs.fh = get_plot_height(ptd->plot);
		widget_size_to_pt(widget, &xs);
		vw = xs.w;
		vh = xs.h;
	}
	else
	{
		vw = pw;
		vh = ph;
	}

	xs.fw = 5.0f;
	xs.fh = 5.0f;
	widget_size_to_pt(widget, &xs);
	lw = xs.w;
	lh = xs.h;

	widget_reset_paging(widget, pw, ph, vw, vh, lw, lh);

	widget_reset_scroll(widget, 1);

	widget_reset_scroll(widget, 0);
}

/***********************************************************************/

int noti_plot_owner(widget_t widget, unsigned int code, link_t_ptr plot, void* data)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);
	NOTICE_PLOT nf = { 0 };

	nf.widget = widget;
	nf.id = widget_get_user_id(widget);
	nf.code = code;

	nf.data = data;
	nf.ret = 0;

	nf.plot = plot;

	widget_send_notice(widget_get_owner(widget), (LPNOTICE)&nf);
	return nf.ret;
}

/***********************************************************************/

int hand_plot_create(widget_t widget, void* data)
{
	plot_delta_t* ptd;

	widget_hand_create(widget);

	ptd = (plot_delta_t*)xmem_alloc(sizeof(plot_delta_t));
	xmem_zero((void*)ptd, sizeof(plot_delta_t));

	SETPLOTDELTA(widget, ptd);

	return 0;
}

void hand_plot_destroy(widget_t widget)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	xmem_free(ptd);

	SETPLOTDELTA(widget, 0);

	widget_hand_destroy(widget);
}

void hand_plot_size(widget_t widget, int code, const xsize_t* pxs)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

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

	_plotctrl_reset_page(widget);
}

void hand_plot_lbutton_down(widget_t widget, const xpoint_t* pxp)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

	if (!ptd->plot)
		return;

	if (widget_can_focus(widget))
	{
		widget_set_focus(widget);
	}
}

void hand_plot_lbutton_up(widget_t widget, const xpoint_t* pxp)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

	if (!ptd->plot)
		return;

	noti_plot_owner(widget, NC_PLOTLBCLK, ptd->plot, (void*)pxp);
}

void hand_plot_lbutton_dbclick(widget_t widget, const xpoint_t* pxp)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

	if (!ptd->plot)
		return;

	noti_plot_owner(widget, NC_PLOTDBCLK, ptd->plot, (void*)pxp);
}

void hand_plot_rbutton_down(widget_t widget, const xpoint_t* pxp)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

	if (!ptd->plot)
		return;

}

void hand_plot_rbutton_up(widget_t widget, const xpoint_t* pxp)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

	if (!ptd->plot)
		return;

	noti_plot_owner(widget, NC_PLOTRBCLK, ptd->plot, (void*)pxp);
}

void hand_plot_scroll(widget_t widget, bool_t bHorz, int nLine)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

	if (!ptd->plot)
		return;

	widget_hand_scroll(widget, bHorz, nLine);
}

void hand_plot_wheel(widget_t widget, bool_t bHorz, int nDelta)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

	if (!ptd->plot)
		return;

	widget_hand_wheel(widget, bHorz, nDelta);
}

void hand_plot_paint(widget_t widget, visual_t dc, const xrect_t* pxr)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);
	visual_t rdc;
	xrect_t xr = { 0 };

	canvas_t canv;
	drawing_interface ifc = {0};
	drawing_interface ifv = {0};

	const color_mod_t* pclrs;
	xbrush_t xb = { 0 };
	xcolor_t xc = { 0 };

	if (!ptd->plot) return;

	pclrs = widget_get_color_mode_ptr(widget);
	default_xbrush(&xb);
	format_xcolor(&(pclrs->clr_bkg), xb.color);
	xmem_copy((void*)&xc, (void*)&(pclrs->clr_frg), sizeof(xcolor_t));

	widget_get_client_rect(widget, &xr);

	canv = widget_get_canvas(widget);
	rdc = begin_canvas_paint(canv, dc, xr.w, xr.h);
	
	get_visual_interface(rdc, &ifv);
	widget_get_view_rect(widget, (viewbox_t*)&(ifv.rect));

	get_canvas_interface(canv, &ifc);
	widget_get_canv_rect(widget, (canvbox_t*)&(ifc.rect));
	ifc.pclrs = pclrs;

	(*ifv.drw->pf_draw_rect)(ifv.ctx, NULL, &xb, &xr);

	if (widget_can_paging(widget))
	{
		lighten_xcolor(&xc, DEF_HARD_DARKEN);

		draw_corner(&ifc, &xc, (const xrect_t*)&(ifc.rect));
	}

	if (ptd->plot)
	{
		draw_plot(&ifc, ptd->plot);
	}

	end_canvas_paint(canv, dc, pxr);
}

/***********************************************************************/

widget_t plotctrl_create(const tchar_t* wname, dword_t wstyle, const xrect_t* pxr, widget_t wparent)
{
	if_dispatch_t ev = { 0 };

	EVENT_BEGIN_DISPATH(&ev)

		EVENT_ON_CREATE(hand_plot_create)
		EVENT_ON_DESTROY(hand_plot_destroy)

		EVENT_ON_PAINT(hand_plot_paint)

		EVENT_ON_SIZE(hand_plot_size)

		EVENT_ON_SCROLL(hand_plot_scroll)
		EVENT_ON_WHEEL(hand_plot_wheel)

		EVENT_ON_LBUTTON_DBCLICK(hand_plot_lbutton_dbclick)
		EVENT_ON_LBUTTON_DOWN(hand_plot_lbutton_down)
		EVENT_ON_LBUTTON_UP(hand_plot_lbutton_up)
		EVENT_ON_RBUTTON_DOWN(hand_plot_rbutton_down)
		EVENT_ON_RBUTTON_UP(hand_plot_rbutton_up)

		

	EVENT_END_DISPATH

	return widget_create(wname, wstyle, pxr, wparent, &ev);
}

void plotctrl_attach(widget_t widget, link_t_ptr ptr)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	XDK_ASSERT(ptr && is_plot_doc(ptr));

	ptd->plot = ptr;

	plotctrl_redraw(widget);
}

link_t_ptr plotctrl_detach(widget_t widget)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);
	link_t_ptr ptr;

	XDK_ASSERT(ptd != NULL);

	ptr = ptd->plot;
	ptd->plot = NULL;

	widget_erase(widget, NULL);
	return ptr;
}

link_t_ptr plotctrl_fetch(widget_t widget)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	return ptd->plot;
}

void plotctrl_redraw(widget_t widget)
{
	plot_delta_t* ptd = GETPLOTDELTA(widget);

	XDK_ASSERT(ptd != NULL);

	if (!ptd->plot)
		return;

	_plotctrl_reset_page(widget);
	widget_erase(widget, NULL);
}
